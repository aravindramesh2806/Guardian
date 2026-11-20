"""Guardian's app core: people, their workspaces, and what the app screen can do.

Each person gets a workspace under users/<id>/ holding everything Guardian keeps about them: their data,
store, runs, outbox and settings. "Delete my data" removes that one folder. Nothing here knows about HTTP
or passkeys (app/server.py does); every function takes a user id and is safe to call from the worker
thread and request threads at once.

Until Gmail is connected, a new workspace runs on the fictional sample data in data/, clearly labelled.
The workspace store is always local SQLite: a shared SingleStore needs per-user partitioning first.
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import sys
import tempfile
import threading
import time
from datetime import datetime, timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import gmail  # noqa: E402
import mailer  # noqa: E402
import vault  # noqa: E402
from agent import respond  # noqa: E402
from agent import run as runner  # noqa: E402
from agent import store as st  # noqa: E402

USERS = os.environ.get("GUARDIAN_USERS_DIR", os.path.join(ROOT, "users"))
SAMPLE = os.path.join(ROOT, "data")
CHECK_EVERY = int(os.environ.get("GUARDIAN_CHECK_EVERY", "300"))  # seconds between background checks

MODES = {
    # "Just tell me": Guardian alerts and asks, and acts on nothing by itself.
    "tell": {"auto_quarantine": False, "auto_block_numbers": False, "auto_lock_card": False,
             "notify_trusted_contacts": True, "dispute_needs_approval": True},
    # "Act for me, then tell me": quarantine, block and lock as needed. Disputes still wait.
    "act": {"auto_quarantine": True, "auto_block_numbers": True, "auto_lock_card": True,
            "notify_trusted_contacts": True, "dispute_needs_approval": True},
}

_locks, _locks_guard = {}, threading.Lock()


class AppError(Exception):
    """A request the person can fix: shown to them as is."""


def _lock(uid):
    with _locks_guard:
        return _locks.setdefault(uid, threading.RLock())


def _now():
    return datetime.now().isoformat(timespec="seconds")


def _dir(uid, *parts):
    if not re.fullmatch(r"[0-9a-f]{32}", uid or ""):
        raise AppError("unknown account")
    return os.path.join(USERS, uid, *parts)


def _read(path, default=None):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def _write(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(obj, f, indent=2)
    os.replace(tmp, path)


def _clean_name(name, field="name"):
    name = " ".join(str(name or "").split())
    if not 1 <= len(name) <= 60:
        raise AppError("Please enter a %s of 1 to 60 characters." % field)
    return name


# ---------- people ----------

def load(uid):
    meta = _read(_dir(uid, "meta.json"))
    if meta is None:
        raise AppError("unknown account")
    return meta


def save(uid, meta):
    _write(_dir(uid, "meta.json"), meta)


EMAIL_RE = re.compile(r"[^@\s]{1,64}@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+")
CODE_MINUTES, CODE_TRIES, UNVERIFIED_HOURS = 15, 5, 24


def clean_email(email):
    email = str(email or "").strip()
    if len(email) > 254 or not EMAIL_RE.fullmatch(email):
        raise AppError("Please enter a valid email address.")
    return email.lower()


def email_in_use(email):
    """Is this address already a verified Guardian account? (Unverified ones expire, so they don't count.)"""
    email = clean_email(email)
    for uid in all_users():
        meta = _read(_dir(uid, "meta.json"), {})
        if meta.get("email_verified") and meta.get("email") == email:
            return True
    return False


def create_user(name, credential, email):
    """A new person with one passkey, not usable until their email is confirmed. Returns their id."""
    email = clean_email(email)
    uid = secrets.token_hex(16)
    with _lock(uid):
        shutil.copytree(SAMPLE, _dir(uid, "data"))
        vault.create_key(_dir(uid))
        # A new person has not done a Persona check: card locks wait until they do.
        _write(_dir(uid, "data", "verification.json"),
               {"claim_type": "live_human_presence", "result": "not checked", "source": "none yet"})
        save(uid, {"id": uid, "name": _clean_name(name), "created": _now(), "setup_done": False,
                   "who": "me", "mode": "tell", "paused": False, "family": None, "data_source": "sample",
                   "credentials": [credential], "test_alert_at": None, "last_run": None, "last_error": None,
                   "gmail": None, "shadow": False, "accounts": [], "email": email, "email_verified": False,
                   "email_code": None, "push": []})
        _index_add(credential["id"], uid)
        _apply_settings(uid)
    return uid


def _index_path():
    return os.path.join(USERS, "credentials.json")


_index_lock = threading.Lock()


def _index_add(cred_id, uid):
    with _index_lock:
        index = _read(_index_path(), {})
        index[cred_id] = uid
        _write(_index_path(), index)


def user_for_credential(cred_id):
    return _read(_index_path(), {}).get(cred_id)


def credential(uid, cred_id):
    return next((c for c in load(uid)["credentials"] if c["id"] == cred_id), None)


def bump_sign_count(uid, cred_id, count):
    with _lock(uid):
        meta = load(uid)
        for c in meta["credentials"]:
            if c["id"] == cred_id:
                c["sign_count"] = count
        save(uid, meta)


def delete_user(uid):
    """Remove everything Guardian holds for this person. Cannot be undone."""
    with _lock(uid):
        meta = load(uid)
        if meta.get("gmail"):
            try:
                gmail.revoke(vault.read_json(_dir(uid), gmail.TOKENS, {}))
            except vault.VaultError:
                pass
        vault.shred(_dir(uid))  # first: any copy left behind can no longer be read
        with _index_lock:
            index = _read(_index_path(), {})
            for c in meta["credentials"]:
                index.pop(c["id"], None)
            _write(_index_path(), index)
        shutil.rmtree(_dir(uid), ignore_errors=True)


def all_users():
    if not os.path.isdir(USERS):
        return []
    return [d for d in os.listdir(USERS) if re.fullmatch(r"[0-9a-f]{32}", d)]


# ---------- email check at sign-up ----------

def _hash_code(code, salt):
    return hashlib.sha256((salt + ":" + code).encode()).hexdigest()


def issue_code(uid, now=None):
    """Email a fresh 6-digit code. At most one a minute and five an hour. Returns the code (for tests only:
    the server never shows it)."""
    now = now or time.time()
    with _lock(uid):
        meta = load(uid)
        if meta.get("email_verified"):
            raise AppError("Your email is already confirmed.")
        state = meta.get("email_code") or {}
        sent = [t for t in state.get("sent", []) if now - t < 3600]
        if sent and now - sent[-1] < 60:
            raise AppError("Please wait a minute before asking for another code.")
        if len(sent) >= 5:
            raise AppError("Too many codes in the last hour. Please try again later.")
        code, salt = "%06d" % secrets.randbelow(10 ** 6), secrets.token_hex(8)
        meta["email_code"] = {"hash": _hash_code(code, salt), "salt": salt, "expires": now + CODE_MINUTES * 60,
                              "attempts": 0, "sent": sent + [now]}
        save(uid, meta)
    mailer.send(meta["email"], "Your Guardian code: %s" % code,
                "Your Guardian code is %s.\n\nIt expires in %d minutes. Enter it in Guardian to finish signing up.\n\n"
                "If you didn't sign up for Guardian, ignore this email: the account is deleted after %d hours.\n"
                "Guardian will never ask you for this code by phone, text or email."
                % (code, CODE_MINUTES, UNVERIFIED_HOURS))
    return code


def verify_code(uid, code, now=None):
    now = now or time.time()
    with _lock(uid):
        meta = load(uid)
        if meta.get("email_verified"):
            return True
        state = meta.get("email_code")
        if not state or now > state["expires"]:
            raise AppError("That code has expired. Ask for a new one.")
        if state["attempts"] >= CODE_TRIES:
            raise AppError("Too many wrong codes. Ask for a new one.")
        code = re.sub(r"\D", "", str(code or ""))
        if not hmac.compare_digest(_hash_code(code, state["salt"]), state["hash"]):
            state["attempts"] += 1
            save(uid, meta)
            left = CODE_TRIES - state["attempts"]
            raise AppError("That code isn't right. %s" % ("%d tries left." % left if left else "Ask for a new one."))
        if email_in_use(meta["email"]):
            raise AppError("That email already has a Guardian account. Sign in to it instead.")
        meta["email_verified"], meta["email_code"] = True, None
        save(uid, meta)
        return True


def purge_unverified(now=None):
    """Delete accounts whose email was never confirmed within 24 hours. Returns how many."""
    now = now or datetime.now()
    removed = 0
    for uid in all_users():
        meta = _read(_dir(uid, "meta.json"), {})
        if meta.get("email_verified") or not meta.get("created"):
            continue
        if now - datetime.fromisoformat(meta["created"]) > timedelta(hours=UNVERIFIED_HOURS):
            delete_user(uid)
            removed += 1
    return removed


# ---------- alerts while the app is closed ----------

def add_push(uid, sub):
    """Remember one device's push subscription (from the browser's PushManager)."""
    if not isinstance(sub, dict) or not str(sub.get("endpoint", "")).startswith("https://") \
            or not (sub.get("keys") or {}).get("p256dh") or not (sub.get("keys") or {}).get("auth"):
        raise AppError("This device couldn't turn on alerts.")
    clean = {"endpoint": sub["endpoint"][:1000], "keys": {"p256dh": sub["keys"]["p256dh"][:200],
                                                         "auth": sub["keys"]["auth"][:100]}}
    with _lock(uid):
        meta = load(uid)
        subs = [x for x in meta.get("push", []) if x["endpoint"] != clean["endpoint"]]
        meta["push"] = (subs + [clean])[-10:]
        save(uid, meta)


def notify(uid, title, body, sender=None):
    """Push to every device this person turned alerts on for; forget devices that unsubscribed."""
    meta = load(uid)
    if not meta.get("push"):
        return 0
    if sender is None:
        try:
            import push
            sender = push.send
        except ImportError:  # pywebpush not installed: no push
            return 0
    keep, sent = [], 0
    for sub in meta["push"]:
        result = sender(sub, title, body)
        if result != "gone":
            keep.append(sub)
        sent += result == "ok"
    if len(keep) != len(meta["push"]):
        with _lock(uid):
            meta = load(uid)
            meta["push"] = keep
            save(uid, meta)
    return sent


# ---------- set up once ----------

def _apply_settings(uid):
    """Write the person's settings into the files the agent reads: profile and gates."""
    meta = load(uid)
    profile = _read(_dir(uid, "data", "profile.json"))
    profile["name"] = meta.get("protected_name") or meta["name"]
    profile["protection"] = "senior" if meta.get("senior") else "standard"
    fam = meta.get("family")
    profile["trusted_contacts"] = ([{"name": fam["name"], "channel": "sms", "address": fam["phone"],
                                     "consent": fam["status"] == "agreed"}] if fam else [])
    if meta.get("gmail"):
        # Real data: the person's own address and the accounts they named; no sample calls, cards or charges.
        profile["emails"] = [meta["gmail"]["email"]] if meta["gmail"].get("email") else []
        profile["accounts"] = [{"name": d, "domain": d} for d in meta.get("accounts", [])]
        for key in ("cards", "usual_merchants", "phone_contacts", "started_actions"):
            profile[key] = []
    _write(_dir(uid, "data", "profile.json"), profile)
    # Shadow mode (real Gmail, read-only): the kill switch stops every action; alerts still reach the person.
    gates = dict(MODES[meta["mode"]], kill_switch=bool(meta["paused"] or meta.get("shadow")))
    _write(_dir(uid, "data", "gates.json"), gates)


def setup(uid, who, protected_name, family_name, family_phone, mode, senior):
    """The one-time setup. A trusted person is saved as "not invited": nothing is sent to them from here.

    The invite goes out from send_invite, after a fresh passkey and Persona check (L6).
    """
    if who not in ("me", "family"):
        raise AppError("Choose who Guardian protects.")
    if mode not in MODES:
        raise AppError("Choose how Guardian should help.")
    with _lock(uid):
        meta = load(uid)
        meta["who"] = who
        meta["protected_name"] = _clean_name(protected_name, "name") if who == "family" else None
        meta["mode"], meta["senior"] = mode, bool(senior)
        before, meta["family"] = meta.get("family"), None
        if family_name or family_phone:
            phone = re.sub(r"[^\d+]", "", str(family_phone or ""))
            if not re.fullmatch(r"\+?\d{7,15}", phone):
                raise AppError("Please enter a phone number with 7 to 15 digits.")
            name = _clean_name(family_name, "name")
            if before and before["phone"] == phone:
                meta["family"] = dict(before, name=name)  # same number: keep their invite and their YES
            else:
                meta["family"] = {"name": name, "phone": phone, "status": "not invited", "invited_at": None}
        meta["setup_done"] = True
        save(uid, meta)
        _apply_settings(uid)
    return load(uid)


def invite_text(meta):
    """What the trusted person is sent. Plain, says who added them, and asks before anything else is sent."""
    adder = meta["name"].split(" ")[0]
    protected = (meta.get("protected_name") or meta["name"]).split(" ")[0]
    return "%s added you to Guardian. If a scammer targets %s, we'll text you. Reply YES to agree." % (
        adder, protected)


def send_invite(uid):
    """Text the trusted person the invite (simulated into the outbox, like every Guardian message).

    The server asks for a fresh passkey first; this needs a Persona pass under 24 hours, so a stolen
    session cannot point Guardian's scam alerts at a number of its own. Their consent stays "waiting"
    until they reply YES.
    """
    with _lock(uid):
        meta = load(uid)
        fam = meta.get("family")
        if not fam:
            raise AppError("No one has been added yet.")
        if fam["status"] == "agreed":
            raise AppError("%s has already said yes." % fam["name"])
        if not verification(uid)["fresh"]:
            raise AppError("Please do the Persona check first. It lasts 24 hours.")
        at = _now()
        os.makedirs(_dir(uid, "outbox"), exist_ok=True)
        with open(_dir(uid, "outbox", "family_invites.jsonl"), "a") as f:
            f.write(json.dumps({"to": fam["phone"], "name": fam["name"], "text": invite_text(meta),
                                "at": at, "simulated": True}) + "\n")
        fam["status"], fam["invited_at"] = "waiting", at
        save(uid, meta)
        _apply_settings(uid)


def family_said_yes(uid):
    """Their trusted person replied YES. (No SMS account yet: the app simulates the reply, labelled.)"""
    with _lock(uid):
        meta = load(uid)
        if not meta.get("family"):
            raise AppError("No one has been added yet.")
        if meta["family"]["status"] == "not invited":
            raise AppError("Send them the invite first.")
        meta["family"]["status"] = "agreed"
        save(uid, meta)
        _apply_settings(uid)


def set_mode(uid, mode):
    if mode not in MODES:
        raise AppError("Choose how Guardian should help.")
    with _lock(uid):
        meta = load(uid)
        meta["mode"] = mode
        save(uid, meta)
        _apply_settings(uid)


def set_paused(uid, paused):
    with _lock(uid):
        meta = load(uid)
        meta["paused"] = bool(paused)
        save(uid, meta)
        _apply_settings(uid)


def test_alert(uid):
    with _lock(uid):
        meta = load(uid)
        meta["test_alert_at"] = _now()
        save(uid, meta)
    return {"title": "This is what a Guardian alert looks like",
            "body": "When something matters, you get one message: what happened, what Guardian did, and the "
                    "one thing to do. Nothing to do for this one."}


# ---------- Gmail ----------

def connect_gmail(uid, tokens):
    """Save the (encrypted) tokens, switch this person from sample data to their Gmail, in shadow mode."""
    email = gmail.profile_email(tokens)
    with _lock(uid):
        vault.write_json(_dir(uid), gmail.TOKENS, tokens)
        vault.write_json(_dir(uid), gmail.CACHE, {})
        for name in ("inbox.json", "calls.json", "transactions.json", "receipts.json", "breaches.json"):
            _write(_dir(uid, "data", name), [])
        meta = load(uid)
        meta["gmail"] = {"email": email, "connected_at": _now(), "last_sync": None, "last_error": None}
        meta["data_source"], meta["shadow"] = "gmail", True
        save(uid, meta)
        _apply_settings(uid)
        # Start fresh: nothing from the sample data carries over into the real account.
        st.reset(_store(uid))
        shutil.rmtree(_dir(uid, "runs"), ignore_errors=True)
        shutil.rmtree(_dir(uid, "outbox"), ignore_errors=True)
    return email


def disconnect_gmail(uid):
    with _lock(uid):
        meta = load(uid)
        if meta.get("gmail"):
            gmail.revoke(vault.read_json(_dir(uid), gmail.TOKENS, {}))
        for name in (gmail.TOKENS, gmail.CACHE):
            if os.path.exists(_dir(uid, name)):
                os.remove(_dir(uid, name))
        meta["gmail"], meta["shadow"] = None, False
        meta["data_source"] = "none"
        save(uid, meta)
        _apply_settings(uid)


def set_accounts(uid, domains):
    """The bank and main accounts the person uses (website addresses): lookalikes of these are flagged."""
    clean = []
    for d in domains or []:
        d = str(d).strip().lower()
        d = re.sub(r"^https?://", "", d).split("/")[0].removeprefix("www.")
        if d and not re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+", d):
            raise AppError("\"%s\" doesn't look like a website address, e.g. mybank.com" % d)
        if d and d not in clean:
            clean.append(d)
    if len(clean) > 30:
        raise AppError("Please list up to 30 accounts.")
    with _lock(uid):
        meta = load(uid)
        meta["accounts"] = clean
        save(uid, meta)
        _apply_settings(uid)
    return clean


def _sync_gmail(uid, meta):
    tokens = vault.read_json(_dir(uid), gmail.TOKENS)
    cache = vault.read_json(_dir(uid), gmail.CACHE, {})
    try:
        cache, changed, new = gmail.sync(tokens, cache)
        meta["gmail"].update(last_sync=_now(), last_error=None)
        if changed:
            vault.write_json(_dir(uid), gmail.TOKENS, tokens)
    except gmail.GmailError as e:
        meta["gmail"]["last_error"] = "%s (%s)" % (e, _now())
    vault.write_json(_dir(uid), gmail.CACHE, cache)
    save(uid, meta)
    return list(cache.values())


def retention(uid, days=None, now=None):
    """Delete what Guardian no longer needs: cached mail and run logs older than the retention period."""
    days = days or gmail.RETENTION_DAYS
    cutoff = (now or time.time()) - days * 86400
    with _lock(uid):
        if os.path.exists(_dir(uid, gmail.CACHE)):
            when = datetime.fromtimestamp(now) if now else None
            vault.write_json(_dir(uid), gmail.CACHE, gmail.prune(vault.read_json(_dir(uid), gmail.CACHE, {}), when))
        runs = _dir(uid, "runs")
        removed = 0
        if os.path.isdir(runs):
            for name in os.listdir(runs):
                path = os.path.join(runs, name)
                if os.path.getmtime(path) < cutoff:
                    os.remove(path)
                    removed += 1
        return removed


# ---------- Persona ----------

def set_claim(uid, result):
    """Keep a Persona live-human result for this person, in their store (it counts for 24 hours)."""
    if result not in ("passed", "failed"):
        raise AppError("Persona did not give a clear answer. Please try again.")
    st.save_claim(_store(uid), "live_human_presence", result, _now(), "Persona Relay")


def verification(uid):
    c = st.claim(_store(uid))
    if not c:
        return {"result": "not checked", "checked_at": None, "fresh": False}
    return {"result": c["result"], "checked_at": c["checked_at"],
            "fresh": c["result"] == "passed" and respond.claim_fresh(c, _now())}


# ---------- checking ----------

def _store(uid):
    return st.LocalStore(_dir(uid, "guardian.sqlite3"))


def run_for(uid):
    """One check for one person. Returns the run summary; records errors instead of raising."""
    with _lock(uid):
        meta = load(uid)
        work = None
        try:
            data_dir = _dir(uid, "data")
            if meta.get("gmail"):
                inbox = _sync_gmail(uid, meta)
                # Decrypted mail exists only in a private temporary folder for the length of this check.
                work = tempfile.mkdtemp(prefix="guardian-run-")
                os.chmod(work, 0o700)
                data_dir = os.path.join(work, "data")
                shutil.copytree(_dir(uid, "data"), data_dir)
                _write(os.path.join(data_dir, "inbox.json"), inbox)
            s = runner.run(data_dir=data_dir, run_dir=_dir(uid, "runs"), outbox_dir=_dir(uid, "outbox"),
                           store=_store(uid), now=_now(), user_id=uid)
            meta = load(uid)
            meta["last_run"], meta["last_error"] = _now(), None
            save(uid, meta)
            if s and s.get("new_threats"):
                n = s["new_threats"]
                # Never message text in a push: just that there is something to look at.
                notify(uid, "Guardian", "Guardian found %d new thing%s. Tap to see." % (n, "" if n == 1 else "s"))
            return s
        except Exception as e:  # one person's failure must not stop the worker
            meta = load(uid)
            meta["last_error"] = "%s at %s" % (type(e).__name__, _now())
            save(uid, meta)
            return None
        finally:
            if work:
                shutil.rmtree(work, ignore_errors=True)


def heartbeat_path():
    return os.path.join(USERS, "worker.json")


def worker_beat():
    _write(heartbeat_path(), {"at": time.time()})


def worker_ok(now=None):
    beat = _read(heartbeat_path(), {})
    return bool(beat) and (now or time.time()) - beat.get("at", 0) < 3 * CHECK_EVERY


def check_everyone():
    purge_unverified()
    for uid in all_users():
        try:
            meta = load(uid)
            if meta.get("setup_done") and meta.get("email_verified"):
                run_for(uid)
                retention(uid)
        except AppError:
            continue
    worker_beat()


def worker_loop(stop):
    """Check every person every CHECK_EVERY seconds until `stop` (a threading.Event) is set."""
    while not stop.is_set():
        check_everyone()
        stop.wait(CHECK_EVERY)


# ---------- the app screen ----------

def _latest_summary(uid):
    runs = _dir(uid, "runs")
    if not os.path.isdir(runs):
        return None
    paths = sorted(p for p in os.listdir(runs) if p.endswith(".summary.json"))
    return _read(os.path.join(runs, paths[-1])) if paths else None


HEADLINES = {"quarantine": "Moved to quarantine", "block_number": "Number blocked", "lock_card": "Card locked",
             "dispute": "Dispute filed", "notify_trusted": "Family told"}


FRIENDLY = {"quarantine": "Quarantine", "block_number": "Blocking the number", "lock_card": "Card lock",
            "dispute": "Dispute", "notify_trusted": "Telling your family"}

# Things Guardian can do about a threat once the person confirms it's a scam. Telling family is not here:
# that depends only on the family member's own YES.
FIXABLE = ("block_number", "quarantine", "lock_card", "dispute")


def _fix_label(action, evidence, profile):
    """Plain words for one fix, e.g. "Block +1-555-0100" or "Lock card ending 4821"."""
    target = action["key"].split(":", 1)[-1]
    if action["action"] == "block_number":
        return "Block " + target
    if action["action"] == "quarantine":
        return "Move this email out of your inbox"
    if action["action"] == "lock_card":
        c = respond.card(profile, target) or {}
        return "Lock card ending " + c["last4"] if c.get("last4") else "Lock the card"
    if action["action"] == "dispute":
        if evidence.get("amount") is not None and evidence.get("merchant"):
            return "Dispute $%.2f at %s" % (evidence["amount"], evidence["merchant"])
        return "Dispute the charge"
    return FRIENDLY.get(action["action"], action["action"])


def _fixes(r, rows, profile):
    """What Guardian could still do about one threat, and whether the person can say yes to it now."""
    out, seen = [], set()
    for a in r["actions"]:
        if a["action"] not in FIXABLE or a["key"] in seen:
            continue
        seen.add(a["key"])
        status = (rows.get(a["key"]) or {}).get("status") or a["status"]
        reason = a.get("reason") or ""
        done = respond.is_done(status)
        # Paused or watch-only (kill switch), already approved, or something only the bank can do: no button.
        can = (not done and status == "waiting for you" and not reason.startswith("kill switch")
               and not reason.startswith("you approved it") and "no lock option" not in reason
               and "Persona" not in reason)
        out.append({"key": a["key"], "action": a["action"], "label": _fix_label(a, r.get("evidence") or {}, profile),
                    "done": done, "can": can, "needs_persona": "Persona" in reason,
                    "reason": "" if done else reason})
    return out


def feed(uid):
    """Everything the home screen shows, in plain words."""
    meta = load(uid)
    s = _latest_summary(uid) or {"results": []}
    store = _store(uid)
    items, needs_you = [], []
    profile = _read(_dir(uid, "data", "profile.json"), {}) or {}
    scams = st.marked_scam(store)
    for r in s["results"]:
        rows = {row["action_key"]: row for row in st.actions_for(store, r["threat"])}
        # What Guardian has done about this threat, from the store (a later run only says "already done").
        did = sorted({HEADLINES[a["action"]] for a in r["actions"] if a["action"] in HEADLINES
                      and respond.is_done((rows.get(a.get("key")) or {}).get("status") or a["status"])})
        undone = [row for row in rows.values() if str(row["status"]).endswith("(simulated undo)")]
        steps = next((a.get("text") for a in r["actions"] if a["action"] == "alert" and a.get("text")), None)
        held = [a for a in r["actions"] if a["status"] == "waiting for you" and not a.get("ask") and a.get("reason")]
        stopped = [a for a in held if a["reason"].startswith("kill switch")]
        # In shadow mode (and while paused) say what Guardian WOULD have done, not that it is "waiting".
        would = sorted({FRIENDLY.get(a["action"], a["action"]) for a in stopped})
        waiting = sorted({FRIENDLY.get(a["action"], a["action"]) + ": " + a["reason"] for a in held if a not in stopped})
        for a in r["actions"]:
            if a.get("ask") and a["status"] == "waiting for you":
                needs_you.append({"key": a["key"], "ask": a["ask"], "threat": r["threat"]})
        items.append({"threat": r["threat"], "kind": r["kind"], "severity": r["severity"], "summary": r["summary"],
                      "did": did, "would": would, "waiting": waiting, "steps": steps, "marked_real": bool(r.get("marked_real")) or bool(undone),
                      # For "Yes, it's a scam": what Guardian can still do, and the person's own steps.
                      "confirmed_scam": r["threat"] in scams, "fixes": _fixes(r, rows, profile),
                      "how": respond.steps_for(r["kind"], r.get("evidence") or {}, profile)})
    return {
        "name": meta.get("protected_name") or meta["name"], "mode": meta["mode"], "paused": meta["paused"],
        "family": meta.get("family"), "data_source": meta["data_source"], "last_run": meta.get("last_run"),
        "last_error": meta.get("last_error"), "checking": worker_ok(),
        "test_alert_at": meta.get("test_alert_at"), "needs_you": needs_you, "items": items,
        "verified": verification(uid),
        "shadow": bool(meta.get("shadow")), "gmail": meta.get("gmail"), "accounts": meta.get("accounts", []),
        "gmail_available": gmail.configured(),
    }


def confirm_scam(uid, threat_key):
    """"Yes, it's a scam": remember it. Nothing runs yet: each fix waits for its own yes (approve)."""
    with _lock(uid):
        item = next((i for i in feed(uid)["items"] if i["threat"] == threat_key), None)
        if not item:
            raise AppError("That item is no longer on your list.")
        store = _store(uid)
        if item["marked_real"] or threat_key in st.marked_real(store):
            raise AppError("You said this one was real. Guardian has left it alone.")
        st.mark_scam(store, threat_key, _now())


def approve(uid, action_key):
    """Say yes to one held action, then check at once so it runs now.

    That is either something Guardian asked about (needs_you), or a fix for a threat the person has
    confirmed is a scam.
    """
    with _lock(uid):
        f = feed(uid)
        held = {n["key"] for n in f["needs_you"]}
        held |= {x["key"] for i in f["items"] if i["confirmed_scam"] for x in i["fixes"] if x["can"]}
        if action_key not in held:
            raise AppError("That request is no longer waiting for you.")
        st.approve(_store(uid), action_key, _now())
        run_for(uid)


def mark_real(uid, threat_key):
    """"This was real": undo what Guardian did about it and never act on it again. Returns what was undone."""
    with _lock(uid):
        if threat_key not in {i["threat"] for i in feed(uid)["items"]}:
            raise AppError("That item is no longer on your list.")
        store = _store(uid)
        st.mark_real(store, threat_key, _now())
        undone = []
        for row in st.actions_for(store, threat_key):
            if respond.is_done(row["status"]):
                status = respond.undo(row, _dir(uid, "outbox"))
                if status:
                    st.set_status(store, row["action_key"], status)
                    undone.append(status)
        return undone
