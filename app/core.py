"""Guardian's app core: people, their workspaces, and what the app screen can do.

Each person gets a workspace under users/<id>/ holding everything Guardian keeps about them: their data,
store, runs, outbox and settings. "Delete my data" removes that one folder. Nothing here knows about HTTP
or passkeys (app/server.py does); every function takes a user id and is safe to call from the worker
thread and request threads at once.

Until Gmail is connected, a new workspace runs on the fictional sample data in data/, clearly labelled.
The workspace store is always local SQLite: a shared SingleStore needs per-user partitioning first.
"""
import json
import os
import re
import secrets
import shutil
import sys
import threading
import time
from datetime import datetime, timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

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


def create_user(name, credential):
    """A new person with one passkey. Returns their id."""
    uid = secrets.token_hex(16)
    with _lock(uid):
        shutil.copytree(SAMPLE, _dir(uid, "data"))
        # A new person has not done a Persona check: card locks wait until they do.
        _write(_dir(uid, "data", "verification.json"),
               {"claim_type": "live_human_presence", "result": "not checked", "source": "none yet"})
        save(uid, {"id": uid, "name": _clean_name(name), "created": _now(), "setup_done": False,
                   "who": "me", "mode": "tell", "paused": False, "family": None, "data_source": "sample",
                   "credentials": [credential], "test_alert_at": None, "last_run": None, "last_error": None})
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
    _write(_dir(uid, "data", "profile.json"), profile)
    gates = dict(MODES[meta["mode"]], kill_switch=bool(meta["paused"]))
    _write(_dir(uid, "data", "gates.json"), gates)


def setup(uid, who, protected_name, family_name, family_phone, mode, senior):
    """The one-time setup. Family members are added as "waiting for their YES"."""
    if who not in ("me", "family"):
        raise AppError("Choose who Guardian protects.")
    if mode not in MODES:
        raise AppError("Choose how Guardian should help.")
    with _lock(uid):
        meta = load(uid)
        meta["who"] = who
        meta["protected_name"] = _clean_name(protected_name, "name") if who == "family" else None
        meta["mode"], meta["senior"] = mode, bool(senior)
        meta["family"] = None
        if family_name or family_phone:
            phone = re.sub(r"[^\d+]", "", str(family_phone or ""))
            if not re.fullmatch(r"\+?\d{7,15}", phone):
                raise AppError("Please enter a phone number with 7 to 15 digits.")
            meta["family"] = {"name": _clean_name(family_name, "name"), "phone": phone, "status": "waiting"}
        meta["setup_done"] = True
        save(uid, meta)
        _apply_settings(uid)
    return load(uid)


def family_said_yes(uid):
    """Their trusted person replied YES. (No SMS account yet: the app simulates the reply, labelled.)"""
    with _lock(uid):
        meta = load(uid)
        if not meta.get("family"):
            raise AppError("No one has been added yet.")
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


# ---------- checking ----------

def _store(uid):
    return st.LocalStore(_dir(uid, "guardian.sqlite3"))


def run_for(uid):
    """One check for one person. Returns the run summary; records errors instead of raising."""
    with _lock(uid):
        meta = load(uid)
        try:
            s = runner.run(data_dir=_dir(uid, "data"), run_dir=_dir(uid, "runs"), outbox_dir=_dir(uid, "outbox"),
                           store=_store(uid), now=_now(), user_id=uid)
            meta = load(uid)
            meta["last_run"], meta["last_error"] = _now(), None
            save(uid, meta)
            return s
        except Exception as e:  # one person's failure must not stop the worker
            meta = load(uid)
            meta["last_error"] = "%s at %s" % (type(e).__name__, _now())
            save(uid, meta)
            return None


def heartbeat_path():
    return os.path.join(USERS, "worker.json")


def worker_beat():
    _write(heartbeat_path(), {"at": time.time()})


def worker_ok(now=None):
    beat = _read(heartbeat_path(), {})
    return bool(beat) and (now or time.time()) - beat.get("at", 0) < 3 * CHECK_EVERY


def check_everyone():
    for uid in all_users():
        try:
            if load(uid).get("setup_done"):
                run_for(uid)
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


def feed(uid):
    """Everything the home screen shows, in plain words."""
    meta = load(uid)
    s = _latest_summary(uid) or {"results": []}
    store = _store(uid)
    items, needs_you = [], []
    for r in s["results"]:
        rows = {row["action_key"]: row for row in st.actions_for(store, r["threat"])}
        # What Guardian has done about this threat, from the store (a later run only says "already done").
        did = sorted({HEADLINES[a["action"]] for a in r["actions"] if a["action"] in HEADLINES
                      and respond.is_done((rows.get(a.get("key")) or {}).get("status") or a["status"])})
        undone = [row for row in rows.values() if str(row["status"]).endswith("(simulated undo)")]
        steps = next((a.get("text") for a in r["actions"] if a["action"] == "alert" and a.get("text")), None)
        waiting = sorted({FRIENDLY.get(a["action"], a["action"]) + ": " + a["reason"] for a in r["actions"]
                          if a["status"] == "waiting for you" and not a.get("ask") and a.get("reason")})
        for a in r["actions"]:
            if a.get("ask") and a["status"] == "waiting for you":
                needs_you.append({"key": a["key"], "ask": a["ask"], "threat": r["threat"]})
        items.append({"threat": r["threat"], "kind": r["kind"], "severity": r["severity"], "summary": r["summary"],
                      "did": did, "waiting": waiting, "steps": steps, "marked_real": bool(r.get("marked_real")) or bool(undone)})
    return {
        "name": meta.get("protected_name") or meta["name"], "mode": meta["mode"], "paused": meta["paused"],
        "family": meta.get("family"), "data_source": meta["data_source"], "last_run": meta.get("last_run"),
        "last_error": meta.get("last_error"), "checking": worker_ok(),
        "test_alert_at": meta.get("test_alert_at"), "needs_you": needs_you, "items": items,
    }


def approve(uid, action_key):
    """Say yes to one held action, then check at once so it runs now."""
    with _lock(uid):
        held = {n["key"] for n in feed(uid)["needs_you"]}
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
