"""Demo sign-in: one ready-made account ("Rose") that signs in with a username and a PIN.

For presenting Guardian only. Real accounts sign in with a passkey and have no PIN. This is off unless
GUARDIAN_DEMO_LOGIN=1, and it only works when the app runs on localhost (the server checks its origin), so
a PIN can never open an account on a public address.

    GUARDIAN_DEMO_LOGIN=1          turn it on
    GUARDIAN_DEMO_USER=rose        the username (default "rose")
    GUARDIAN_DEMO_PIN=482913       the PIN, 4 to 8 digits (default 482913)

The PIN is kept only as a salted PBKDF2 hash. Five wrong PINs lock the demo sign-in for 15 minutes. The
same PIN confirms risky changes on the demo account (it has no passkey to do that with).
"""
import hashlib
import hmac
import os
import re
import secrets
import time

import core

DEFAULT_USER, DEFAULT_PIN = "rose", "482913"
TRIES, LOCK_SECONDS, ITERATIONS = 5, 15 * 60, 200_000
LOCAL_HOSTS = ("localhost", "127.0.0.1", "[::1]")


def enabled(origin):
    """On only when asked for, and only for an app served on this computer."""
    if os.environ.get("GUARDIAN_DEMO_LOGIN") != "1":
        return False
    host = re.sub(r"^https?://", "", str(origin or "")).split("/")[0].rsplit(":", 1)[0]
    return host in LOCAL_HOSTS


def username():
    return (os.environ.get("GUARDIAN_DEMO_USER") or DEFAULT_USER).strip().lower()


def _pin():
    pin = os.environ.get("GUARDIAN_DEMO_PIN") or DEFAULT_PIN
    if not re.fullmatch(r"\d{4,8}", pin):
        raise core.AppError("GUARDIAN_DEMO_PIN must be 4 to 8 digits.")
    return pin


def _hash(pin, salt):
    return hashlib.pbkdf2_hmac("sha256", pin.encode(), bytes.fromhex(salt), ITERATIONS).hex()


def find_user():
    name = username()
    for uid in core.all_users():
        meta = core._read(core._dir(uid, "meta.json"), {}) or {}
        if meta.get("demo_username") == name:
            return uid
    return None


def ensure_user():
    """Make the demo account if it isn't there yet (set up, sample data, one check run). Returns its id.

    The PIN hash is refreshed each time, so changing GUARDIAN_DEMO_PIN takes effect on the next start.
    """
    pin = _pin()
    uid = find_user()
    if not uid:
        # create_user wants a passkey; give it a placeholder, then take it away: this account has none.
        placeholder = {"id": "demo-no-passkey-" + secrets.token_hex(8), "public_key": "", "sign_count": 0}
        uid = core.create_user("Rose", placeholder, "rose.demo@example.com")
        with core._index_lock:
            index = core._read(core._index_path(), {})
            index.pop(placeholder["id"], None)
            core._write(core._index_path(), index)
        with core._lock(uid):
            meta = core.load(uid)
            meta.update(credentials=[], email_verified=True, email_code=None, demo_username=username())
            core.save(uid, meta)
        core.setup(uid, "me", None, "Sam (daughter)", "+1 555 0142", "tell", True)
        core.run_for(uid)
    with core._lock(uid):
        meta = core.load(uid)
        state = meta.get("demo_pin") or {}
        if not state.get("salt") or _hash(pin, state["salt"]) != state.get("hash"):
            salt = secrets.token_hex(16)
            meta["demo_pin"] = {"salt": salt, "hash": _hash(pin, salt), "failed": 0, "locked_until": 0}
            core.save(uid, meta)
    return uid


def _check(uid, pin, now):
    """True if the PIN is right. Counts wrong ones and locks after TRIES. Raises when locked."""
    with core._lock(uid):
        meta = core.load(uid)
        state = meta.get("demo_pin") or {}
        if not state.get("hash"):
            return False
        if now < state.get("locked_until", 0):
            mins = int((state["locked_until"] - now) // 60) + 1
            raise core.AppError("Too many wrong PINs. Try again in %d minute%s." % (mins, "" if mins == 1 else "s"))
        ok = hmac.compare_digest(_hash(re.sub(r"\D", "", str(pin or "")), state["salt"]), state["hash"])
        if ok:
            state["failed"] = 0
        else:
            state["failed"] = state.get("failed", 0) + 1
            if state["failed"] >= TRIES:
                state["failed"], state["locked_until"] = 0, now + LOCK_SECONDS
        meta["demo_pin"] = state
        core.save(uid, meta)
        return ok


def login(user, pin, now=None):
    """The demo account's id for a right username and PIN. One message for every wrong answer."""
    uid = find_user()
    if not uid or str(user or "").strip().lower() != username() or not _check(uid, pin, now or time.time()):
        raise core.AppError("That username or PIN isn't right.")
    return uid


def confirm(uid, pin, now=None):
    """The PIN as the demo account's "confirm it's you" for risky changes."""
    if not core.load(uid).get("demo_username"):
        raise core.AppError("Confirm with Face ID or fingerprint instead.")
    if not _check(uid, pin, now or time.time()):
        raise core.AppError("That PIN isn't right.")
