"""Where the agent keeps threats and actions, so every run sees what earlier runs did.

LocalStore uses SQLite and needs nothing. SingleStoreStore uses SingleStore's HTTP Data API when
SINGLESTORE_HOST, SINGLESTORE_USER, SINGLESTORE_PASSWORD and SINGLESTORE_DATABASE are set.
The Data API paths below follow SingleStore's docs as we understand them; confirm on the first live run.
"""
import base64
import json
import os
import sqlite3
import urllib.request

SCHEMA = [
    """CREATE TABLE IF NOT EXISTS threats (
        threat_key VARCHAR(128) PRIMARY KEY, kind VARCHAR(32), severity VARCHAR(16),
        summary TEXT, run_id VARCHAR(64), created_at VARCHAR(32))""",
    """CREATE TABLE IF NOT EXISTS actions (
        action_key VARCHAR(128) PRIMARY KEY, threat_key VARCHAR(128), action VARCHAR(32),
        status VARCHAR(64), detail TEXT, run_id VARCHAR(64), created_at VARCHAR(32))""",
    """CREATE TABLE IF NOT EXISTS approvals (
        action_key VARCHAR(128) PRIMARY KEY, approved_at VARCHAR(32))""",
    """CREATE TABLE IF NOT EXISTS feedback (
        threat_key VARCHAR(128) PRIMARY KEY, label VARCHAR(16), at VARCHAR(32))""",
    """CREATE TABLE IF NOT EXISTS claims (
        claim_type VARCHAR(64) PRIMARY KEY, result VARCHAR(16), checked_at VARCHAR(32), source VARCHAR(64))""",
    """CREATE TABLE IF NOT EXISTS verdicts (
        item_key VARCHAR(128) PRIMARY KEY, label VARCHAR(16), decided_by VARCHAR(128), created_at VARCHAR(32))""",
]


class LocalStore:
    """SQLite store; the default, and what the tests use."""

    name = "sqlite"

    def __init__(self, path):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.db = sqlite3.connect(path)
        for stmt in SCHEMA:
            self.db.execute(stmt)
        self.db.commit()

    def exec(self, sql, args=()):
        self.db.execute(sql.replace("%s", "?"), args)
        self.db.commit()

    def rows(self, sql, args=()):
        cur = self.db.execute(sql.replace("%s", "?"), args)
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]


class SingleStoreStore:
    """SingleStore through its HTTP Data API, using only the standard library."""

    name = "singlestore"

    def __init__(self, host, user, password, database):
        self.base = "https://" + host.replace("https://", "").rstrip("/")
        self.auth = "Basic " + base64.b64encode(("%s:%s" % (user, password)).encode()).decode()
        self.database = database
        for stmt in SCHEMA:
            self.exec(stmt)

    def _post(self, path, sql, args):
        body = json.dumps({"sql": sql.replace("%s", "?"), "args": list(args),
                           "database": self.database}, default=str).encode()
        req = urllib.request.Request(self.base + path, data=body, headers={
            "Content-Type": "application/json", "Authorization": self.auth})
        with urllib.request.urlopen(req, timeout=8) as resp:
            return json.loads(resp.read() or b"{}")

    def exec(self, sql, args=()):
        self._post("/api/v2/exec", sql, args)

    def rows(self, sql, args=()):
        out = self._post("/api/v2/query/rows", sql, args)
        results = out.get("results") or [{}]
        return results[0].get("rows", [])


def open_store(local_path, remote=None):
    """SingleStore when its settings exist, otherwise SQLite at local_path.

    If SingleStore is configured but unreachable, protection must not stop: fall back to SQLite and say so
    in the store's name (it shows in the run summary and the report). `remote` replaces the SingleStore
    constructor in tests.
    """
    env = os.environ
    keys = ("SINGLESTORE_HOST", "SINGLESTORE_USER", "SINGLESTORE_PASSWORD", "SINGLESTORE_DATABASE")
    if remote is None and all(env.get(k) for k in keys):
        remote = lambda: SingleStoreStore(*(env[k] for k in keys))
    if remote is not None:
        try:
            return remote()
        except Exception as e:
            local = LocalStore(local_path)
            local.name = "sqlite (singlestore unreachable: %s)" % type(e).__name__
            return local
    return LocalStore(local_path)


def reset(store):
    """Forget every threat and action. For demo resets only: the next run treats everything as new."""
    store.exec("DELETE FROM actions")
    store.exec("DELETE FROM threats")
    store.exec("DELETE FROM verdicts")
    store.exec("DELETE FROM approvals")
    store.exec("DELETE FROM feedback")


def save_claim(store, claim_type, result, checked_at, source):
    """A Persona claim result for this person (the agent prefers this to data/verification.json)."""
    store.exec("DELETE FROM claims WHERE claim_type = %s", (claim_type,))
    store.exec("INSERT INTO claims (claim_type, result, checked_at, source) VALUES (%s, %s, %s, %s)",
               (claim_type, result, checked_at, source))


def claim(store, claim_type="live_human_presence"):
    found = store.rows("SELECT claim_type, result, checked_at, source FROM claims WHERE claim_type = %s", (claim_type,))
    return found[0] if found else None


def approve(store, action_key, at):
    """The person said yes to a held action (a dispute, or locking a card over a small charge)."""
    store.exec("DELETE FROM approvals WHERE action_key = %s", (action_key,))
    store.exec("INSERT INTO approvals (action_key, approved_at) VALUES (%s, %s)", (action_key, at))


def approved_keys(store):
    return {r["action_key"] for r in store.rows("SELECT action_key FROM approvals")}


def mark_real(store, threat_key, at):
    """The person said "this was real": remember it, so Guardian never acts on this threat again."""
    store.exec("DELETE FROM feedback WHERE threat_key = %s", (threat_key,))
    store.exec("INSERT INTO feedback (threat_key, label, at) VALUES (%s, %s, %s)", (threat_key, "real", at))


def marked_real(store):
    return {r["threat_key"] for r in store.rows("SELECT threat_key FROM feedback WHERE label = %s", ("real",))}


def actions_for(store, threat_key):
    return store.rows("SELECT action_key, action, status, detail FROM actions WHERE threat_key = %s", (threat_key,))


def set_status(store, action_key, status):
    store.exec("UPDATE actions SET status = %s WHERE action_key = %s", (status, action_key))


def verdict_get(store, key):
    """A model's earlier answer for one message, so daily runs never ask about it twice."""
    found = store.rows("SELECT label, decided_by FROM verdicts WHERE item_key = %s", (key,))
    return found[0] if found else None


def verdict_put(store, key, label, decided_by, at):
    store.exec("DELETE FROM verdicts WHERE item_key = %s", (key,))
    store.exec("INSERT INTO verdicts (item_key, label, decided_by, created_at) VALUES (%s, %s, %s, %s)",
               (key, label, decided_by, at))


def threat_seen(store, key):
    found = store.rows("SELECT run_id FROM threats WHERE threat_key = %s", (key,))
    return found[0] if found else None


def action_done(store, key):
    """An action that already ran. Held and failed actions are not 'done', so they run again later."""
    found = store.rows("SELECT status, run_id, detail FROM actions WHERE action_key = %s AND status <> %s AND status <> %s",
                       (key, "waiting for you", "failed, will retry"))
    return found[0] if found else None


def waiting(store):
    """Keys of actions held for the person, so --approve can check what it is approving."""
    return [r["action_key"] for r in store.rows(
        "SELECT action_key FROM actions WHERE status = %s", ("waiting for you",))]


def save_threat(store, t, run_id, at):
    store.exec("INSERT INTO threats (threat_key, kind, severity, summary, run_id, created_at) "
               "VALUES (%s, %s, %s, %s, %s, %s)", (t["key"], t["kind"], t["severity"], t["summary"], run_id, at))


STARTED = "started"


def mark_started(store, action, threat_key, run_id, at):
    """Written just before an action runs. If Guardian dies mid-action, this stays, and the action is not
    repeated blindly next time (at most once): the person is asked to check instead."""
    save_action(store, action, threat_key, {"status": STARTED}, run_id, at)


def save_action(store, action, threat_key, result, run_id, at):
    store.exec("DELETE FROM actions WHERE action_key = %s", (action["key"],))
    store.exec("INSERT INTO actions (action_key, threat_key, action, status, detail, run_id, created_at) "
               "VALUES (%s, %s, %s, %s, %s, %s, %s)",
               (action["key"], threat_key, action["type"], result["status"],
                json.dumps(result, default=str), run_id, at))
