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
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read() or b"{}")

    def exec(self, sql, args=()):
        self._post("/api/v2/exec", sql, args)

    def rows(self, sql, args=()):
        out = self._post("/api/v2/query/rows", sql, args)
        results = out.get("results") or [{}]
        return results[0].get("rows", [])


def open_store(local_path):
    """SingleStore when its settings exist, otherwise SQLite at local_path."""
    env = os.environ
    keys = ("SINGLESTORE_HOST", "SINGLESTORE_USER", "SINGLESTORE_PASSWORD", "SINGLESTORE_DATABASE")
    if all(env.get(k) for k in keys):
        return SingleStoreStore(*(env[k] for k in keys))
    return LocalStore(local_path)


def threat_seen(store, key):
    found = store.rows("SELECT run_id FROM threats WHERE threat_key = %s", (key,))
    return found[0] if found else None


def action_done(store, key):
    """An action that already ran. Held actions are not 'done', so they can run once approved."""
    found = store.rows("SELECT status, run_id, detail FROM actions WHERE action_key = %s AND status <> %s",
                       (key, "waiting for you"))
    return found[0] if found else None


def waiting(store):
    """Keys of actions held for the person, so --approve can check what it is approving."""
    return [r["action_key"] for r in store.rows(
        "SELECT action_key FROM actions WHERE status = %s", ("waiting for you",))]


def save_threat(store, t, run_id, at):
    store.exec("INSERT INTO threats (threat_key, kind, severity, summary, run_id, created_at) "
               "VALUES (%s, %s, %s, %s, %s, %s)", (t["key"], t["kind"], t["severity"], t["summary"], run_id, at))


def save_action(store, action, threat_key, result, run_id, at):
    store.exec("DELETE FROM actions WHERE action_key = %s", (action["key"],))
    store.exec("INSERT INTO actions (action_key, threat_key, action, status, detail, run_id, created_at) "
               "VALUES (%s, %s, %s, %s, %s, %s, %s)",
               (action["key"], threat_key, action["type"], result["status"],
                json.dumps(result, default=str), run_id, at))
