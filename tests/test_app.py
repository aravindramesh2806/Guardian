"""The web app: people's workspaces (app/core.py) and the server's security rules (app/server.py).

The server tests need the webauthn package: run them with .venv/bin/python -m unittest discover -s tests -t .
(the core tests run with plain python3 too). The full passkey flow is covered by a browser test with a
virtual authenticator; tests/e2e_app.js.
"""
import http.client
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
USERS_TMP = tempfile.mkdtemp(prefix="guardian-users-")
os.environ["GUARDIAN_USERS_DIR"] = USERS_TMP
os.environ["GUARDIAN_QUIET"] = "1"
for _k in ("SIE_BASE_URL", "SINGLESTORE_HOST", "AMPLITUDE_API_KEY", "STATSIG_SERVER_SECRET"):
    os.environ.pop(_k, None)
sys.path.insert(0, os.path.join(ROOT, "app"))

import core  # noqa: E402

try:
    import server  # noqa: E402
except ImportError:  # webauthn not installed in this interpreter
    server = None

CRED = {"id": "cred-1", "public_key": "x", "sign_count": 0}


def new_user(name="Rose", mode="act", family=True):
    uid = core.create_user(name, dict(CRED, id="cred-%f" % time.time()))
    core.setup(uid, "me", None, "Sam (daughter)" if family else None, "+1 555 0142" if family else None, mode, True)
    core.run_for(uid)
    return uid


class Core(unittest.TestCase):
    def test_new_person_sees_sample_data_and_no_persona_pass(self):
        uid = new_user()
        f = core.feed(uid)
        self.assertEqual(f["data_source"], "sample")
        self.assertEqual(len(f["items"]), 9)
        lock = next(i for i in f["items"] if "389.00" in i["summary"])
        self.assertTrue(any("Persona" in w for w in lock["waiting"]))
        self.assertEqual(json.load(open(os.path.join(USERS_TMP, uid, "data", "verification.json")))["result"], "not checked")

    def test_family_is_not_told_until_they_say_yes(self):
        uid = new_user()
        self.assertFalse(any("Family told" in i["did"] for i in core.feed(uid)["items"]))
        core.family_said_yes(uid)
        core.run_for(uid)
        self.assertTrue(any("Family told" in i["did"] for i in core.feed(uid)["items"]))

    def test_just_tell_me_acts_on_nothing(self):
        uid = new_user(mode="tell")
        self.assertEqual([i["did"] for i in core.feed(uid)["items"] if i["did"]], [])

    def test_approve_runs_the_held_dispute_and_refuses_anything_else(self):
        uid = new_user()
        with self.assertRaises(core.AppError):
            core.approve(uid, "lock:card-visa-4821")  # not something waiting for this person
        key = core.feed(uid)["needs_you"][0]["key"]
        core.approve(uid, key)
        f = core.feed(uid)
        self.assertEqual(f["needs_you"], [])
        self.assertIn("Dispute filed", next(i for i in f["items"] if "389.00" in i["summary"])["did"])

    def stick(self, uid):
        """Make it look as if a check died part-way through quarantining the PayLinc email."""
        from agent import store as st
        st.mark_started(core._store(uid), {"key": "quarantine:m-101", "type": "quarantine"}, "phishing:m-101",
                        "run-crashed", "2000-01-01T00:00:00")
        core.run_for(uid)
        return next(n for n in core.feed(uid)["needs_you"] if n["key"] == "quarantine:m-101")

    def test_a_stuck_action_is_in_needs_you_and_already_happened_closes_it(self):
        uid = new_user()
        n = self.stick(uid)
        self.assertTrue(n["stuck"])
        self.assertIn("stopped part-way", n["ask"])
        dispute = next(n["key"] for n in core.feed(uid)["needs_you"] if not n["stuck"])
        with self.assertRaises(core.AppError):  # the dispute is waiting, but it is not stuck
            core.already_done(uid, dispute)
        core.already_done(uid, "quarantine:m-101")
        f = core.feed(uid)
        self.assertNotIn("quarantine:m-101", [n["key"] for n in f["needs_you"]])
        self.assertIn("Moved to quarantine", next(i for i in f["items"] if "paylinc" in i["summary"])["did"])

    def test_a_stuck_action_can_be_tried_again(self):
        uid = new_user()
        self.stick(uid)
        core.approve(uid, "quarantine:m-101")
        f = core.feed(uid)
        self.assertNotIn("quarantine:m-101", [n["key"] for n in f["needs_you"]])
        self.assertIn("Moved to quarantine", next(i for i in f["items"] if "paylinc" in i["summary"])["did"])

    def test_this_was_real_undoes_once_and_never_acts_again(self):
        uid = new_user()
        phish = next(i for i in core.feed(uid)["items"] if "paylinc" in i["summary"])
        self.assertEqual(core.mark_real(uid, phish["threat"]), ["moved back to the inbox (simulated undo)"])
        self.assertEqual(core.mark_real(uid, phish["threat"]), [])  # nothing left to undo
        core.run_for(uid)
        again = next(i for i in core.feed(uid)["items"] if i["threat"] == phish["threat"])
        self.assertTrue(again["marked_real"])
        self.assertEqual(again["did"], [])

    def test_pause_stops_actions(self):
        uid = core.create_user("Jo", dict(CRED, id="cred-pause"))
        core.setup(uid, "me", None, None, None, "act", True)
        core.set_paused(uid, True)
        core.run_for(uid)
        self.assertEqual([i["did"] for i in core.feed(uid)["items"] if i["did"]], [])
        self.assertTrue(core.feed(uid)["paused"])

    def test_bad_input_is_refused_plainly(self):
        uid = core.create_user("Jo", dict(CRED, id="cred-bad"))
        with self.assertRaises(core.AppError):
            core.setup(uid, "me", None, "Sam", "call me", "act", False)
        with self.assertRaises(core.AppError):
            core.setup(uid, "someone", None, None, None, "act", False)
        with self.assertRaises(core.AppError):
            core.load("../../etc")

    def test_delete_removes_everything(self):
        uid = new_user()
        cred = core.load(uid)["credentials"][0]["id"]
        core.delete_user(uid)
        self.assertFalse(os.path.exists(os.path.join(USERS_TMP, uid)))
        self.assertIsNone(core.user_for_credential(cred))

    def test_people_are_kept_apart(self):
        a, b = new_user("A"), new_user("B")
        phish = next(i for i in core.feed(a)["items"] if "paylinc" in i["summary"])
        core.mark_real(a, phish["threat"])
        self.assertFalse(next(i for i in core.feed(b)["items"] if i["threat"] == phish["threat"])["marked_real"])

    def test_worker_beat_and_staleness(self):
        core.check_everyone()
        self.assertTrue(core.worker_ok())
        self.assertFalse(core.worker_ok(now=time.time() + 4 * core.CHECK_EVERY))


@unittest.skipIf(server is None, "webauthn not installed; run with .venv/bin/python")
class Server(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd, cls.stop = server.serve(port=0, worker=False)
        cls.port = cls.httpd.server_address[1]
        server.ORIGIN = "http://localhost:%d" % cls.port
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def request(self, method, path, body=None, cookie=None, origin=True):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if origin:
            headers["Origin"] = server.ORIGIN
        if cookie:
            headers["Cookie"] = "gsid=" + cookie
        conn.request(method, path, json.dumps(body) if body is not None else None, headers)
        r = conn.getresponse()
        raw = r.read()
        try:
            data = json.loads(raw or b"{}")
        except ValueError:
            data = {"html": raw.decode(errors="replace")}
        return r.status, data, r

    def session(self, stepped_up):
        uid = new_user()
        token = server._new_session(uid, stepped_up=stepped_up)
        return uid, token

    def test_posts_from_another_site_are_refused(self):
        _, token = self.session(True)
        status, _, _ = self.request("POST", "/api/check-now", {}, token, origin=False)
        self.assertEqual(status, 403)

    def test_signed_out_gets_nothing(self):
        self.assertEqual(self.request("GET", "/api/feed")[0], 401)
        self.assertEqual(self.request("POST", "/api/approve", {"key": "x"})[0], 401)

    def test_risky_changes_need_a_fresh_passkey_check(self):
        uid, token = self.session(stepped_up=False)
        key = core.feed(uid)["needs_you"][0]["key"]
        status, body, _ = self.request("POST", "/api/approve", {"key": key}, token)
        self.assertEqual((status, body.get("step_up")), (403, True))
        status, body, _ = self.request("POST", "/api/already-done", {"key": key}, token)
        self.assertEqual((status, body.get("step_up")), (403, True))
        status, body, _ = self.request("POST", "/api/delete", {}, token)
        self.assertEqual((status, body.get("step_up")), (403, True))
        self.assertTrue(os.path.exists(os.path.join(USERS_TMP, uid)))
        # Safe changes don't need it.
        self.assertEqual(self.request("POST", "/api/pause", {"paused": True}, token)[0], 200)
        self.assertEqual(self.request("POST", "/api/mode", {"mode": "tell"}, token)[0], 200)
        # Turning "act for me" back on does.
        self.assertEqual(self.request("POST", "/api/mode", {"mode": "act"}, token)[1].get("step_up"), True)

    def test_with_a_fresh_check_approve_works(self):
        uid, token = self.session(stepped_up=True)
        key = core.feed(uid)["needs_you"][0]["key"]
        status, feed, _ = self.request("POST", "/api/approve", {"key": key}, token)
        self.assertEqual((status, feed["needs_you"]), (200, []))

    def test_session_cookie_is_locked_down(self):
        status, _, r = self.request("POST", "/api/logout", {}, server._new_session(new_user(), True))
        cookie = r.getheader("Set-Cookie")
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)

    def test_pages_carry_security_headers_and_no_path_tricks(self):
        status, _, r = self.request("GET", "/../agent/run.py")
        self.assertEqual(status, 404)
        _, _, r = self.request("GET", "/api/me")
        self.assertIn("frame-ancestors 'none'", r.getheader("Content-Security-Policy"))
        self.assertEqual(r.getheader("X-Content-Type-Options"), "nosniff")

    def test_verify_page_may_frame_persona_and_nothing_else(self):
        status, _, r = self.request("GET", "/verify")
        self.assertEqual(status, 200)
        csp = r.getheader("Content-Security-Policy")
        self.assertIn("frame-src https://*.withpersona.com", csp)
        self.assertIn("frame-ancestors 'none'", csp)

    def test_internal_errors_are_not_shown_to_the_page(self):
        _, token = self.session(True)
        status, body, _ = self.request("POST", "/api/real", {"threat": "no-such-threat"}, token)
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], "That item is no longer on your list.")


@unittest.skipIf(server is None, "webauthn not installed; run with .venv/bin/python")
class PersonaInApp(unittest.TestCase):
    """The app's Persona check, against a fake sidecar that enforces the shared secret like persona/server.js."""

    SECRET = "s" * 32

    @classmethod
    def setUpClass(cls):
        import http.server

        class Fake(http.server.BaseHTTPRequestHandler):
            sessions = {}

            def log_message(self, *a):
                pass

            def do_POST(self):
                ok = self.headers.get("X-Guardian-Secret") == PersonaInApp.SECRET
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])) or b"{}")
                if not ok:
                    out, code = {"error": "forbidden"}, 403
                elif self.path == "/internal/session":
                    sid = "sess-%d" % len(Fake.sessions)
                    Fake.sessions[sid] = True
                    out, code = {"sessionId": sid, "accessToken": "tok-" + sid}, 200
                elif self.path == "/internal/result" and Fake.sessions.pop(body.get("sessionId"), None):
                    out, code = {"result": "passed"}, 200
                else:
                    out, code = {"error": "unknown or expired session"}, 404
                raw = json.dumps(out).encode()
                self.send_response(code)
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        cls.fake = http.server.HTTPServer(("127.0.0.1", 0), Fake)
        threading.Thread(target=cls.fake.serve_forever, daemon=True).start()
        server.PERSONA_URL = "http://127.0.0.1:%d" % cls.fake.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.fake.shutdown()

    def setUp(self):
        os.environ["GUARDIAN_SIDECAR_SECRET"] = self.SECRET
        self.addCleanup(os.environ.pop, "GUARDIAN_SIDECAR_SECRET", None)

    def test_a_passed_check_lets_card_locks_run(self):
        uid = new_user()
        self.assertFalse(core.feed(uid)["verified"]["fresh"])
        flow = server.persona_begin(uid)
        self.assertTrue(flow["accessToken"].startswith("tok-"))
        self.assertEqual(server.persona_finish(uid, flow["flow"]), "passed")
        self.assertTrue(core.feed(uid)["verified"]["fresh"])
        core.run_for(uid)
        card = next(i for i in core.feed(uid)["items"] if "389.00" in i["summary"])
        self.assertIn("Card locked", card["did"])

    def test_someone_elses_check_cannot_be_used(self):
        a, b = new_user("A"), new_user("B")
        flow = server.persona_begin(a)
        with self.assertRaises(core.AppError):
            server.persona_finish(b, flow["flow"])
        self.assertFalse(core.feed(b)["verified"]["fresh"])

    def test_a_check_works_once(self):
        uid = new_user()
        flow = server.persona_begin(uid)
        server.persona_finish(uid, flow["flow"])
        with self.assertRaises(core.AppError):
            server.persona_finish(uid, flow["flow"])

    def test_wrong_or_missing_secret_is_refused(self):
        os.environ["GUARDIAN_SIDECAR_SECRET"] = "x" * 32
        with self.assertRaises(core.AppError):
            server.persona_begin(new_user())
        os.environ.pop("GUARDIAN_SIDECAR_SECRET")
        with self.assertRaises(core.AppError) as e:
            server.persona_begin(new_user())
        self.assertIn("isn't set up", str(e.exception))


class FakeGoogle:
    """Google's OAuth and Gmail endpoints, enough for Guardian: token, refresh, revoke, profile, list, get."""

    def __init__(self, scope=None):
        import base64 as b64
        import http.server
        import urllib.parse as up
        self.calls, self.revoked, self.scope = [], [], scope or "https://www.googleapis.com/auth/gmail.readonly"
        now_ms = int(time.time() * 1000)

        def message(mid, sender, subject, body, link):
            text = body + " " + link
            return {"id": mid, "internalDate": str(now_ms), "payload": {
                "headers": [{"name": "From", "value": sender}, {"name": "Subject", "value": subject}],
                "mimeType": "text/plain", "body": {"data": b64.urlsafe_b64encode(text.encode()).decode()}}}
        self.messages = {
            "g1": message("g1", "Security <alerts@rnybank.com>", "Your account is on hold",
                          "Verify immediately or your account will be suspended. Log in to confirm your details.",
                          "http://rnybank-login.test/verify"),
            "g2": message("g2", "Pat <pat@friends.example>", "Lunch?", "Lunch on Thursday?", ""),
        }
        fake = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def reply(self, obj, code=200):
                raw = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self):
                form = dict(up.parse_qsl(self.rfile.read(int(self.headers["Content-Length"])).decode()))
                fake.calls.append(("POST", self.path, form.get("grant_type")))
                if self.path == "/token" and form.get("grant_type") == "authorization_code":
                    if form.get("code") != "good-code" or not form.get("code_verifier"):
                        return self.reply({"error": "invalid_grant"}, 400)
                    return self.reply({"access_token": "AT-1", "refresh_token": "RT-secret-123", "expires_in": 3600,
                                       "scope": fake.scope})
                if self.path == "/token" and form.get("grant_type") == "refresh_token":
                    return self.reply({"access_token": "AT-2", "expires_in": 3600})
                if self.path == "/revoke":
                    fake.revoked.append(form.get("token"))
                    return self.reply({})
                self.reply({"error": "not found"}, 404)

            def do_GET(self):
                path = self.path.split("?")[0]
                fake.calls.append(("GET", path, None))
                if self.headers.get("Authorization") not in ("Bearer AT-1", "Bearer AT-2"):
                    return self.reply({"error": "unauthorized"}, 401)
                if path == "/gmail/v1/users/me/profile":
                    return self.reply({"emailAddress": "rose.real@example.com"})
                if path == "/gmail/v1/users/me/messages":
                    return self.reply({"messages": [{"id": k} for k in fake.messages]})
                mid = path.rsplit("/", 1)[-1]
                if mid in fake.messages:
                    return self.reply(fake.messages[mid])
                self.reply({"error": "not found"}, 404)

        self.server = http.server.HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        base = "http://127.0.0.1:%d" % self.server.server_port
        import gmail
        gmail.AUTH_URL, gmail.TOKEN_URL, gmail.REVOKE_URL = base + "/auth", base + "/token", base + "/revoke"
        gmail.API_URL = base + "/gmail/v1"

    def gets(self, path_part):
        return [c for c in self.calls if c[0] == "GET" and path_part in c[1]]


class GmailInApp(unittest.TestCase):
    def setUp(self):
        import gmail
        self.gmail = gmail
        for k, v in (("GOOGLE_CLIENT_ID", "cid"), ("GOOGLE_CLIENT_SECRET", "csecret")):
            os.environ[k] = v
            self.addCleanup(os.environ.pop, k, None)
        self.google = FakeGoogle()
        self.addCleanup(self.google.server.shutdown)

    def connected_user(self):
        uid = new_user()
        tokens = self.gmail.exchange_code("good-code", "http://localhost/cb", "verifier")
        core.connect_gmail(uid, tokens)
        core.set_accounts(uid, ["mybank.com"])
        core.run_for(uid)
        return uid

    def test_sign_in_asks_for_read_only_with_pkce(self):
        import urllib.parse as up
        url, state, verifier = self.gmail.auth_url("http://localhost:8800/oauth/google/callback")
        q = dict(up.parse_qsl(url.split("?", 1)[1]))
        self.assertEqual(q["scope"], "https://www.googleapis.com/auth/gmail.readonly")
        self.assertEqual((q["code_challenge_method"], q["access_type"], q["state"]), ("S256", "offline", state))
        self.assertNotIn(verifier, url)

    def test_wider_or_missing_permission_is_refused(self):
        self.google.scope = "https://www.googleapis.com/auth/userinfo.email"
        with self.assertRaises(self.gmail.GmailError):
            self.gmail.exchange_code("good-code", "http://localhost/cb", "v")
        with self.assertRaises(self.gmail.GmailError):
            self.gmail.exchange_code("bad-code", "http://localhost/cb", "v")

    def test_shadow_mode_flags_but_acts_on_nothing(self):
        uid = self.connected_user()
        f = core.feed(uid)
        self.assertEqual((f["data_source"], f["shadow"], f["gmail"]["email"]), ("gmail", True, "rose.real@example.com"))
        phish = [i for i in f["items"] if "rnybank" in i["summary"]]
        self.assertEqual(len(phish), 1)
        self.assertEqual(phish[0]["did"], [])
        self.assertIn("Quarantine", phish[0]["would"])
        self.assertFalse(any("Lunch" in i["summary"] for i in f["items"]))
        self.assertFalse(any("paylinc" in i["summary"] for i in f["items"]))  # no sample data left
        self.assertFalse(os.path.exists(os.path.join(USERS_TMP, uid, "outbox", "quarantine.jsonl")))

    def test_tokens_and_mail_are_never_stored_in_plain_text(self):
        uid = self.connected_user()
        folder = os.path.join(USERS_TMP, uid)
        for name in (self.gmail.TOKENS, self.gmail.CACHE):
            raw = open(os.path.join(folder, name), "rb").read()
            self.assertNotIn(b"RT-secret-123", raw)
            self.assertNotIn(b"Lunch", raw)
            self.assertNotIn(b"rnybank", raw)
        self.assertEqual(json.load(open(os.path.join(folder, "data", "inbox.json"))), [])  # nothing at rest in data/

    def test_messages_are_fetched_once_and_tokens_refresh(self):
        import vault
        uid = self.connected_user()
        first = len(self.google.gets("/messages/g"))
        folder = os.path.join(USERS_TMP, uid)
        tokens = vault.read_json(folder, self.gmail.TOKENS)
        tokens["expires_at"] = 0  # expired
        vault.write_json(folder, self.gmail.TOKENS, tokens)
        core.run_for(uid)
        self.assertEqual(len(self.google.gets("/messages/g")), first)  # cached: not fetched again
        self.assertIn(("POST", "/token", "refresh_token"), self.google.calls)
        self.assertEqual(vault.read_json(folder, self.gmail.TOKENS)["access_token"], "AT-2")

    def test_retention_drops_old_mail_and_logs(self):
        import vault
        uid = self.connected_user()
        folder = os.path.join(USERS_TMP, uid)
        cache = vault.read_json(folder, self.gmail.CACHE)
        cache["old"] = {"id": "old", "from": "x@y.example", "subject": "old", "body": "", "links": [],
                        "received": "2020-01-01T00:00:00"}
        vault.write_json(folder, self.gmail.CACHE, cache)
        runs = os.path.join(folder, "runs")
        old_log = os.path.join(runs, os.listdir(runs)[0])
        os.utime(old_log, (time.time() - 40 * 86400,) * 2)
        self.assertGreaterEqual(core.retention(uid), 1)
        self.assertFalse(os.path.exists(old_log))
        self.assertNotIn("old", vault.read_json(folder, self.gmail.CACHE))

    def test_delete_revokes_google_and_destroys_the_key(self):
        uid = self.connected_user()
        core.delete_user(uid)
        self.assertIn("RT-secret-123", self.google.revoked)
        self.assertFalse(os.path.exists(os.path.join(USERS_TMP, uid)))

    def test_disconnect_revokes_and_forgets_mail(self):
        uid = self.connected_user()
        core.disconnect_gmail(uid)
        self.assertIn("RT-secret-123", self.google.revoked)
        self.assertFalse(os.path.exists(os.path.join(USERS_TMP, uid, self.gmail.CACHE)))
        self.assertEqual(core.feed(uid)["data_source"], "none")

    def test_another_master_key_cannot_read_anything(self):
        import vault
        from cryptography.fernet import Fernet
        uid = self.connected_user()
        saved = vault._master
        vault._master = Fernet(Fernet.generate_key())
        try:
            with self.assertRaises(vault.VaultError):
                vault.read_json(os.path.join(USERS_TMP, uid), self.gmail.TOKENS)
        finally:
            vault._master = saved

    def test_bad_account_addresses_are_refused(self):
        uid = new_user()
        with self.assertRaises(core.AppError):
            core.set_accounts(uid, ["not a site"])
        self.assertEqual(core.set_accounts(uid, ["https://www.MyBank.com/login", "mybank.com"]), ["mybank.com"])

    @unittest.skipIf(server is None, "webauthn not installed")
    def test_callback_needs_the_state_its_own_session_made(self):
        httpd, _ = server.serve(port=0, worker=False)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.shutdown)
        port = httpd.server_address[1]

        def get(path):
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=20)
            conn.request("GET", path)
            r = conn.getresponse()
            return r.read().decode()
        self.assertIn("gmail_error", get("/oauth/google/callback?state=forged&code=good-code"))
        uid = new_user()
        server.oauth_flows["st-1"] = {"uid": uid, "verifier": "v", "created": time.time()}
        self.assertIn("/?gmail=connected", get("/oauth/google/callback?state=st-1&code=good-code"))
        self.assertEqual(core.feed(uid)["data_source"], "gmail")
        self.assertIn("gmail_error", get("/oauth/google/callback?state=st-1&code=good-code"))  # used once


def tearDownModule():
    shutil.rmtree(USERS_TMP, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
