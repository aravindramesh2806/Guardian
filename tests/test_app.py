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
        return r.status, json.loads(r.read() or b"{}"), r

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

    def test_internal_errors_are_not_shown_to_the_page(self):
        _, token = self.session(True)
        status, body, _ = self.request("POST", "/api/real", {"threat": "no-such-threat"}, token)
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], "That item is no longer on your list.")


def tearDownModule():
    shutil.rmtree(USERS_TMP, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
