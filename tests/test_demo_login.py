"""Demo sign-in (username and PIN) and signing out.

The demo sign-in is off unless GUARDIAN_DEMO_LOGIN=1, works only on localhost, keeps the PIN as a salted
hash, locks after 5 wrong PINs, and the PIN also confirms risky changes on the demo account.
"""
import json
import os
import threading
import unittest

from tests import test_app
from tests.test_app import core, server

import demo  # noqa: E402  (app/ is on the path via tests.test_app)

PIN = "482913"


class DemoEnv(unittest.TestCase):
    def setUp(self):
        self._env = {k: os.environ.get(k) for k in ("GUARDIAN_DEMO_LOGIN", "GUARDIAN_DEMO_PIN", "GUARDIAN_DEMO_USER")}
        os.environ["GUARDIAN_DEMO_LOGIN"] = "1"
        os.environ["GUARDIAN_DEMO_PIN"] = PIN
        os.environ.pop("GUARDIAN_DEMO_USER", None)
        old = demo.find_user()
        if old:
            core.delete_user(old)

    def tearDown(self):
        for k, v in self._env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


class DemoCore(DemoEnv):
    def test_only_on_localhost_and_only_when_asked(self):
        self.assertTrue(demo.enabled("http://localhost:8800"))
        self.assertTrue(demo.enabled("http://127.0.0.1:8800"))
        self.assertFalse(demo.enabled("https://guardian.example.org"))
        self.assertFalse(demo.enabled("https://localhost.evil.example"))
        os.environ["GUARDIAN_DEMO_LOGIN"] = "0"
        self.assertFalse(demo.enabled("http://localhost:8800"))

    def test_demo_account_is_ready_to_show(self):
        uid = demo.ensure_user()
        self.assertEqual(demo.ensure_user(), uid)  # made once
        meta = core.load(uid)
        self.assertEqual((meta["name"], meta["setup_done"], meta["email_verified"]), ("Rose", True, True))
        self.assertEqual(meta["credentials"], [])  # no passkey: nothing to sign in with but the PIN
        self.assertNotIn(PIN, json.dumps(meta))  # only a hash is kept
        self.assertTrue(core.feed(uid)["items"])

    def test_right_pin_signs_in_and_wrong_ones_are_refused_alike(self):
        uid = demo.ensure_user()
        self.assertEqual(demo.login("rose", PIN), uid)
        self.assertEqual(demo.login(" Rose ", PIN), uid)
        for user, pin in (("rose", "000000"), ("sam", PIN), ("", "")):
            with self.assertRaisesRegex(core.AppError, "username or PIN isn't right"):
                demo.login(user, pin)

    def test_five_wrong_pins_lock_it(self):
        demo.ensure_user()
        for _ in range(demo.TRIES):
            with self.assertRaises(core.AppError):
                demo.login("rose", "111111", now=1000)
        with self.assertRaisesRegex(core.AppError, "Too many wrong PINs"):
            demo.login("rose", PIN, now=1001)  # even the right PIN waits
        self.assertTrue(demo.login("rose", PIN, now=1000 + demo.LOCK_SECONDS + 1))

    def test_changing_the_pin_takes_effect(self):
        demo.ensure_user()
        os.environ["GUARDIAN_DEMO_PIN"] = "2468"
        demo.ensure_user()
        with self.assertRaises(core.AppError):
            demo.login("rose", PIN)
        self.assertTrue(demo.login("rose", "2468"))

    def test_pin_confirms_only_on_the_demo_account(self):
        uid = demo.ensure_user()
        demo.confirm(uid, PIN)
        with self.assertRaises(core.AppError):
            demo.confirm(uid, "000000")
        with self.assertRaisesRegex(core.AppError, "Face ID"):
            demo.confirm(test_app.new_user(), PIN)


@unittest.skipIf(server is None, "webauthn not installed; run with .venv/bin/python")
class DemoServer(DemoEnv):
    request = test_app.Server.request

    @classmethod
    def setUpClass(cls):
        cls.httpd, cls.stop = server.serve(port=0, worker=False)
        cls.port = cls.httpd.server_address[1]
        server.ORIGIN = "http://localhost:%d" % cls.port
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def login(self, pin=PIN):
        status, body, r = self.request("POST", "/api/demo/login", {"username": "rose", "pin": pin})
        cookie = (r.getheader("Set-Cookie") or "").split(";")[0].partition("=")[2]
        return status, body, cookie

    def test_sign_in_see_home_sign_out(self):
        demo.ensure_user()
        self.assertTrue(self.request("GET", "/api/me")[1]["demo_login"])
        status, _, cookie = self.login()
        self.assertEqual(status, 200)
        me = self.request("GET", "/api/me", cookie=cookie)[1]
        self.assertEqual((me["signed_in"], me["name"], me["demo"], me["setup_done"]), (True, "Rose", True, True))
        self.assertEqual(self.request("GET", "/api/feed", cookie=cookie)[0], 200)
        # Sign out: the session is gone, and the cookie no longer works.
        status, _, r = self.request("POST", "/api/logout", {}, cookie)
        self.assertEqual(status, 200)
        self.assertIn("Max-Age=0", r.getheader("Set-Cookie"))
        self.assertEqual(self.request("GET", "/api/feed", cookie=cookie)[0], 401)
        self.assertFalse(self.request("GET", "/api/me", cookie=cookie)[1]["signed_in"])

    def test_wrong_pin_gets_no_session(self):
        demo.ensure_user()
        status, body, cookie = self.login("000000")
        self.assertEqual((status, body["error"], cookie), (400, "That username or PIN isn't right.", ""))

    def test_off_means_not_there(self):
        demo.ensure_user()
        os.environ["GUARDIAN_DEMO_LOGIN"] = "0"
        self.assertEqual(self.login()[0], 404)
        self.assertFalse(self.request("GET", "/api/me")[1]["demo_login"])

    def test_risky_change_asks_for_the_pin_again(self):
        uid = demo.ensure_user()
        _, _, cookie = self.login()
        with server._state:
            server.sessions[cookie]["stepped_up_at"] = 0  # pretend the sign-in was a while ago
        self.assertEqual(self.request("POST", "/api/mode", {"mode": "act"}, cookie)[1].get("step_up"), True)
        self.assertEqual(self.request("POST", "/api/stepup/pin", {"pin": "000000"}, cookie)[0], 400)
        self.assertEqual(self.request("POST", "/api/stepup/pin", {"pin": PIN}, cookie)[0], 200)
        self.assertEqual(self.request("POST", "/api/mode", {"mode": "act"}, cookie)[0], 200)
        self.assertEqual(core.load(uid)["mode"], "act")


if __name__ == "__main__":
    unittest.main()
