"""'Yes, it's a scam': the person confirms a threat, then says yes to each fix and sees their own steps.

Confirming records the answer only. Every fix still needs its own yes (and Face ID on the server), the
kill switch still stops everything, and a card lock still needs a fresh Persona check.
"""
import threading
import unittest

from tests import test_app
from tests.test_app import core, new_user, server
from agent import respond


def item(uid, text):
    return next(i for i in core.feed(uid)["items"] if text in i["summary"])


def fix(it, action):
    return next(f for f in it["fixes"] if f["action"] == action)


class ConfirmScam(unittest.TestCase):
    def test_every_item_comes_with_steps_for_the_person(self):
        uid = new_user(mode="tell")
        for i in core.feed(uid)["items"]:
            self.assertTrue(i["how"], i["kind"])
            self.assertFalse(i["confirmed_scam"])

    def test_confirm_then_block_the_number(self):
        uid = new_user(mode="tell")
        call = item(uid, "+1-555-0100")
        block = fix(call, "block_number")
        self.assertEqual((block["label"], block["can"], block["done"]), ("Block +1-555-0100", True, False))
        with self.assertRaises(core.AppError):
            core.approve(uid, block["key"])  # not before the person says it's a scam
        core.confirm_scam(uid, call["threat"])
        self.assertTrue(item(uid, "+1-555-0100")["confirmed_scam"])
        self.assertFalse(fix(item(uid, "+1-555-0100"), "block_number")["done"])  # confirming alone does nothing
        core.approve(uid, block["key"])
        call = item(uid, "+1-555-0100")
        self.assertTrue(fix(call, "block_number")["done"])
        self.assertIn("Number blocked", call["did"])

    def test_phishing_email_can_be_moved_aside(self):
        uid = new_user(mode="tell")
        phish = item(uid, "paylinc")
        core.confirm_scam(uid, phish["threat"])
        core.approve(uid, fix(phish, "quarantine")["key"])
        self.assertIn("Moved to quarantine", item(uid, "paylinc")["did"])

    def test_card_lock_still_needs_a_persona_check(self):
        uid = new_user(mode="tell")
        charge = item(uid, "389.00")
        core.confirm_scam(uid, charge["threat"])
        lock = fix(charge, "lock_card")
        self.assertEqual((lock["label"], lock["can"], lock["needs_persona"]), ("Lock card ending 4821", False, True))
        with self.assertRaises(core.AppError):
            core.approve(uid, lock["key"])
        core.set_claim(uid, "passed")
        core.run_for(uid)
        lock = fix(item(uid, "389.00"), "lock_card")
        self.assertTrue(lock["can"])
        core.approve(uid, lock["key"])
        self.assertTrue(fix(item(uid, "389.00"), "lock_card")["done"])

    def test_paused_means_no_fix_buttons(self):
        uid = new_user(mode="tell")
        core.set_paused(uid, True)
        core.run_for(uid)
        call = item(uid, "+1-555-0100")
        core.confirm_scam(uid, call["threat"])
        block = fix(item(uid, "+1-555-0100"), "block_number")
        self.assertFalse(block["can"])
        with self.assertRaises(core.AppError):
            core.approve(uid, block["key"])

    def test_cannot_confirm_what_you_said_was_real(self):
        uid = new_user(mode="tell")
        call = item(uid, "+1-555-0100")
        core.mark_real(uid, call["threat"])
        with self.assertRaises(core.AppError):
            core.confirm_scam(uid, call["threat"])

    def test_guard_approval_never_beats_the_kill_switch(self):
        action = {"type": "quarantine", "key": "quarantine:m1"}
        self.assertTrue(respond.guard(action, {"auto_quarantine": False}, {}, {}, approved={"quarantine:m1"})[0])
        self.assertFalse(respond.guard(action, {"auto_quarantine": False, "kill_switch": True}, {}, {},
                                       approved={"quarantine:m1"})[0])


@unittest.skipIf(server is None, "webauthn not installed; run with .venv/bin/python")
class ConfirmScamServer(unittest.TestCase):
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

    def test_confirm_needs_no_face_id_but_each_fix_does(self):
        uid = new_user(mode="tell")
        token = server._new_session(uid, stepped_up=False)
        call = item(uid, "+1-555-0100")
        status, feed, _ = self.request("POST", "/api/scam", {"threat": call["threat"]}, token)
        self.assertEqual(status, 200)
        self.assertTrue(next(i for i in feed["items"] if i["threat"] == call["threat"])["confirmed_scam"])
        status, body, _ = self.request("POST", "/api/approve", {"key": fix(call, "block_number")["key"]}, token)
        self.assertEqual((status, body.get("step_up")), (403, True))
        self.assertFalse(fix(item(uid, "+1-555-0100"), "block_number")["done"])

    def test_unknown_threat_is_refused(self):
        token = server._new_session(new_user(mode="tell"), stepped_up=True)
        status, body, _ = self.request("POST", "/api/scam", {"threat": "nope"}, token)
        self.assertEqual((status, body["error"]), (400, "That item is no longer on your list."))


if __name__ == "__main__":
    unittest.main()
