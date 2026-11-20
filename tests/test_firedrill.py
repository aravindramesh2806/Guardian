"""Guardian against fake Firedrill services (Gmail, Stripe, Slack shapes from the real APIs)."""
import base64
import io
import json
import os
import shutil
import tempfile
import unittest
import urllib.error
from unittest import mock

from agent import brief, detect, drill, firedrill
from agent import run as runner
from agent import store as st

SAMPLE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
URLS = {"GUARDIAN_GMAIL_URL": "http://127.0.0.1:9/gmail/mail/v1/invoke",
        "GUARDIAN_STRIPE_URL": "http://127.0.0.1:9/stripe/pay/v1/invoke",
        "GUARDIAN_SLACK_URL": "http://127.0.0.1:9/slack/chat/v1/invoke"}


def b64(text):
    return base64.urlsafe_b64encode(text.encode()).decode().rstrip("=")


def gmail_message(mid, sender, subject, body, epoch_ms):
    return {"id": mid, "threadId": "t" + mid, "labelIds": ["INBOX"], "internalDate": str(epoch_ms),
            "payload": {"mimeType": "multipart/alternative",
                        "headers": [{"name": "From", "value": "Support <%s>" % sender},
                                    {"name": "Subject", "value": subject}],
                        "parts": [{"mimeType": "text/plain", "body": {"data": b64(body)}},
                                  {"mimeType": "text/html", "body": {"data": b64("<p>x</p>")}}]}}


class FakeWorld:
    """Answers invoke calls the way the synthetic services would, and records them."""

    def __init__(self):
        self.calls = []
        self.down = set()
        self.messages = {
            "m-1": gmail_message("m-1", "support@paylinc.example", "Refund on hold - verify within 24 hours",
                                 "Log in and verify your account within 24 hours: http://paylinc-verify.example/login",
                                 1795680000000),
            "m-2": gmail_message("m-2", "jordan@friends.example", "Dinner?", "Still on for 7?", 1795680000000),
        }
        self.labels = [{"id": "INBOX", "name": "INBOX"}]
        self.charges = [
            {"id": "ch_1", "amount": 38900, "created": 1795680000, "status": "succeeded", "refunded": False,
             "description": "QX DIGITAL SVCS", "payment_method_details": {"card": {"last4": "4821"}}},
            {"id": "ch_2", "amount": 4210, "created": 1795600000, "status": "succeeded", "refunded": False,
             "calculated_statement_descriptor": "Green Grocer",
             "payment_method_details": {"card": {"last4": "4821"}}},
        ]
        self.posts = []

    def __call__(self, req, timeout=None):
        service = req.full_url.split("/")[3]
        body = json.loads(req.data)
        self.calls.append((service, body["operation"], body["arguments"]))
        if service in self.down:
            raise urllib.error.HTTPError(req.full_url, 503, "down", {},
                                         io.BytesIO(b'{"error":{"code":"dependency_unavailable"}}'))
        return io.BytesIO(json.dumps(self.answer(service, body["operation"], body["arguments"])).encode())

    def answer(self, service, op, args):
        if op == "messages.list":
            return {"messages": [{"id": k, "threadId": "t" + k} for k in self.messages], "resultSizeEstimate": 2}
        if op == "messages.get":
            return self.messages[args["id"]]
        if op == "labels.list":
            return {"labels": self.labels}
        if op == "labels.create":
            label = {"id": "Label_7", "name": args["name"]}
            self.labels.append(label)
            return label
        if op == "messages.modify":
            m = self.messages[args["id"]]
            m["labelIds"] = [l for l in m["labelIds"] if l not in args["removeLabelIds"]] + args["addLabelIds"]
            return m
        if op == "charges.list":
            return {"object": "list", "data": self.charges, "has_more": False}
        if op == "conversations.list":
            return {"ok": True, "channels": [{"id": "C0FAMILY", "name": "family"}]}
        if op == "chat.postMessage":
            self.posts.append(args)
            return {"ok": True, "channel": args["channel"], "ts": "1.0"}
        raise AssertionError("unexpected operation " + op)


class FiredrillTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.data = os.path.join(self.tmp, "data")
        shutil.copytree(SAMPLE, self.data)
        self.world = FakeWorld()
        firedrill._label_ids.clear()
        patches = [mock.patch.dict(os.environ, URLS), mock.patch("urllib.request.urlopen", self.world),
                   mock.patch("time.sleep", lambda s: None)]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.store = st.LocalStore(os.path.join(self.tmp, "t.sqlite3"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_once(self, **kw):
        return runner.run(data_dir=self.data, run_dir=os.path.join(self.tmp, "runs"),
                          outbox_dir=os.path.join(self.tmp, "outbox"), store=self.store,
                          now="2026-11-20T14:00:00", **kw)

    def test_gmail_message_becomes_guardian_shape(self):
        m = firedrill.message_from_gmail(self.world.messages["m-1"])
        self.assertEqual(m["from"], "support@paylinc.example")
        self.assertIn("verify your account", m["body"])
        self.assertEqual(m["links"], ["http://paylinc-verify.example/login"])

    def test_threats_come_from_firedrill_not_local_files(self):
        keys = {t["key"] for t in detect.all_threats(self.data)}
        self.assertIn("phishing:m-1", keys)
        self.assertIn("charge:ch_1", keys)
        self.assertNotIn("phishing:m-101", keys)  # the local sample inbox is not read
        self.assertNotIn("charge:ch_2", keys)     # a usual merchant, amount converted from cents

    def test_phishing_is_quarantined_in_gmail(self):
        r = {x["threat"]: x for x in self.run_once()["results"]}
        status = next(a["status"] for a in r["phishing:m-1"]["actions"] if a["action"] == "quarantine")
        self.assertEqual(status, "quarantined (Firedrill Gmail, simulated)")
        self.assertEqual(self.world.messages["m-1"]["labelIds"], ["Label_7"])
        self.assertEqual(self.world.messages["m-2"]["labelIds"], ["INBOX"])

    def test_family_alert_goes_to_the_slack_channel(self):
        s = self.run_once()
        self.assertEqual(s["family_told"], 3)
        self.assertEqual({p["channel"] for p in self.world.posts}, {"C0FAMILY"})

    def test_gmail_outage_is_reported_not_replaced_with_demo_data(self):
        self.world.down.add("gmail")
        s = self.run_once()
        self.assertEqual(len(s["source_errors"]), 1)
        self.assertNotIn("phishing:m-101", {r["threat"] for r in s["results"]})
        self.assertIn("Could not check everything", "\n".join(brief.brief_lines(s)))

    def test_failed_quarantine_waits_and_retries_next_run(self):
        real = self.world.answer

        def flaky(service, op, args):
            if op == "messages.modify":
                raise urllib.error.HTTPError("x", 403, "no", {}, io.BytesIO(b'{"error":{"code":"forbidden"}}'))
            return real(service, op, args)
        self.world.answer = flaky
        r = {x["threat"]: x for x in self.run_once()["results"]}
        self.assertEqual(next(a["status"] for a in r["phishing:m-1"]["actions"]), "waiting for you")
        self.world.answer = real
        r = {x["threat"]: x for x in self.run_once()["results"]}
        self.assertEqual(next(a["status"] for a in r["phishing:m-1"]["actions"]),
                         "quarantined (Firedrill Gmail, simulated)")


class DrillProtocolTests(unittest.TestCase):
    def test_only_a_clear_yes_approves_the_dispute(self):
        self.assertTrue(drill.approves_dispute("Yes, please dispute that charge."))
        self.assertFalse(drill.approves_dispute("No, don't dispute it yet"))
        self.assertFalse(drill.approves_dispute("What is a dispute?"))
        self.assertFalse(drill.approves_dispute("yes thanks"))

    def test_replies_one_json_line_per_step(self):
        with mock.patch.dict(os.environ, {k: "" for k in URLS}):
            out = io.StringIO()
            drill.main(io.StringIO('{"id": "a", "session": "s", "kind": "message", "input": "hi"}\nnot json\n'), out)
        lines = [json.loads(l) for l in out.getvalue().splitlines()]
        self.assertEqual(lines[0]["id"], "a")
        self.assertIn("new threats", lines[0]["output"])
        self.assertIn("error", lines[1])


if __name__ == "__main__":
    unittest.main()
