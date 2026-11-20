"""Adversarial and failure tests (PLAN.md section 6, items 3 and 5), plus the quality bar on synthetic people."""
import json
import os
import time
import unittest

from agent import audit, detect, evaluate, models
from agent import run as runner
from tests.test_guardian import Base

KNOWN = {"examplebank.example", "shopnest.example", "streambox.example", "paylink.example", "fittrack.example"}


def email(**kw):
    m = {"id": "adv-1", "from": "someone@example.org", "received": "2026-11-20T09:00:00", "subject": "Hello",
         "body": "", "links": []}
    m.update(kw)
    return m


class Adversarial(Base):
    def test_display_name_cannot_hide_a_lookalike_sender(self):
        score, reasons = detect.phishing_score(email(**{"from": "Example Bank <alerts@examp1ebank.example>"}), KNOWN)
        self.assertGreaterEqual(score, 0.5)
        self.assertIn("examp1ebank.example", reasons[0])

    def test_unicode_lookalike_sender_is_caught(self):
        score, reasons = detect.phishing_score(email(**{"from": "security@exаmplebank.example"}), KNOWN)  # Cyrillic a
        self.assertGreaterEqual(score, 0.5)
        self.assertIn("looks like examplebank.example", reasons[0])

    def test_encoded_international_sender_is_flagged(self):
        score, reasons = detect.phishing_score(email(**{"from": "security@xn--exmplebank-q9a.example"}), KNOWN)
        self.assertTrue(any("encoded international name" in r for r in reasons))

    def test_link_with_a_username_goes_where_it_really_goes(self):
        self.assertEqual(detect.domain_of("http://examplebank.example@evil.test/login"), "evil.test")
        score, reasons = detect.phishing_score(email(links=["http://examplebank.example@evil.test/login"]), KNOWN)
        self.assertIn("link goes to evil.test", reasons)

    def test_huge_message_is_scored_quickly(self):
        start = time.time()
        detect.phishing_score(email(body="verify immediately " * 60000), KNOWN)  # about 1 MB
        self.assertLess(time.time() - start, 2.0)

    def test_missing_fields_do_not_crash(self):
        m = email()
        del m["links"]
        detect.phishing_score(m, KNOWN)
        detect.call_score({"id": "c", "from": "+1-555-0000"}, [])

    def test_html_in_a_message_cannot_inject_into_the_report(self):
        from agent import brief
        inbox = detect.load("inbox.json", self.data)
        inbox.append(email(id="adv-x", **{"from": "support@paylinc.example",
                                          "subject": "<script>alert(1)</script> verify immediately",
                                          "body": "Log in now", "links": ["http://evil.test/x"]}))
        with open(os.path.join(self.data, "inbox.json"), "w") as f:
            json.dump(inbox, f)
        s = self.run_once()
        page = open(brief.report(s, os.path.join(self.tmp, "runs"), os.path.join(self.tmp, "r.html"), client_key="")).read()
        self.assertNotIn("<script>alert(1)", page)
        self.assertIn("&lt;script&gt;alert(1)", page)

    def test_a_duplicated_message_is_acted_on_once(self):
        inbox = detect.load("inbox.json", self.data)
        inbox.append(dict(next(m for m in inbox if m["id"] == "m-101")))
        with open(os.path.join(self.data, "inbox.json"), "w") as f:
            json.dump(inbox, f)
        self.run_once()
        with open(os.path.join(self.tmp, "outbox", "quarantine.jsonl")) as f:
            self.assertEqual(sum(1 for l in f if "m-101" in l), 1)


class Failures(Base):
    def test_amplitude_down_still_completes_and_records_the_error(self):
        os.environ["AMPLITUDE_API_KEY"] = "test-key"
        self.addCleanup(os.environ.pop, "AMPLITUDE_API_KEY", None)
        original = audit.AMPLITUDE_URL
        audit.AMPLITUDE_URL = "http://127.0.0.1:9/2/httpapi"  # nothing listens on the discard port
        self.addCleanup(setattr, audit, "AMPLITUDE_URL", original)
        s = self.run_once()
        self.assertEqual(s["threats"], 8)
        self.assertTrue(os.path.exists(os.path.join(self.tmp, "runs", s["run_id"] + ".jsonl.errors")))

    def test_model_down_falls_back_to_rules(self):
        for k, v in (("SIE_BASE_URL", "http://127.0.0.1:9"), ("SIE_API_KEY", "x"), ("SIE_MODEL", "m")):
            os.environ[k] = v
            self.addCleanup(os.environ.pop, k, None)
        label, by = models.classify("anything")
        self.assertEqual(label, "suspicious")
        self.assertIn("model error", by)


class QualityBar(unittest.TestCase):
    """The MVP bar on a month of synthetic data (agent/evaluate.py). See PLAN.md section 6."""

    def test_both_people_meet_the_bar_on_the_dev_set(self):
        for name in ("rose", "jordan"):
            r = evaluate.evaluate(name)
            self.assertTrue(r["meets_bar"], "%s: %s" % (name, json.dumps(r["passes"])))

    def test_held_out_set_is_still_safe(self):
        # Recall on unseen scams is measured, not asserted (see the eval report). Safety must hold regardless.
        for name in ("rose", "jordan"):
            r = evaluate.evaluate(name, variant="holdout")
            self.assertEqual(r["fp_actions"], 0, r["fp_action_cases"])
            self.assertEqual(r["repeats"], 0)


if __name__ == "__main__":
    unittest.main()
