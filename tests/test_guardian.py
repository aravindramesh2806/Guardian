"""Guardian tests. Each test copies the sample data into a temp folder and uses a temp SQLite store."""
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
for _k in ("SIE_BASE_URL", "SINGLESTORE_HOST", "AMPLITUDE_API_KEY"):
    os.environ.pop(_k, None)

from agent import brief, detect, respond
from agent import run as runner
from agent import store as st

SAMPLE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.data = os.path.join(self.tmp, "data")
        shutil.copytree(SAMPLE, self.data)
        self.store = st.LocalStore(os.path.join(self.tmp, "t.sqlite3"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def edit(self, name, **changes):
        path = os.path.join(self.data, name)
        with open(path) as f:
            obj = json.load(f)
        obj.update(changes)
        with open(path, "w") as f:
            json.dump(obj, f)

    def run_once(self):
        return runner.run(data_dir=self.data, run_dir=os.path.join(self.tmp, "runs"),
                          outbox_dir=os.path.join(self.tmp, "outbox"), store=self.store, now="2026-11-20T14:00:00")

    @staticmethod
    def by_key(summary):
        return {r["threat"]: r for r in summary["results"]}

    @staticmethod
    def status(result, action):
        return next(a["status"] for a in result["actions"] if a["action"] == action)


class DetectorTests(Base):
    def test_finds_every_sample_threat_and_nothing_else(self):
        keys = {t["key"] for t in detect.all_threats(self.data)}
        self.assertEqual(keys, {
            "scam:c-201", "scam:c-202", "scam:c-203", "charge:tx-4", "takeover:m-102",
            "phishing:m-101", "merchant-breach:BR-1101", "breach:BR-1088:rose.demo@example.com"})

    def test_requested_reset_is_not_a_takeover(self):
        self.assertNotIn("takeover:m-103", {t["key"] for t in detect.all_threats(self.data)})

    def test_normal_email_calls_and_known_charges_are_not_flagged(self):
        keys = " ".join(t["key"] for t in detect.all_threats(self.data))
        for safe in ("m-104", "m-105", "c-204", "c-205", "tx-1", "tx-2", "tx-3", "tx-5", "BR-0920"):
            self.assertNotIn(safe, keys)

    def test_spoofed_bank_caller_id_is_explained(self):
        t = next(t for t in detect.all_threats(self.data) if t["key"] == "scam:c-201")
        self.assertTrue(any("real number is +1-555-0199" in r for r in t["evidence"]["reasons"]))

    def test_senior_mode_lowers_the_bar(self):
        borderline = {"id": "x", "kind": "voicemail", "from": "+1-555-0999", "caller_id": "Unknown",
                      "at": "2026-11-20T09:00:00", "transcript": "Please call back about your gift card."}
        prof = detect.load("profile.json", self.data)
        self.assertEqual(len(detect.scam_calls(prof, [borderline])), 1)
        prof["protection"] = "standard"
        self.assertEqual(len(detect.scam_calls(prof, [borderline])), 0)

    def test_scam_calls_come_first(self):
        self.assertEqual(detect.all_threats(self.data)[0]["kind"], "scam_call")


class ResponseTests(Base):
    def test_first_run_actions(self):
        s = self.run_once()
        r = self.by_key(s)
        self.assertIn("blocked", self.status(r["scam:c-201"], "block_number"))
        self.assertIn("Sam (daughter) told", self.status(r["scam:c-202"], "notify_trusted"))
        self.assertIn("quarantined", self.status(r["phishing:m-101"], "quarantine"))
        self.assertIn("locked", self.status(r["charge:tx-4"], "lock_card"))
        self.assertIn("already done", self.status(r["merchant-breach:BR-1101"], "lock_card"))
        self.assertEqual(self.status(r["charge:tx-4"], "dispute"), "waiting for you")
        self.assertEqual((s["threats"], s["stopped"], s["family_told"], s["waiting_for_you"]), (8, 5, 3, 1))

    def test_card_is_locked_once_even_when_two_threats_need_it(self):
        self.run_once()
        with open(os.path.join(self.tmp, "outbox", "card_locks.jsonl")) as f:
            self.assertEqual(len(f.readlines()), 1)

    def test_second_run_repeats_nothing(self):
        self.run_once()
        s = self.run_once()
        self.assertEqual((s["new_threats"], s["stopped"], s["alerts"], s["family_told"]), (0, 0, 0, 0))
        self.assertEqual(s["waiting_for_you"], 1)

    def test_approved_dispute_runs_on_the_next_run(self):
        self.run_once()
        self.edit("gates.json", dispute_needs_approval=False)
        r = self.by_key(self.run_once())
        self.assertEqual(self.status(r["charge:tx-4"], "dispute"), "dispute filed (simulated)")

    def test_no_persona_pass_means_no_card_lock(self):
        self.edit("verification.json", result="failed")
        r = self.by_key(self.run_once())
        self.assertEqual(self.status(r["charge:tx-4"], "lock_card"), "waiting for you")

    def test_kill_switch_stops_actions_but_still_alerts(self):
        self.edit("gates.json", kill_switch=True)
        s = self.run_once()
        self.assertEqual(s["stopped"], 0)
        self.assertEqual(s["family_told"], 0)
        self.assertEqual(s["alerts"], 7)  # every threat but the phishing email, which is quarantined instead

    def test_family_needs_consent(self):
        prof = detect.load("profile.json", self.data)
        prof["trusted_contacts"][0]["consent"] = False
        threat = next(t for t in detect.all_threats(self.data) if t["kind"] == "scam_call")
        act = respond.decide(threat, prof)[-1]
        ok, reason = respond.guard(act, detect.load("gates.json", self.data), {"result": "passed"}, prof)
        self.assertFalse(ok)
        self.assertIn("has not agreed", reason)

    def test_alert_has_exact_steps_without_a_model(self):
        t = next(t for t in detect.all_threats(self.data) if t["key"] == "charge:tx-4")
        text, by = respond.alert_text(t, detect.load("profile.json", self.data))
        self.assertEqual(by, "template")
        self.assertIn("$389.00", text)
        self.assertIn("1.", text)


class BriefTests(Base):
    def test_brief_is_short_and_leads_with_scams(self):
        lines = brief.brief_lines(self.run_once())
        self.assertLessEqual(len(lines), 5)
        self.assertIn("family was told about 3", lines[0])
        self.assertIn("Scam", lines[1])
        self.assertTrue(any(l.startswith("Needs you: Dispute $389.00") for l in lines))

    def test_brief_says_all_clear_when_nothing_is_new(self):
        self.run_once()
        self.assertEqual(brief.brief_lines(self.run_once()), ["All clear: nothing new since your last check."])

    def test_audit_trail_covers_every_threat(self):
        s = self.run_once()
        with open(os.path.join(self.tmp, "runs", s["run_id"] + ".jsonl")) as f:
            rows = [json.loads(l) for l in f]
        self.assertEqual({r["subject_id"] for r in rows}, set(self.by_key(s)))


if __name__ == "__main__":
    unittest.main()
