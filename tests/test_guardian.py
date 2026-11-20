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

from agent import brief, detect, flags, respond
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
            "phishing:m-101", "merchant-breach:BR-1101", "breach:BR-1088:rose.demo@example.com",
            "suspicious:c-206"})

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
        self.assertEqual((s["threats"], s["stopped"], s["family_told"], s["waiting_for_you"]), (9, 5, 3, 1))

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

    def test_approving_one_dispute_files_only_that_dispute(self):
        self.run_once()
        runs = os.path.join(self.tmp, "runs")
        runner.approve("dispute:tx-4", run_dir=runs, store=self.store, now="2026-11-20T14:05:00")
        r = self.by_key(self.run_once())["charge:tx-4"]
        self.assertEqual(self.status(r, "dispute"), "dispute filed (simulated)")
        self.assertEqual(detect.load("gates.json", self.data)["dispute_needs_approval"], True)
        with open(os.path.join(runs, sorted(f for f in os.listdir(runs) if f.endswith(".jsonl"))[-1])) as f:
            guard = [json.loads(l) for l in f if '"guard_dispute"' in l][0]
        self.assertIn("you approved this dispute at 2026-11-20T14:05:00", guard["output"]["reason"])
        s = self.run_once()
        self.assertEqual(s["waiting_for_you"], 0)
        self.assertIn("already done", self.status(self.by_key(s)["charge:tx-4"], "dispute"))

    def test_approve_refuses_what_is_not_waiting(self):
        self.run_once()
        with self.assertRaises(SystemExit):
            runner.approve("dispute:tx-999", run_dir=os.path.join(self.tmp, "runs"), store=self.store)

    def test_no_persona_pass_means_no_card_lock(self):
        self.edit("verification.json", result="failed")
        r = self.by_key(self.run_once())
        self.assertEqual(self.status(r["charge:tx-4"], "lock_card"), "waiting for you")

    def test_kill_switch_stops_actions_but_still_alerts(self):
        self.edit("gates.json", kill_switch=True)
        s = self.run_once()
        self.assertEqual(s["stopped"], 0)
        self.assertEqual(s["family_told"], 0)
        self.assertEqual(s["alerts"], 8)  # every threat but the phishing email, which is quarantined instead

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

    def test_brief_reports_an_approved_dispute(self):
        self.run_once()
        runner.approve("dispute:tx-4", run_dir=os.path.join(self.tmp, "runs"), store=self.store)
        lines = brief.brief_lines(self.run_once())
        self.assertTrue(lines[0].startswith("Nothing new"))
        self.assertIn("dispute filed", lines[1])

    def test_report_shows_messages_and_how_to_approve(self):
        s = self.run_once()
        out = os.path.join(self.tmp, "report.html")
        page = open(brief.report(s, os.path.join(self.tmp, "runs"), out, client_key="")).read()
        self.assertIn("To Rose", page)
        self.assertIn("Do not call back, pay, or share any code.", page)
        self.assertIn("To Sam (daughter)", page)
        self.assertIn("python3 agent/run.py --approve dispute:tx-4", page)
        # On a repeat run the messages still show, from the store.
        page = open(brief.report(self.run_once(), os.path.join(self.tmp, "runs"), out, client_key="")).read()
        self.assertIn("To Sam (daughter)", page)

    def test_report_trail_is_plain_language(self):
        s = self.run_once()
        with open(brief.report(s, os.path.join(self.tmp, "runs"), os.path.join(self.tmp, "r.html"), client_key="")) as f:
            page = f.read()
        self.assertIn("Example Bank&#x27;s real number is +1-555-0199</li>", page)  # a full reason, not cut off
        self.assertIn("gate auto_block_numbers on (local)", page)
        self.assertIn("Persona live_human_presence: passed", page)
        self.assertIn("Tell family: Sam (daughter) agreed to be told about serious scams", page)
        self.assertIn("File a dispute: disputes wait for your confirmation", page)
        self.assertIn("Raw events (7)", page)

    def test_audit_trail_covers_every_threat(self):
        s = self.run_once()
        with open(os.path.join(self.tmp, "runs", s["run_id"] + ".jsonl")) as f:
            rows = [json.loads(l) for l in f]
        self.assertEqual({r["subject_id"] for r in rows} - {"run"}, set(self.by_key(s)))
        self.assertEqual(rows[0]["tool"], "check_gates")
        self.assertTrue(all(r["gates"]["auto_block_numbers"] is True for r in rows[1:]))


class PageTests(Base):
    def test_statsig_only_with_a_client_key(self):
        s = self.run_once()
        runs = os.path.join(self.tmp, "runs")
        without = brief.report(s, runs, os.path.join(self.tmp, "a.html"), client_key="")
        withkey = brief.report(s, runs, os.path.join(self.tmp, "b.html"), client_key="client-test")
        self.assertNotIn("statsig.min.js", open(without).read())
        page = open(withkey).read()
        self.assertIn('new StatsigClient("client-test"', page)
        self.assertIn("StatsigSessionReplayPlugin()", page)
        self.assertIn("guardian_report_viewed", page)
        self.assertIn("data-kind='scam_call'", page)
        self.assertIn("Gates: senior_protection on (local)", page)


class FlagTests(Base):
    def test_local_gates_when_no_statsig_key(self):
        os.environ.pop("STATSIG_SERVER_SECRET", None)
        snap = flags.snapshot(detect.load("gates.json", self.data), detect.load("profile.json", self.data))
        self.assertEqual(snap["senior_protection"], {"value": True, "source": "local"})
        self.assertEqual(snap["kill_switch"], {"value": False, "source": "local"})

    def test_statsig_answer_wins_and_is_labelled(self):
        snap = flags.snapshot({}, {}, check=lambda gate, user: {"value": gate == "kill_switch", "rule_id": "r1"})
        self.assertEqual(snap["kill_switch"], {"value": True, "source": "statsig"})
        self.assertEqual(snap["senior_protection"]["source"], "statsig")

    def test_gate_not_set_up_in_statsig_keeps_the_safe_local_value(self):
        snap = flags.snapshot({"dispute_needs_approval": True, "auto_block_numbers": True}, {},
                              check=lambda gate, user: {"value": False, "rule_id": None})
        self.assertEqual(snap["dispute_needs_approval"], {"value": True, "source": "local (not in Statsig)"})
        self.assertTrue(snap["auto_block_numbers"]["value"])

    def test_statsig_failure_falls_back_to_local(self):
        def broken(gate, user):
            raise OSError("unreachable")
        snap = flags.snapshot({"auto_lock_card": True}, {}, check=broken)
        self.assertTrue(snap["auto_lock_card"]["value"])
        self.assertIn("statsig error: OSError", snap["auto_lock_card"]["source"])

    def test_senior_gate_off_misses_the_borderline_call(self):
        # The "complete the loop" demo beat: the shipped data, gate on versus off.
        on = self.run_once()
        self.store = st.LocalStore(os.path.join(self.tmp, "t2.sqlite3"))
        off = runner.run(data_dir=self.data, run_dir=os.path.join(self.tmp, "runs2"),
                         outbox_dir=os.path.join(self.tmp, "outbox2"), store=self.store,
                         gate_check=lambda gate, user: {"value": gate not in (
                             "senior_protection", "kill_switch", "dispute_needs_approval"), "rule_id": "r1"})
        self.assertIn("suspicious:c-206", self.by_key(on))
        self.assertNotIn("suspicious:c-206", self.by_key(off))
        self.assertEqual(off["gates"]["senior_protection"], {"value": False, "source": "statsig"})


if __name__ == "__main__":
    unittest.main()
