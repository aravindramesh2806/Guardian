"""Guardian tests. Each test copies the sample data into a temp folder and uses a temp SQLite store."""
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
for _k in ("SIE_BASE_URL", "SINGLESTORE_HOST", "AMPLITUDE_API_KEY", "STATSIG_SERVER_SECRET", "STATSIG_CLIENT_KEY"):
    os.environ.pop(_k, None)

from agent import backfill, brief, detect, flags, metrics, respond
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
        # The "complete the loop" comparison: same data, gate on versus off.
        with open(os.path.join(self.data, "calls.json")) as f:
            calls = json.load(f)
        calls.append({"id": "c-299", "kind": "voicemail", "from": "+1-555-0999", "caller_id": "Unknown",
                      "at": "2026-11-20T15:00:00", "transcript": "Please call back about your gift card."})
        with open(os.path.join(self.data, "calls.json"), "w") as f:
            json.dump(calls, f)
        on = self.run_once()
        self.store = st.LocalStore(os.path.join(self.tmp, "t2.sqlite3"))
        off = runner.run(data_dir=self.data, run_dir=os.path.join(self.tmp, "runs2"),
                         outbox_dir=os.path.join(self.tmp, "outbox2"), store=self.store,
                         gate_check=lambda gate, user: {"value": gate not in (
                             "senior_protection", "kill_switch", "dispute_needs_approval"), "rule_id": "r1"})
        self.assertIn("suspicious:c-299", self.by_key(on))
        self.assertNotIn("suspicious:c-299", self.by_key(off))
        self.assertEqual(off["gates"]["senior_protection"], {"value": False, "source": "statsig"})


if __name__ == "__main__":
    unittest.main()


class MetricsTests(Base):
    def events(self, summary):
        return metrics.build_events(summary, detect.load("profile.json", self.data))

    def test_first_run_kpis(self):
        s = self.run_once()
        ev = self.events(s)
        types = [e["event_type"] for e in ev]
        self.assertEqual(types.count("guardian_threat_detected"), 8)
        self.assertEqual(types.count("guardian_run_completed"), 1)
        self.assertEqual(types.count("guardian_family_notified"), s["family_told"])
        self.assertEqual(types.count("guardian_needs_attention"), s["waiting_for_you"])
        run = next(e for e in ev if e["event_type"] == "guardian_run_completed")["event_properties"]
        self.assertEqual(run["money_protected_usd"], 389.0)
        self.assertEqual(sum(run["threats_by_kind"].values()), 8)
        self.assertEqual(len({e["insert_id"] for e in ev}), len(ev))
        self.assertEqual(len({e["session_id"] for e in ev}), 1)

    def test_second_run_counts_nothing_twice(self):
        self.run_once()
        ev = self.events(self.run_once())
        types = {e["event_type"] for e in ev}
        self.assertNotIn("guardian_threat_detected", types)
        self.assertNotIn("guardian_money_protected", types)
        self.assertIn("guardian_needs_attention", types)  # the dispute is still waiting
        run = next(e for e in ev if e["event_type"] == "guardian_run_completed")
        self.assertTrue(run["event_properties"]["all_clear"])
        self.assertEqual(run["user_properties"]["$add"]["lifetime_threats"], 0)

    def test_nothing_sent_without_keys(self):
        s = self.run_once()
        self.assertEqual(s["metrics"]["sent"], {"amplitude": 0, "statsig": 0})

    def test_statsig_shape(self):
        ev = self.events(self.run_once())
        money = metrics.to_statsig(next(e for e in ev if e["event_type"] == "guardian_money_protected"))
        self.assertEqual(money["value"], 389.0)
        self.assertTrue(all(isinstance(v, str) for v in money["metadata"].values()))

    def test_backfill_is_synthetic_and_repeatable(self):
        a = backfill.build(days=5, users=4, seed=1, now=1.8e9)
        b = backfill.build(days=5, users=4, seed=1, now=1.8e9)
        self.assertEqual([e["insert_id"] for e in a], [e["insert_id"] for e in b])
        self.assertTrue(all(e["user_id"].startswith("synthetic-") for e in a))
        self.assertTrue(all(e["event_properties"]["is_synthetic"] for e in a))

    def test_report_has_amplitude_tag_only_with_key(self):
        s = self.run_once()
        self.assertEqual(brief.amplitude_script(s, ""), "")
        self.assertIn("guardian_threat_opened", brief.amplitude_script(s, "k"))
