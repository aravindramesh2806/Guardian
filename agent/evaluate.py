"""Score Guardian against the MVP quality bar on synthetic people (agent/synthetic.py).

    python3 agent/evaluate.py            # both people, prints the scorecard, writes runs/eval/
    python3 agent/evaluate.py rose

Replays 30 days, one run per evening, against a fresh local store, with no network services (Statsig,
Amplitude, SingleStore, the model and Firedrill are switched off for the run). Each day sees only the
items that existed by then, so this is also the 30-day soak: nothing may be repeated across days.

The bar (PLAN.md, section 6):
  - zero automatic actions on legitimate items
  - at least 90% of threats flagged
  - fewer than 2 alerts to the person per day on average
  - no action carried out twice
"""
import json
import os
import shutil
import sys
import tempfile
from collections import Counter, defaultdict
from datetime import date, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent import respond, synthetic
from agent import run as runner
from agent import store as st

OFFLINE = ("STATSIG_SERVER_SECRET", "AMPLITUDE_API_KEY", "SIE_BASE_URL", "SIE_API_KEY", "SIE_MODEL",
           "SINGLESTORE_HOST", "GUARDIAN_GMAIL_URL", "GUARDIAN_STRIPE_URL", "GUARDIAN_SLACK_URL")
BAR = {"fp_actions": 0, "recall": 0.90, "alerts_per_day": 2.0, "repeats": 0}
GATES = {"auto_quarantine": True, "auto_lock_card": True, "dispute_needs_approval": True, "kill_switch": False,
         "auto_block_numbers": True, "notify_trusted_contacts": True}
EVIDENCE_IDS = ("email", "call", "transaction", "breach")


def _write(folder, name, obj):
    with open(os.path.join(folder, name), "w") as f:
        json.dump(obj, f)


def _day_files(world, folder, day):
    """The data as it stood on the evening of `day`."""
    os.makedirs(folder, exist_ok=True)
    cut = day.isoformat()
    _write(folder, "profile.json", world["profile"])
    _write(folder, "inbox.json", [m for m in world["inbox"] if m["received"][:10] <= cut])
    _write(folder, "calls.json", [c for c in world["calls"] if c["at"][:10] <= cut])
    _write(folder, "transactions.json", [t for t in world["transactions"] if t["date"] <= cut])
    _write(folder, "receipts.json", [r for r in world["receipts"] if r["date"] <= cut])
    _write(folder, "breaches.json", [b for b in world["breaches"] if b["disclosed"] <= cut])
    _write(folder, "gates.json", GATES)
    _write(folder, "verification.json", {"claim_type": "live_human_presence", "result": "passed",
                                         "checked_at": cut + "T08:00:00", "source": "synthetic"})


def evaluate(name, seed=7, days=30, workdir=None, variant="dev"):
    saved = {k: os.environ.pop(k) for k in OFFLINE if k in os.environ}
    own_tmp = workdir is None
    workdir = workdir or tempfile.mkdtemp(prefix="guardian-eval-")
    try:
        world = synthetic.generate(name, seed, days, variant)
        items = {i["id"]: i for key in ("inbox", "calls", "transactions", "breaches") for i in world[key]}
        store = st.LocalStore(os.path.join(workdir, "store.sqlite3"))
        run_dir, outbox = os.path.join(workdir, "runs"), os.path.join(workdir, "outbox")
        flagged = defaultdict(list)      # item id -> [(kind, severity)]
        acted = defaultdict(list)        # item id -> ["quarantine (simulated)", ...] (non-alert actions done)
        alerts_by_day, done_keys = [], Counter()
        for d_i in range(days):
            day = synthetic.START + timedelta(days=d_i)
            folder = os.path.join(workdir, "data")
            _day_files(world, folder, day)
            s = runner.run(data_dir=folder, run_dir=run_dir, outbox_dir=outbox, store=store,
                           now=day.isoformat() + "T21:00:00")
            alerts_by_day.append(s["alerts"])
            for r in s["results"]:
                ids = [r["evidence"][k] for k in EVIDENCE_IDS if isinstance(r["evidence"].get(k), str)]
                for a in r["actions"]:
                    if respond.is_done(a["status"]):
                        done_keys[(r["threat"], a["action"])] += 1
                if not r["new"]:
                    continue
                for item_id in ids:
                    flagged[item_id].append((r["kind"], r["severity"]))
                    acted[item_id] += [a["action"] for a in r["actions"]
                                       if a["action"] != "alert" and respond.is_done(a["status"])]
        threats = [i for i in items.values() if i["_truth"] == "threat"]
        legit = [i for i in items.values() if i["_truth"] == "legit"]
        caught = [i for i in threats if flagged.get(i["id"])]
        missed = Counter(i["_case"] for i in threats if not flagged.get(i["id"]))
        weak = Counter(i["_case"] for i in threats
                       if flagged.get(i["id"]) and all(sev != "high" for _, sev in flagged[i["id"]]))
        fp_flag = Counter(i["_case"] for i in legit if flagged.get(i["id"]))
        fp_act = Counter("%s -> %s" % (i["_case"], "+".join(sorted(set(acted[i["id"]]))))
                         for i in legit if acted.get(i["id"]))
        result = {
            "person": name, "variant": variant, "seed": seed, "days": days,
            "items": {"threat": len(threats), "legit": len(legit)},
            "recall": round(len(caught) / max(len(threats), 1), 3),
            "caught_as_high": len(caught) - sum(weak.values()),
            "missed": dict(missed), "caught_only_as_suspicious": dict(weak),
            "fp_flags": sum(fp_flag.values()), "fp_flag_cases": dict(fp_flag),
            "fp_actions": sum(fp_act.values()), "fp_action_cases": dict(fp_act),
            "alerts_per_day": round(sum(alerts_by_day) / days, 2), "alerts_max_day": max(alerts_by_day),
            "repeats": sum(1 for n in done_keys.values() if n > 1),
        }
        result["passes"] = {
            "zero_auto_actions_on_legit": result["fp_actions"] <= BAR["fp_actions"],
            "recall_at_least_90pct": result["recall"] >= BAR["recall"],
            "under_2_alerts_a_day": result["alerts_per_day"] < BAR["alerts_per_day"],
            "nothing_repeated": result["repeats"] <= BAR["repeats"],
        }
        result["meets_bar"] = all(result["passes"].values())
        return result
    finally:
        os.environ.update(saved)
        if own_tmp:
            shutil.rmtree(workdir, ignore_errors=True)


def show(r):
    mark = lambda ok: "PASS" if ok else "FAIL"
    p = r["passes"]
    print("\n== %s (%s set): %d threats, %d legitimate items, %d days" % (
        r["person"], r["variant"], r["items"]["threat"], r["items"]["legit"], r["days"]))
    print("  %s  threats flagged       %5.1f%%   (bar 90%%; %d of them as high severity)" % (
        mark(p["recall_at_least_90pct"]), r["recall"] * 100, r["caught_as_high"]))
    print("  %s  auto actions on legit %5d    (bar 0)" % (mark(p["zero_auto_actions_on_legit"]), r["fp_actions"]))
    print("  %s  alerts per day        %5.2f    (bar under 2; busiest day %d)" % (
        mark(p["under_2_alerts_a_day"]), r["alerts_per_day"], r["alerts_max_day"]))
    print("  %s  actions repeated      %5d    (bar 0)" % (mark(p["nothing_repeated"]), r["repeats"]))
    print("  info  legit items flagged  %5d    (alerts the person did not need)" % r["fp_flags"])
    for title, key in (("missed threats", "missed"), ("caught only as 'suspicious'", "caught_only_as_suspicious"),
                       ("legit items acted on", "fp_action_cases"), ("legit items flagged", "fp_flag_cases")):
        if r[key]:
            print("  %s: %s" % (title, ", ".join("%s x%d" % kv for kv in sorted(r[key].items()))))


if __name__ == "__main__":
    args = sys.argv[1:]
    variant = "holdout" if "--holdout" in args else "dev"
    names = [a for a in args if not a.startswith("--")] or ["rose", "jordan"]
    out_dir = os.path.join(runner.ROOT, "runs", "eval")
    os.makedirs(out_dir, exist_ok=True)
    results = [evaluate(n, variant=variant) for n in names]
    for r in results:
        show(r)
        with open(os.path.join(out_dir, "%s-%s.json" % (r["person"], variant)), "w") as f:
            json.dump(r, f, indent=2)
    print("\nOverall: %s" % ("MEETS THE BAR" if all(r["meets_bar"] for r in results) else "DOES NOT MEET THE BAR yet"))
