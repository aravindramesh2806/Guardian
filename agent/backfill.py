"""Fill Amplitude and Statsig with history so dashboards have something to show.

Simulates daily Guardian runs for a set of fictional users over the past N days. Each threat goes
through the real respond.decide and respond.guard, so outcomes follow the same rules as a live run.
Events are built by metrics.build_events, the same code a live run uses.

Every event and user is marked is_synthetic=true and user ids start with "synthetic-", so this data
is easy to filter out later. insert_ids are deterministic for a given --seed: sending twice does not
double count.

    python3 agent/backfill.py --days 30 --users 40 --dry-run   # counts only, nothing sent
    python3 agent/backfill.py --days 30 --users 40             # send to every tool with a key set
"""
import argparse
import json
import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent import metrics, respond

# Average threats per user per day, by kind. Seniors are targeted by calls far more often.
RATES = {"senior": {"scam_call": 0.35, "suspicious": 0.15, "phishing": 0.30, "card_misuse": 0.04,
                    "takeover": 0.05, "merchant_breach": 0.02, "identity_breach": 0.03},
         "standard": {"scam_call": 0.12, "suspicious": 0.08, "phishing": 0.35, "card_misuse": 0.04,
                      "takeover": 0.06, "merchant_breach": 0.02, "identity_breach": 0.04}}
MERCHANTS = ["QX DIGITAL SVCS", "ZETA ONLINE", "GLOBAL GIFT HUB", "FASTPAY*LTD", "NOVA MARKET"]
CALL_KINDS = ["voicemail", "voicemail", "call", "sms", "sms"]
DECIDERS = ["rules", "rules", "rules", "superlinked-sie"]


def make_user(i, rng):
    """A fictional user with a cohort that decides their gates."""
    senior = rng.random() < 0.6
    cohort = rng.choices(["default", "cautious", "hands_off"], weights=[70, 20, 10])[0]
    gates = {"senior_protection": senior, "auto_quarantine": True, "auto_block_numbers": True,
             "auto_lock_card": cohort != "cautious", "notify_trusted_contacts": True,
             "dispute_needs_approval": cohort != "hands_off", "kill_switch": rng.random() < 0.03}
    if senior and rng.random() < 0.25:  # the Statsig experiment: senior bar turned off for some
        gates["senior_protection"] = False
    n_contacts = rng.choice([0, 1, 1, 2]) if senior else rng.choice([0, 0, 1])
    profile = {
        "user_id": "synthetic-user-%03d" % i, "protection": "senior" if senior else "standard",
        "emails": ["user%d.%d@example.com" % (i, k) for k in range(rng.choice([1, 2]))],
        "accounts": [{"name": "Acct%d" % k, "domain": "acct%d.example" % k} for k in range(rng.randint(3, 8))],
        "cards": [{"id": "card-%d-%d" % (i, k), "last4": "%04d" % rng.randint(0, 9999),
                   "issuer": "Example Bank", "issuer_lock_api": rng.random() < 0.7}
                  for k in range(rng.randint(1, 3))],
        "trusted_contacts": [{"name": "Contact %d" % k, "channel": "sms", "address": "+1-555-01%02d" % k,
                              "consent": rng.random() < 0.85} for k in range(n_contacts)],
    }
    verification = {"result": "passed" if rng.random() < 0.8 else "pending"}
    return profile, gates, verification, cohort


def make_threat(kind, uid, day, n, profile, rng):
    key = "%s:%s:d%d:%d" % (kind, uid, day, n)
    card = rng.choice(profile["cards"])["id"]
    sev = "high" if kind in ("scam_call", "card_misuse", "takeover") else rng.choice(["high", "medium"])
    if kind == "suspicious":
        sev = "medium"
    ev = {"decided_by": rng.choice(DECIDERS)}
    if kind in ("scam_call", "suspicious"):
        ev.update({"kind": rng.choice(CALL_KINDS), "from": "+1-555-%04d" % rng.randint(200, 999),
                   "score": round(rng.uniform(0.3 if kind == "suspicious" else 0.5, 1.0), 2)})
    elif kind == "phishing":
        ev.update({"email": "m-%s" % key, "score": round(rng.uniform(0.7, 1.0), 2)})
    elif kind == "card_misuse":
        ev.update({"transaction": "tx-" + key, "card": card, "merchant": rng.choice(MERCHANTS),
                   "amount": round(rng.choice([rng.uniform(15, 120), rng.uniform(120, 900)]), 2),
                   "date": "day-%d" % day})
    elif kind == "merchant_breach":
        ev.update({"card": card, "merchant": rng.choice(MERCHANTS)})
    elif kind == "takeover":
        ev.update({"account": rng.choice(profile["accounts"])["name"]})
    else:
        ev.update({"domains": [rng.choice(profile["accounts"])["domain"]]})
    return {"kind": kind, "key": key, "severity": sev, "summary": kind.replace("_", " "), "evidence": ev}


def simulate(threat, profile, gates, verification):
    """What a run would do with this threat, without writing to the outbox."""
    actions = []
    for a in respond.decide(threat, profile):
        allowed, reason = respond.guard(a, gates, verification, profile)
        if allowed:
            status = "%s (simulated)" % a["type"]
            out = {"action": a["type"], "status": status, "reason": reason}
            if a["type"] == "alert":
                out["drafted_by"] = threat["evidence"]["decided_by"].replace("rules", "template")
        else:
            out = {"action": a["type"], "status": "waiting for you", "reason": reason}
            if a["type"] == "dispute":
                out["ask"] = "Dispute $%.2f at %s?" % (a["amount"], a["merchant"])
        actions.append(out)
    return {"threat": threat["key"], "kind": threat["kind"], "severity": threat["severity"],
            "summary": threat["summary"], "evidence": threat["evidence"], "new": True, "actions": actions}


def poisson(rate, rng):
    n, p, limit = 0, 1.0, 2.718281828 ** -rate
    while True:
        p *= rng.random()
        if p <= limit:
            return n
        n += 1


def build(days, users, seed=7, now=None):
    rng = random.Random(seed)
    now = now or time.time()
    events = []
    for i in range(users):
        profile, gates, verification, cohort = make_user(i, rng)
        uid = profile["user_id"]
        start = rng.randint(0, days // 3)  # users join over the first third of the window
        for day in range(start, days):
            if rng.random() < 0.08:
                continue  # some days the agent did not run (phone off, travel)
            results = []
            # senior_protection off: borderline calls slip through, so fewer calls get caught
            for kind, rate in RATES[profile["protection"]].items():
                if kind == "scam_call" and profile["protection"] == "senior" and not gates["senior_protection"]:
                    rate *= 0.7
                for n in range(poisson(rate, rng)):
                    results.append(simulate(make_threat(kind, uid, day, n, profile, rng), profile, gates, verification))

            def count(pred):
                return sum(1 for r in results for a in r["actions"] if pred(a))
            run_time = now - (days - day) * 86400 + rng.randint(6 * 3600, 9 * 3600) - 12 * 3600
            run_id = "synthetic-run-%s-d%03d" % (uid, day)
            summary = {
                "run_id": run_id, "store": "sqlite", "persona": verification["result"],
                "threats": len(results), "new_threats": len(results),
                "stopped": count(lambda a: a["action"] in metrics.DONE_TYPES and a["status"].endswith("(simulated)")),
                "alerts": count(lambda a: a["action"] == "alert" and a["status"].endswith("(simulated)")),
                "family_told": count(lambda a: a["action"] == "notify_trusted" and a["status"].endswith("(simulated)")),
                "waiting_for_you": count(lambda a: a["status"] == "waiting for you"),
                "gates": {k: {"value": v, "source": "synthetic"} for k, v in gates.items()},
                "duration_ms": rng.randint(300, 4000), "results": results}
            events += metrics.build_events(summary, profile, user_id=uid, time_ms=int(run_time * 1000),
                                           extra={"is_synthetic": True, "cohort": cohort})
    return events


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--days", type=int, default=30)
    p.add_argument("--users", type=int, default=40)
    p.add_argument("--seed", type=int, default=7)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--only", choices=["amplitude", "statsig"])
    args = p.parse_args(argv)
    from agent.run import load_env
    load_env()
    events = build(args.days, args.users, args.seed)
    by_type = {}
    for e in events:
        by_type[e["event_type"]] = by_type.get(e["event_type"], 0) + 1
    print(json.dumps({"events": len(events), "by_type": by_type}, indent=2))
    if args.dry_run:
        return
    if args.only != "statsig":
        print("amplitude:", metrics.send_amplitude(events, batch=True) or "skipped (no AMPLITUDE_API_KEY)")
    if args.only != "amplitude":
        print("statsig:", metrics.send_statsig(events) or "skipped (no STATSIG_SERVER_SECRET)")


if __name__ == "__main__":
    main()
