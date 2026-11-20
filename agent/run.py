"""Run Guardian once: detect threats, decide, check gates, act, write back, and record every step."""
import json
import os
import sys
import time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent import detect, flags, respond
from agent import store as st
from agent.audit import AuditLog

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_env(path=os.path.join(ROOT, ".env")):
    """Read KEY=value lines from .env into the environment, without overriding what is already set."""
    if not os.path.exists(path):
        return
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                if value.strip():
                    os.environ.setdefault(key.strip(), value.strip())


def load_approvals(run_dir):
    """Action keys the person said yes to, mapped to when. Kept beside the runs, so a fresh start clears it."""
    path = os.path.join(run_dir, "approvals.json")
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        return json.load(f)


def approve(key, run_dir=None, store=None, now=None):
    """Say yes to one held action (for example dispute:tx-4). It runs on the next run, and only it."""
    run_dir = run_dir or os.path.join(ROOT, "runs")
    store = store or st.open_store(os.path.join(run_dir, "guardian.sqlite3"))
    held = st.waiting(store)
    if key not in held:
        raise SystemExit("nothing waiting for you as %r; waiting: %s" % (key, ", ".join(held) or "nothing"))
    approvals = load_approvals(run_dir)
    approvals[key] = now or datetime.now().isoformat(timespec="seconds")
    os.makedirs(run_dir, exist_ok=True)
    with open(os.path.join(run_dir, "approvals.json"), "w") as f:
        json.dump(approvals, f, indent=2)
    return approvals


def load_incoming(run_dir):
    """Calls and texts that arrived during the day (--incoming). Kept beside the runs, like real new data."""
    path = os.path.join(run_dir, "incoming.json")
    if not os.path.exists(path):
        return []
    with open(path) as f:
        return json.load(f)


def receive(path, run_dir=None):
    """A new call or text arrives: add it to what Guardian will see on this and every later run."""
    run_dir = run_dir or os.path.join(ROOT, "runs")
    with open(path) as f:
        new = json.load(f)
    new = new.get("calls", []) if isinstance(new, dict) else new
    have = load_incoming(run_dir)
    ids = {c["id"] for c in have}
    have += [c for c in new if c["id"] not in ids]
    os.makedirs(run_dir, exist_ok=True)
    with open(os.path.join(run_dir, "incoming.json"), "w") as f:
        json.dump(have, f, indent=2)
    return new


def message(result):
    """The message an action sent, if it sent one: who it went to, how, and the text."""
    if result.get("text") and result.get("to"):
        return {"to": result["to"], "channel": result.get("channel", ""), "text": result["text"],
                "drafted_by": result.get("drafted_by")}
    return None


def handle(threat, ctx):
    """Work one threat end to end. New threats are recorded; held actions are retried each run."""
    log, store, run_id, now = ctx["log"], ctx["store"], ctx["run_id"], ctx["now"]
    log.event("detect", "detect_" + threat["kind"], {"key": threat["key"]},
              {"summary": threat["summary"], "evidence": threat["evidence"]}, threat["key"])
    is_new = not st.threat_seen(store, threat["key"])
    if is_new:
        st.save_threat(store, threat, run_id, now)

    outcomes = []
    for action in respond.decide(threat, ctx["profile"]):
        done = st.action_done(store, action["key"])
        if done:
            try:
                earlier = json.loads(done.get("detail") or "{}")
            except ValueError:
                earlier = {}
            outcomes.append({"action": action["type"], "status": "already done in " + done["run_id"],
                             "message": message(earlier)})
            log.event("check_history", "check_history", {"action": action["key"]},
                      {k: v for k, v in done.items() if k != "detail"}, threat["key"])
            continue
        allowed, reason = respond.guard(action, ctx["gates"], ctx["verification"], ctx["profile"],
                                        ctx["approvals"])
        log.event("guard", "guard_" + action["type"], {"action": action["key"]},
                  {"allowed": allowed, "reason": reason}, threat["key"])
        if allowed:
            result = respond.act(action, threat, ctx["profile"], ctx["outbox_dir"])
        else:
            result = respond.held(action, threat, ctx["profile"], reason)
        log.event("act", "act_" + action["type"], {"action": action["key"]}, result, threat["key"])
        st.save_action(store, action, threat["key"], result, run_id, now)
        outcomes.append({"action": action["type"], "status": result["status"],
                         "reason": result.get("reason", reason), "ask": result.get("ask"),
                         "approve": result.get("approve"), "message": message(result)})
    return {"threat": threat["key"], "kind": threat["kind"], "severity": threat["severity"],
            "summary": threat["summary"], "evidence": threat["evidence"], "new": is_new, "actions": outcomes}


def run(data_dir=None, run_dir=None, outbox_dir=None, store=None, now=None, gate_check=None):
    run_id = "run-" + time.strftime("%Y%m%d-%H%M%S") + "-%04d" % (int(time.time() * 1000) % 10000)
    run_dir = run_dir or os.path.join(ROOT, "runs")
    ctx = {
        "run_id": run_id,
        "now": now or datetime.now().isoformat(timespec="seconds"),
        "log": AuditLog(run_dir, run_id),
        "store": store or st.open_store(os.path.join(run_dir, "guardian.sqlite3")),
        "outbox_dir": outbox_dir or os.path.join(ROOT, "outbox"),
        "profile": detect.load("profile.json", data_dir),
        "verification": detect.load("verification.json", data_dir),
        "approvals": load_approvals(run_dir),
    }
    ctx["flags"] = flags.snapshot(detect.load("gates.json", data_dir), ctx["profile"], check=gate_check)
    ctx["gates"] = flags.values(ctx["flags"])
    ctx["log"].gates = ctx["gates"]
    ctx["log"].event("gates", "check_gates", {}, ctx["flags"], "run")
    results = [handle(t, ctx) for t in detect.all_threats(
        data_dir, senior=ctx["gates"]["senior_protection"], extra_calls=load_incoming(run_dir))]

    def count(pred):
        return sum(1 for r in results for a in r["actions"] if pred(a))
    summary = {
        "run_id": run_id, "store": ctx["store"].name, "persona": ctx["verification"].get("result"),
        "threats": len(results), "new_threats": sum(1 for r in results if r["new"]),
        "stopped": count(lambda a: a["action"] in ("quarantine", "lock_card", "dispute", "block_number")
                         and a["status"].endswith("(simulated)")),
        "alerts": count(lambda a: a["action"] == "alert" and a["status"].endswith("(simulated)")),
        "family_told": count(lambda a: a["action"] == "notify_trusted" and a["status"].endswith("(simulated)")),
        "waiting_for_you": count(lambda a: a["status"] == "waiting for you"),
        "gates": ctx["flags"],
        "results": results,
    }
    with open(os.path.join(run_dir, run_id + ".summary.json"), "w") as f:
        json.dump(summary, f, indent=2, default=str)
    return summary


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Run Guardian once.")
    parser.add_argument("--approve", metavar="ACTION", help="say yes to a held action first, e.g. dispute:tx-4")
    parser.add_argument("--incoming", metavar="FILE", help="a call or text arrives first, e.g. demo/incoming_text.json")
    args = parser.parse_args()
    load_env()
    if args.incoming:
        for c in receive(args.incoming):
            print("New %s from %s just arrived. Running Guardian now." % (c["kind"], c["from"]))
    if args.approve:
        approve(args.approve)
        print("Approved %s. Running Guardian now." % args.approve)
    s = run()
    print("Demo mode: every action below is simulated and written to outbox/.")
    print(json.dumps({k: v for k, v in s.items() if k != "results"}, indent=2))
    for r in s["results"]:
        print("-", r["severity"], r["summary"])
        for a in r["actions"]:
            print("    ", a["action"], "->", a["status"], ("(" + a["reason"] + ")") if a["status"] == "waiting for you" else "")
            if a.get("approve"):
                print("        to approve: python3 agent/run.py --approve", a["approve"])
