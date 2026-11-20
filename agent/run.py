"""Run Guardian once: detect threats, decide, check gates, act, write back, and record every step."""
import json
import os
import sys
import time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent import detect, respond
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
            outcomes.append({"action": action["type"], "status": "already done in " + done["run_id"]})
            log.event("check_history", "check_history", {"action": action["key"]}, done, threat["key"])
            continue
        allowed, reason = respond.guard(action, ctx["gates"], ctx["verification"], ctx["profile"])
        log.event("guard", "guard_" + action["type"], {"action": action["key"]},
                  {"allowed": allowed, "reason": reason}, threat["key"])
        if allowed:
            result = respond.act(action, threat, ctx["profile"], ctx["outbox_dir"])
        else:
            result = respond.held(action, threat, ctx["profile"], reason)
        log.event("act", "act_" + action["type"], {"action": action["key"]}, result, threat["key"])
        st.save_action(store, action, threat["key"], result, run_id, now)
        outcomes.append({"action": action["type"], "status": result["status"],
                         "reason": result.get("reason", reason), "ask": result.get("ask")})
    return {"threat": threat["key"], "kind": threat["kind"], "severity": threat["severity"],
            "summary": threat["summary"], "evidence": threat["evidence"], "new": is_new, "actions": outcomes}


def run(data_dir=None, run_dir=None, outbox_dir=None, store=None, now=None):
    run_id = "run-" + time.strftime("%Y%m%d-%H%M%S") + "-%04d" % (int(time.time() * 1000) % 10000)
    run_dir = run_dir or os.path.join(ROOT, "runs")
    ctx = {
        "run_id": run_id,
        "now": now or datetime.now().isoformat(timespec="seconds"),
        "log": AuditLog(run_dir, run_id),
        "store": store or st.open_store(os.path.join(run_dir, "guardian.sqlite3")),
        "outbox_dir": outbox_dir or os.path.join(ROOT, "outbox"),
        "profile": detect.load("profile.json", data_dir),
        "gates": detect.load("gates.json", data_dir),
        "verification": detect.load("verification.json", data_dir),
    }
    results = [handle(t, ctx) for t in detect.all_threats(data_dir)]

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
        "results": results,
    }
    with open(os.path.join(run_dir, run_id + ".summary.json"), "w") as f:
        json.dump(summary, f, indent=2, default=str)
    return summary


if __name__ == "__main__":
    load_env()
    s = run()
    print(json.dumps({k: v for k, v in s.items() if k != "results"}, indent=2))
    for r in s["results"]:
        print("-", r["severity"], r["summary"])
        for a in r["actions"]:
            print("    ", a["action"], "->", a["status"], ("(" + a["reason"] + ")") if a["status"] == "waiting for you" else "")
