"""Run Guardian once: detect threats, decide, check gates, act, write back, and record every step."""
import json
import os
import sys
import time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent import detect, flags, models, respond
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
    if threat["key"] in ctx.get("real", ()):
        # The person said this was real: never act on it again.
        return {"threat": threat["key"], "kind": threat["kind"], "severity": threat["severity"],
                "summary": threat["summary"], "evidence": threat["evidence"], "new": is_new, "actions": [],
                "marked_real": True}
    for action in respond.decide(threat, ctx["profile"]):
        done = st.action_done(store, action["key"])
        if done:
            outcomes.append({"action": action["type"], "key": action["key"], "status": "already done in " + done["run_id"]})
            log.event("check_history", "check_history", {"action": action["key"]}, done, threat["key"])
            continue
        allowed, reason = respond.guard(action, ctx["gates"], ctx["verification"], ctx["profile"], now,
                                        ctx.get("approved", ()))
        log.event("guard", "guard_" + action["type"], {"action": action["key"]},
                  {"allowed": allowed, "reason": reason}, threat["key"])
        if allowed:
            try:
                result = respond.act(action, threat, ctx["profile"], ctx["outbox_dir"])
            except Exception as e:  # a service outage must not stop the run; the action retries next run
                result = {"status": respond.FAILED, "reason": "%s: %s" % (type(e).__name__, str(e)[:120])}
        else:
            result = respond.held(action, threat, ctx["profile"], reason)
            if action["key"] in ctx.get("approved", ()):
                # Already approved, but something else still holds it (e.g. no Persona check): don't ask again.
                result.pop("ask", None)
                result["reason"] = "you approved it, but " + reason
        log.event("act", "act_" + action["type"], {"action": action["key"]}, result, threat["key"])
        st.save_action(store, action, threat["key"], result, run_id, now)
        outcomes.append({"action": action["type"], "key": action["key"], "status": result["status"],
                         "reason": result.get("reason", reason), "ask": result.get("ask"),
                         "text": result.get("text")})
    return {"threat": threat["key"], "kind": threat["kind"], "severity": threat["severity"],
            "summary": threat["summary"], "evidence": threat["evidence"], "new": is_new, "actions": outcomes}


def make_ask(store, now, budget):
    """The model's second look, cached per message in the store and capped per run. None if no model is set."""
    if not models.configured():
        return None
    used = {"calls": 0}

    def ask(key, text):
        cached = st.verdict_get(store, key)
        if cached:
            return cached["label"], cached["decided_by"]
        if used["calls"] >= budget:
            return None, "model budget for this run used up"
        used["calls"] += 1
        label, by = models.classify(text, default="unknown")
        if not by.startswith("rules"):  # only a real answer is cached; an error is asked again next run
            st.verdict_put(store, key, label, by, now)
        return label, by
    ask.used = used
    return ask


def run(data_dir=None, run_dir=None, outbox_dir=None, store=None, now=None, gate_check=None, user_id="demo-user"):
    run_id = "run-" + time.strftime("%Y%m%d-%H%M%S") + "-%04d" % (int(time.time() * 1000) % 10000)
    run_dir = run_dir or os.path.join(ROOT, "runs")
    ctx = {
        "run_id": run_id,
        "now": now or datetime.now().isoformat(timespec="seconds"),
        "log": AuditLog(run_dir, run_id, user_id),
        "store": store or st.open_store(os.path.join(run_dir, "guardian.sqlite3")),
        "outbox_dir": outbox_dir or os.path.join(ROOT, "outbox"),
        "profile": detect.load("profile.json", data_dir),
        "verification": detect.load("verification.json", data_dir),
    }
    ctx["approved"] = st.approved_keys(ctx["store"])
    ctx["real"] = st.marked_real(ctx["store"])
    ctx["flags"] = flags.snapshot(detect.load("gates.json", data_dir), ctx["profile"], check=gate_check)
    ctx["gates"] = flags.values(ctx["flags"])
    ctx["log"].gates = ctx["gates"]
    ctx["log"].event("gates", "check_gates", {}, ctx["flags"], "run")
    sources = {}
    ask = make_ask(ctx["store"], ctx["now"], int(os.environ.get("GUARDIAN_MODEL_BUDGET", "40")))
    threats = detect.all_threats(data_dir, senior=ctx["gates"]["senior_protection"], sources=sources, ask=ask)
    sources["model_second_look"] = ("%d asked" % ask.used["calls"]) if ask else "off (no model configured)"
    ctx["log"].event("sources", "read_sources", {}, sources, "run")
    results = [handle(t, ctx) for t in threats]

    def count(pred):
        return sum(1 for r in results for a in r["actions"] if pred(a))
    done = respond.is_done
    summary = {
        "run_id": run_id, "store": ctx["store"].name, "persona": ctx["verification"].get("result"),
        "sources": sources,
        "threats": len(results), "new_threats": sum(1 for r in results if r["new"]),
        "stopped": count(lambda a: a["action"] in ("quarantine", "lock_card", "dispute", "block_number")
                         and done(a["status"])),
        "alerts": count(lambda a: a["action"] == "alert" and done(a["status"])),
        "family_told": count(lambda a: a["action"] == "notify_trusted" and done(a["status"])),
        "waiting_for_you": count(lambda a: a["status"] == "waiting for you"),
        "failed": count(lambda a: a["status"] == respond.FAILED),
        "gates": ctx["flags"],
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
