"""Product metrics: the KPIs a team watches, built from a run summary and sent to Amplitude and Statsig.

audit.py records every low-level step (agent_* events). This module records what those steps mean:

  guardian_run_completed      one per run: threats, stopped, waiting, family told, money protected,
                              automation rate, duration, gate values. Also sets user properties.
  guardian_threat_detected    one per threat first seen: kind, severity, channel, who decided, score.
  guardian_action_completed   one per action decided in a run: type, outcome, automated or held, why.
  guardian_money_protected    one per card charge stopped: amount in USD.
  guardian_family_notified    one per trusted contact told.
  guardian_needs_attention    one per action waiting for the person (dispute to confirm, gate held).

Every event carries the same session_id (the run) and an insert_id, so sending a run twice never
double counts. Amplitude and Statsig get the same event names, so charts line up across both tools.
"""
import hashlib
import json
import os
import urllib.request

AMPLITUDE_HTTP = "https://api2.amplitude.com/2/httpapi"
AMPLITUDE_BATCH = "https://api2.amplitude.com/batch"
STATSIG_LOG_EVENT = "https://events.statsigapi.net/v1/log_event"

DONE_TYPES = ("quarantine", "lock_card", "dispute", "block_number")  # actions that stop a threat
CHANNEL = {"phishing": "email", "takeover": "email", "identity_breach": "breach_feed",
           "merchant_breach": "breach_feed", "card_misuse": "card"}


def channel(threat):
    if threat["kind"] in ("scam_call", "suspicious"):
        return threat["evidence"].get("kind", "call")
    return CHANNEL.get(threat["kind"], "other")


def outcome(status):
    if status.endswith("(simulated)"):
        return "done"
    if status.startswith("already done"):
        return "already_done"
    return "held"


def _insert_id(*parts):
    return hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()


def build_events(summary, profile, user_id="demo-user", time_ms=None, extra=None):
    """Amplitude-shaped events for one run. `extra` is merged into every event's properties."""
    t0 = int(time_ms if time_ms is not None else summary.get("started_ms", 0))
    session = t0
    gates = {k: v["value"] for k, v in (summary.get("gates") or {}).items()}
    base = dict(extra or {}, run_id=summary["run_id"])
    events = []

    def add(event_type, subject, props, offset=0, user_properties=None):
        ev = {"user_id": user_id, "event_type": event_type, "time": t0 + offset, "session_id": session,
              "insert_id": _insert_id(summary["run_id"], user_id, event_type, subject),
              "event_properties": dict(base, **props)}
        if user_properties:
            ev["user_properties"] = user_properties
        events.append(ev)

    money = 0.0
    by_kind, by_sev, drafted, held_reasons = {}, {}, {}, {}
    auto_done = auto_possible = 0
    for i, r in enumerate(summary["results"]):
        kind, sev = r["kind"], r["severity"]
        threat = {"kind": kind, "evidence": r["evidence"]}
        done_types = [a["action"] for a in r["actions"] if outcome(a["status"]) == "done"]
        if r["new"]:
            by_kind[kind] = by_kind.get(kind, 0) + 1
            by_sev[sev] = by_sev.get(sev, 0) + 1
            add("guardian_threat_detected", r["threat"], {
                "threat_kind": kind, "severity": sev, "channel": channel(threat),
                "decided_by": r["evidence"].get("decided_by", "rules"),
                "score": r["evidence"].get("score"),
                "senior_protection": gates.get("senior_protection"),
                "actions_planned": len(r["actions"]),
                "auto_handled": any(t in DONE_TYPES for t in done_types)}, offset=i * 10)
        for j, a in enumerate(r["actions"]):
            out = outcome(a["status"])
            if out == "already_done":
                continue  # repeats are visible in the audit trail; KPIs count each action once
            automated = out == "done"
            if a["action"] != "alert":
                auto_possible += 1
                auto_done += automated
            props = {"action_type": a["action"], "outcome": out, "automated": automated,
                     "threat_kind": kind, "severity": sev, "channel": channel(threat)}
            if out == "held":
                props["held_reason"] = a.get("reason") or ""
                held_reasons[props["held_reason"]] = held_reasons.get(props["held_reason"], 0) + 1
            add("guardian_action_completed", r["threat"] + ":" + a["action"] + ":%d" % j, props,
                offset=i * 10 + j + 1)
            if out == "held":
                add("guardian_needs_attention", r["threat"] + ":" + a["action"], {
                    "action_type": a["action"], "threat_kind": kind, "severity": sev,
                    "reason": a.get("reason") or "", "ask": a.get("ask") or ""}, offset=i * 10 + j + 2)
            if a["action"] == "notify_trusted" and automated:
                add("guardian_family_notified", r["threat"] + ":family:%d" % j, {
                    "threat_kind": kind, "channel": channel(threat)}, offset=i * 10 + j + 2)
            if a["action"] == "alert" and automated:
                d = a.get("drafted_by") or "template"
                drafted[d] = drafted.get(d, 0) + 1
        if r["new"] and kind == "card_misuse" and any(t in ("lock_card", "dispute") for t in done_types):
            amount = float(r["evidence"].get("amount") or 0)
            money += amount
            add("guardian_money_protected", r["threat"], {
                "amount_usd": amount, "merchant": r["evidence"].get("merchant", ""),
                "how": "+".join(t for t in done_types if t in ("lock_card", "dispute"))}, offset=i * 10 + 9)

    contacts = profile.get("trusted_contacts", [])
    cards = profile.get("cards", [])
    run_props = {
        "threats": summary["threats"], "new_threats": summary["new_threats"],
        "stopped": summary["stopped"], "alerts": summary["alerts"],
        "family_told": summary.get("family_told", 0), "waiting_for_you": summary["waiting_for_you"],
        "money_protected_usd": round(money, 2),
        "automation_rate": round(auto_done / auto_possible, 3) if auto_possible else None,
        "threats_by_kind": by_kind, "threats_by_severity": by_sev,
        "held_reasons": held_reasons, "alerts_drafted_by": drafted,
        "high_severity_new": by_sev.get("high", 0),
        "all_clear": summary["new_threats"] == 0,
        "duration_ms": summary.get("duration_ms"), "store": summary.get("store"),
        "persona_passed": summary.get("persona") == "passed", "gates": gates,
        "gate_sources": {k: v["source"] for k, v in (summary.get("gates") or {}).items()},
    }
    user_props = {
        "$set": {"protection_mode": profile.get("protection", "standard"),
                 "senior_protection": gates.get("senior_protection"),
                 "cards_monitored": len(cards),
                 "cards_lockable": sum(1 for c in cards if c.get("issuer_lock_api")),
                 "emails_monitored": len(profile.get("emails", [])),
                 "accounts_monitored": len(profile.get("accounts", [])),
                 "trusted_contacts": len(contacts),
                 "trusted_contacts_consented": sum(1 for c in contacts if c.get("consent")),
                 "persona_verified": summary.get("persona") == "passed",
                 "kill_switch": gates.get("kill_switch"),
                 "last_run_id": summary["run_id"]},
        "$add": {"lifetime_runs": 1, "lifetime_threats": summary["new_threats"],
                 "lifetime_stopped": summary["stopped"],
                 "lifetime_family_told": summary.get("family_told", 0),
                 "lifetime_money_protected_usd": round(money, 2)},
    }
    if extra:
        user_props["$set"].update({k: v for k, v in extra.items() if k in ("is_synthetic", "cohort")})
    add("guardian_run_completed", "run", run_props, offset=len(summary["results"]) * 10 + 20,
        user_properties=user_props)
    return events


def _post(url, body, headers=None):
    req = urllib.request.Request(url, data=json.dumps(body, default=str).encode(),
                                 headers=dict({"Content-Type": "application/json"}, **(headers or {})))
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.status, resp.read().decode()


def send_amplitude(events, key=None, batch=False):
    """Send events to Amplitude in chunks. Returns the number accepted. Raises on a failed chunk."""
    key = key or os.environ.get("AMPLITUDE_API_KEY", "")
    if not key or not events:
        return 0
    url, size, sent = (AMPLITUDE_BATCH, 1000, 0) if batch else (AMPLITUDE_HTTP, 500, 0)
    for i in range(0, len(events), size):
        chunk = events[i:i + size]
        _post(url, {"api_key": key, "events": chunk, "options": {"min_id_length": 1}})
        sent += len(chunk)
    return sent


def to_statsig(ev):
    """The same event in Statsig's log_event shape (metadata values as strings)."""
    meta = {k: (v if isinstance(v, str) else json.dumps(v, default=str))
            for k, v in ev["event_properties"].items() if v is not None}
    value = ev["event_properties"].get("threat_kind") or ev["event_properties"].get("action_type")
    if ev["event_type"] == "guardian_money_protected":
        value = ev["event_properties"]["amount_usd"]
    out = {"eventName": ev["event_type"], "user": {"userID": ev["user_id"]}, "time": ev["time"],
           "metadata": meta}
    if value is not None:
        out["value"] = value
    return out


def send_statsig(events, secret=None):
    """Send events to Statsig. Returns the number sent. Raises on a failed chunk."""
    secret = secret or os.environ.get("STATSIG_SERVER_SECRET", "")
    if not secret or not events:
        return 0
    sent = 0
    for i in range(0, len(events), 500):
        chunk = [to_statsig(e) for e in events[i:i + 500]]
        _post(STATSIG_LOG_EVENT, {"events": chunk}, {"statsig-api-key": secret})
        sent += len(chunk)
    return sent


def send(events, error_path=None):
    """Send to every connected tool. A failed send is noted in error_path and never stops a run."""
    sent = {}
    for name, fn in (("amplitude", send_amplitude), ("statsig", send_statsig)):
        try:
            sent[name] = fn(events)
        except Exception as e:
            sent[name] = "error: %s" % type(e).__name__
            if error_path:
                with open(error_path, "a") as f:
                    f.write("metrics %s: %s\n" % (name, e))
    return sent
