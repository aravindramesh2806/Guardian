"""Turn threats into actions, check each action against the gates, and carry it out.

Actions are simulated into the outbox folder. Swapping a simulated action for a real one
(Gmail label, card issuer API) changes only the matching function in ACT.
"""
import json
import os

from agent import models

STEPS = {
    "identity_breach": [
        "Change the password on {domains} today.",
        "Change it anywhere else you used the same password.",
        "Turn on two-step sign-in for {domains}.",
    ],
    "takeover": [
        "Do not click links in that email.",
        "Open {account} yourself (app or typed address) and change your password.",
        "Turn on two-step sign-in and sign out other devices.",
    ],
    "merchant_breach": [
        "Watch card ending {last4} for charges you do not recognise.",
        "Be wary of emails claiming to be {merchant} for the next few weeks.",
    ],
    "card_misuse": [
        "Confirm the dispute for ${amount:.2f} at {merchant} if you did not make this charge.",
        "Ask your bank for a replacement card.",
    ],
    "scam_call": [
        "Do not call back, pay, or share any code.",
        "If it was about your bank, hang up and call the number on the back of your card.",
        "Real family can wait while you check: call them on the number you already have.",
    ],
    "suspicious": ["Do not click links or call back until you have checked who it is."],
    "phishing": [],
}


def card(profile, card_id):
    return next((c for c in profile["cards"] if c["id"] == card_id), None)


def decide(threat, profile):
    """The actions this threat calls for, in order."""
    ev = threat["evidence"]
    if threat["kind"] == "phishing":
        return [{"type": "quarantine", "key": "quarantine:" + ev["email"], "email": ev["email"]}]
    if threat["kind"] == "scam_call":
        acts = [{"type": "block_number", "key": "block:" + ev["from"], "number": ev["from"]},
                {"type": "alert", "key": "alert:" + threat["key"]}]
        for c in profile.get("trusted_contacts", []):
            acts.append({"type": "notify_trusted", "key": "notify:%s:%s" % (c["address"], threat["key"]),
                         "contact": c})
        return acts
    if threat["kind"] in ("merchant_breach", "card_misuse"):
        acts = [{"type": "lock_card", "key": "lock:" + ev["card"], "card": ev["card"]}]
        if threat["kind"] == "card_misuse":
            acts.append({"type": "dispute", "key": "dispute:" + ev["transaction"], "transaction": ev["transaction"],
                         "card": ev["card"], "merchant": ev["merchant"], "amount": ev["amount"], "date": ev["date"]})
        return acts + [{"type": "alert", "key": "alert:" + threat["key"]}]
    return [{"type": "alert", "key": "alert:" + threat["key"]}]


def guard(action, gates, verification, profile):
    """May this action run now? Returns (allowed, reason)."""
    if action["type"] == "alert":
        return True, "alerts always go to you"
    if gates.get("kill_switch"):
        return False, "kill switch is on; nothing runs without you"
    if action["type"] == "quarantine":
        return (True, "auto-quarantine is on") if gates.get("auto_quarantine") else (False, "auto-quarantine is off")
    if action["type"] == "block_number":
        return (True, "auto-block is on") if gates.get("auto_block_numbers") else (False, "auto-block is off")
    if action["type"] == "notify_trusted":
        if not action["contact"].get("consent"):
            return False, "%s has not agreed to receive alerts" % action["contact"]["name"]
        if not gates.get("notify_trusted_contacts"):
            return False, "family alerts are off"
        return True, "%s agreed to be told about serious scams" % action["contact"]["name"]
    if action["type"] == "lock_card":
        if verification.get("result") != "passed":
            return False, "no verified person behind this agent yet (Persona check not passed)"
        if not gates.get("auto_lock_card"):
            return False, "auto-lock is off"
        c = card(profile, action["card"])
        if not c or not c.get("issuer_lock_api"):
            return False, "the card issuer has no lock option for agents; call them"
        return True, "verified person, auto-lock on, issuer supports locking"
    if action["type"] == "dispute":
        if gates.get("dispute_needs_approval", True):
            return False, "disputes wait for your confirmation"
        return True, "auto-dispute is on"
    return False, "unknown action"


def alert_text(threat, profile):
    """Plain-language alert with exact steps. Returns (text, drafted_by)."""
    ev = threat["evidence"]
    c = card(profile, ev.get("card", "")) or {}
    fill = {"domains": ", ".join(ev.get("domains", [])), "account": ev.get("account", ""),
            "last4": c.get("last4", ""), "merchant": ev.get("merchant", ""), "amount": ev.get("amount", 0)}
    steps = [s.format(**fill) for s in STEPS.get(threat["kind"], [])]
    fallback = threat["summary"] + "." + "".join("\n  %d. %s" % (i + 1, s) for i, s in enumerate(steps))
    facts = {"what_happened": threat["summary"], "evidence": ev, "steps": steps}
    must = {"identity_breach": [fill["domains"]], "takeover": [fill["account"]],
            "merchant_breach": [fill["merchant"], fill["last4"]],
            "card_misuse": ["%.2f" % fill["amount"], fill["merchant"]],
            "scam_call": ["call", "code"]}.get(threat["kind"], [])
    return models.draft(facts, fallback, required=[m for m in must if m])


def _append(outbox_dir, name, record):
    os.makedirs(outbox_dir, exist_ok=True)
    path = os.path.join(outbox_dir, name)
    with open(path, "a") as f:
        f.write(json.dumps(record, default=str) + "\n")
    # Record a short relative path, so reports never reveal where the project lives on disk.
    return os.path.join(os.path.basename(os.path.normpath(outbox_dir)), name)


def act(action, threat, profile, outbox_dir):
    """Carry out one allowed action (simulated). Returns the result record."""
    if action["type"] == "quarantine":
        path = _append(outbox_dir, "quarantine.jsonl", {"email": action["email"], "label": "Guardian/Quarantine"})
        return {"status": "quarantined (simulated)", "file": path}
    if action["type"] == "lock_card":
        c = card(profile, action["card"])
        path = _append(outbox_dir, "card_locks.jsonl", {"card": action["card"], "issuer": c["issuer"]})
        return {"status": "card ending %s locked (simulated)" % c["last4"], "file": path}
    if action["type"] == "dispute":
        path = _append(outbox_dir, "disputes.jsonl", {k: action[k] for k in ("transaction", "card", "merchant", "amount", "date")})
        return {"status": "dispute filed (simulated)", "file": path}
    if action["type"] == "block_number":
        path = _append(outbox_dir, "blocked_numbers.jsonl", {"number": action["number"]})
        return {"status": "number %s blocked (simulated)" % action["number"], "file": path}
    if action["type"] == "notify_trusted":
        c = action["contact"]
        msg = "Guardian: %s just got a likely scam (%s). It has been blocked. You may want to check in." % (
            profile["name"].split(" ")[0], threat["summary"])
        path = _append(outbox_dir, "family_alerts.jsonl", {"to": c["name"], "channel": c["channel"], "text": msg})
        return {"status": "%s told (simulated)" % c["name"], "file": path, "text": msg}
    if action["type"] == "alert":
        text, drafted_by = alert_text(threat, profile)
        path = _append(outbox_dir, "alerts.jsonl", {"threat": threat["key"], "severity": threat["severity"], "text": text})
        return {"status": "alert sent (simulated)", "file": path, "drafted_by": drafted_by, "text": text}
    raise ValueError("unknown action " + action["type"])


def held(action, threat, profile, reason):
    """A held action still tells the person what is waiting for them."""
    if action["type"] == "dispute":
        return {"status": "waiting for you", "reason": reason,
                "ask": "Dispute $%.2f at %s on card ending %s?" % (
                    action["amount"], action["merchant"], card(profile, action["card"])["last4"])}
    return {"status": "waiting for you", "reason": reason}
