"""Turn threats into actions, check each action against the gates, and carry it out.

Actions are simulated into the outbox folder. Swapping a simulated action for a real one
(Gmail label, card issuer API) changes only the matching function in ACT.
"""
import json
import os
from datetime import datetime, timedelta

from agent import firedrill, models

# How a finished action's status ends: written to the local outbox, or carried out on a Firedrill service.
DONE_SUFFIXES = ("(simulated)", "(firedrill)")
# An action whose service failed. It is not "done", so the next run tries it again.
FAILED = "failed, will retry"


def is_done(status):
    return isinstance(status, str) and status.endswith(DONE_SUFFIXES)


UNDO = {"quarantine": "moved back to the inbox", "block_number": "unblocked", "lock_card": "unlocked"}


def undo(action_row, outbox_dir):
    """Reverse one finished action after the person said "this was real". Returns the new status, or None.

    Alerts and family messages cannot be unsent; a filed dispute is withdrawn with the bank.
    """
    kind = action_row["action"]
    if kind == "dispute":
        _append(outbox_dir, "undo.jsonl", {"action": action_row["action_key"], "undo": "withdraw dispute"})
        return "dispute withdrawn (simulated undo)"
    if kind not in UNDO:
        return None
    _append(outbox_dir, "undo.jsonl", {"action": action_row["action_key"], "undo": UNDO[kind]})
    return "%s (simulated undo)" % UNDO[kind]

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
    "phishing": [
        "Do not click links or open attachments in that email.",
        "If you already typed a password after clicking, change it now on the real site or app.",
        "If it asks you to act, check by opening the company's app or typing its address yourself.",
    ],
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
    if threat["kind"] == "card_misuse" and ev.get("small"):
        # A small unknown charge is more often parking than fraud: ask before locking, no dispute.
        return [{"type": "lock_card", "key": "lock:" + ev["card"], "card": ev["card"], "ask_first": True,
                 "merchant": ev["merchant"], "amount": ev["amount"]},
                {"type": "alert", "key": "alert:" + threat["key"]}]
    if threat["kind"] in ("merchant_breach", "card_misuse"):
        acts = [{"type": "lock_card", "key": "lock:" + ev["card"], "card": ev["card"]}]
        if threat["kind"] == "card_misuse":
            acts.append({"type": "dispute", "key": "dispute:" + ev["transaction"], "transaction": ev["transaction"],
                         "card": ev["card"], "merchant": ev["merchant"], "amount": ev["amount"], "date": ev["date"]})
        return acts + [{"type": "alert", "key": "alert:" + threat["key"]}]
    return [{"type": "alert", "key": "alert:" + threat["key"]}]


CLAIM_MAX_AGE = timedelta(hours=24)
# Turning protection down, changing who gets family alerts, or undoing a lock or quarantine needs a pass
# from the last few minutes: someone who has taken over the account would do exactly these things first.
REQUEST_MAX_AGE = timedelta(minutes=15)

# Each setting's safe value. Moving a setting TO it never needs a check; moving it away does.
SAFE = {"senior_protection": True, "auto_quarantine": True, "auto_block_numbers": True, "auto_lock_card": True,
        "notify_trusted_contacts": True, "dispute_needs_approval": True, "kill_switch": False}


def _parse_time(ts):
    """ISO time, naive or with an offset ("Z" too), as naive local time."""
    d = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    return d.astimezone().replace(tzinfo=None) if d.tzinfo else d


def claim_fresh(verification, now, max_age=CLAIM_MAX_AGE):
    """A Persona pass counts for `max_age` (24 hours by default). Missing, unreadable or future times do not count."""
    try:
        age = _parse_time(now) - _parse_time(verification["checked_at"])
    except (KeyError, TypeError, ValueError):
        return False
    return timedelta(minutes=-5) <= age <= max_age


def persona_ok(verification, now, max_age=CLAIM_MAX_AGE):
    """Is there a passed Persona check, fresh enough? Returns (ok, reason). `now` None skips the time check."""
    if verification.get("result") != "passed":
        return False, "no verified person behind this agent yet (Persona check not passed)"
    if now is not None and not claim_fresh(verification, now, max_age):
        if max_age == CLAIM_MAX_AGE:
            return False, "the Persona check is more than 24 hours old; verify again"
        return False, "this change needs a Persona check from the last %d minutes; verify again" % (
            max_age.total_seconds() // 60)
    return True, "verified person"


def guard_request(request, verification, now):
    """May the person's own change go ahead? Returns (allowed, reason).

    The kill switch does not apply here: these are the person's requests, not Guardian acting alone,
    and the person must always be able to turn Guardian back on.
    """
    kind = request["type"]
    if kind == "change_setting":
        gate, value = request["gate"], request["value"]
        if gate not in SAFE or not isinstance(value, bool):
            return False, "unknown setting"
        if value == SAFE[gate]:
            return True, "makes Guardian safer; no check needed"
        ok, reason = persona_ok(verification, now, REQUEST_MAX_AGE)
        return (True, "verified person just now; protection turned down at their request") if ok else (False, reason)
    if kind in ("change_contact", "unlock_card", "release_quarantine"):
        ok, reason = persona_ok(verification, now, REQUEST_MAX_AGE)
        what = {"change_contact": "who hears about scams changed", "unlock_card": "card unlocked",
                "release_quarantine": "email released"}[kind]
        return (True, "verified person just now; %s at their request" % what) if ok else (False, reason)
    return False, "unknown request"


def guard(action, gates, verification, profile, now=None, approved=()):
    """May this action run now? Returns (allowed, reason).

    `now` turns on the Persona freshness check. `approved` holds the action keys the person said yes to.
    """
    if action["type"] == "alert":
        return True, "alerts always go to you"
    if gates.get("kill_switch"):
        return False, "kill switch is on; nothing runs without you"
    if action["type"] == "quarantine":
        if action["key"] in approved:
            return True, "you confirmed it's a scam and asked for this"
        return (True, "auto-quarantine is on") if gates.get("auto_quarantine") else (False, "auto-quarantine is off")
    if action["type"] == "block_number":
        if action["key"] in approved:
            return True, "you confirmed it's a scam and asked for this"
        return (True, "auto-block is on") if gates.get("auto_block_numbers") else (False, "auto-block is off")
    if action["type"] == "notify_trusted":
        if not action["contact"].get("consent"):
            return False, "%s has not agreed to receive alerts" % action["contact"]["name"]
        if not gates.get("notify_trusted_contacts"):
            return False, "family alerts are off"
        return True, "%s agreed to be told about serious scams" % action["contact"]["name"]
    if action["type"] == "lock_card":
        if action.get("ask_first") and action["key"] not in approved:
            return False, "a small charge you may have made: Guardian asks before locking your card"
        ok, reason = persona_ok(verification, now)
        if not ok:
            return False, reason
        if not gates.get("auto_lock_card") and action["key"] not in approved:
            return False, "auto-lock is off"
        c = card(profile, action["card"])
        if not c or not c.get("issuer_lock_api"):
            return False, "the card issuer has no lock option for agents; call them"
        return True, "verified person, auto-lock on, issuer supports locking"
    if action["type"] == "dispute":
        if action["key"] in approved:
            return True, "you approved it"
        if gates.get("dispute_needs_approval", True):
            return False, "disputes wait for your confirmation"
        return True, "auto-dispute is on"
    return False, "unknown action"


def _fill(ev, profile):
    c = card(profile, ev.get("card", "")) or {}
    return {"domains": ", ".join(ev.get("domains", [])), "account": ev.get("account", ""),
            "last4": c.get("last4", ""), "merchant": ev.get("merchant", ""), "amount": ev.get("amount", 0)}


def steps_for(kind, ev, profile):
    """The person's own steps for one threat, in plain words."""
    fill = _fill(ev, profile)
    return [s.format(**fill) for s in STEPS.get(kind, [])]


def alert_text(threat, profile):
    """Plain-language alert with exact steps. Returns (text, drafted_by)."""
    ev = threat["evidence"]
    fill = _fill(ev, profile)
    steps = steps_for(threat["kind"], ev, profile)
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
    """Carry out one allowed action. Returns the result record.

    Quarantine and family alerts go to Firedrill's synthetic Gmail and Slack when their addresses are set;
    everything else is simulated into the outbox. A service error raises; run.handle records it as FAILED.
    """
    if action["type"] == "quarantine":
        if firedrill.configured("gmail"):
            firedrill.quarantine(action["email"])
            return {"status": "quarantined (firedrill)", "label": firedrill.QUARANTINE_LABEL}
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
        if firedrill.configured("slack"):
            channel = firedrill.tell_family(msg, action["key"])
            return {"status": "%s told in #%s (firedrill)" % (c["name"], channel), "text": msg}
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
    if action["type"] == "lock_card" and action.get("ask_first"):
        return {"status": "waiting for you", "reason": reason,
                "ask": "Lock card ending %s? You may not recognise $%.2f at %s." % (
                    card(profile, action["card"])["last4"], action["amount"], action["merchant"])}
    return {"status": "waiting for you", "reason": reason}
