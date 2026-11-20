"""The person's own changes to Guardian, each checked against Persona first.

    python3 agent/settings.py set auto_lock_card off
    python3 agent/settings.py set kill_switch on
    python3 agent/settings.py contact add "Alex (grandson)" sms +1-555-0177 --consent
    python3 agent/settings.py contact remove +1-555-0142
    python3 agent/settings.py contact consent +1-555-0142 off
    python3 agent/settings.py unlock card-visa-4821
    python3 agent/settings.py release m-101

Making Guardian safer never needs a check. Turning protection down, changing who hears about scams, and
undoing a card lock or a quarantine need a Persona pass from the last 15 minutes (respond.guard_request):
someone who has taken over the account would do exactly these things first. Run the Persona sidecar
(`node persona/server.js`) to verify, then try again.

Settings and contacts are written to data/gates.json and data/profile.json, the local defaults. Statsig can
still tighten a gate on top of them (agent/flags.py). Unlocks and releases are simulated into the outbox.
Every request, allowed or held, is one event in the audit trail.
"""
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
ON_OFF = {"on": True, "off": False, "true": True, "false": False}


def _save(data_dir, name, obj):
    with open(os.path.join(data_dir, name), "w") as f:
        json.dump(obj, f, indent=2)
        f.write("\n")


def apply(request, data_dir, outbox_dir):
    """Carry out an allowed request. Returns the result record; raises ValueError for a bad request."""
    kind = request["type"]
    if kind == "change_setting":
        gate, value = request["gate"], request["value"]
        if gate == "senior_protection":
            profile = detect.load("profile.json", data_dir)
            profile["protection"] = "senior" if value else "standard"
            _save(data_dir, "profile.json", profile)
        else:
            gates = detect.load("gates.json", data_dir)
            gates[gate] = value
            _save(data_dir, "gates.json", gates)
        return {"status": "%s turned %s" % (gate, "on" if value else "off")}
    if kind == "change_contact":
        profile = detect.load("profile.json", data_dir)
        contacts = profile.setdefault("trusted_contacts", [])
        address = request["contact"]["address"]
        match = [c for c in contacts if c["address"] == address]
        if request["op"] == "add":
            if match:
                raise ValueError("that contact is already on the list")
            contacts.append(dict(request["contact"]))
            status = "%s added" % request["contact"]["name"]
        elif not match:
            raise ValueError("no trusted contact with that address")
        elif request["op"] == "remove":
            contacts.remove(match[0])
            status = "%s removed" % match[0]["name"]
        else:  # consent
            match[0]["consent"] = request["contact"]["consent"]
            status = "%s %s alerts" % (match[0]["name"], "will get" if match[0]["consent"] else "will no longer get")
        _save(data_dir, "profile.json", profile)
        return {"status": status}
    if kind == "unlock_card":
        c = respond.card(detect.load("profile.json", data_dir), request["card"])
        if not c:
            raise ValueError("no card with that id")
        path = respond._append(outbox_dir, "card_unlocks.jsonl", {"card": c["id"], "issuer": c["issuer"]})
        return {"status": "card ending %s unlocked (simulated)" % c["last4"], "file": path}
    if kind == "release_quarantine":
        path = respond._append(outbox_dir, "quarantine_releases.jsonl", {"email": request["email"]})
        return {"status": "email %s back in the inbox (simulated)" % request["email"], "file": path}
    raise ValueError("unknown request")


def verification(data_dir, store):
    """The Persona claim to check against: the one kept in the store wins over the file, as in run.py."""
    stored = st.claim(store) if store is not None else None
    return dict(stored) if stored else detect.load("verification.json", data_dir)


def handle(request, data_dir=None, run_dir=None, outbox_dir=None, now=None, store=None):
    """Check one request with Persona, then apply it or hold it. Returns the result record."""
    data_dir = data_dir or os.path.join(ROOT, "data")
    run_dir = run_dir or os.path.join(ROOT, "runs")
    outbox_dir = outbox_dir or os.path.join(ROOT, "outbox")
    now = now or datetime.now().isoformat(timespec="seconds")
    log = AuditLog(run_dir, "change-" + time.strftime("%Y%m%d-%H%M%S"))
    subject = "request:" + request["type"]
    if store is None:
        store = st.open_store(os.path.join(run_dir, "guardian.sqlite3"))
    allowed, reason = respond.guard_request(request, verification(data_dir, store), now)
    log.event("guard", "guard_" + request["type"], request, {"allowed": allowed, "reason": reason}, subject)
    if allowed:
        try:
            result = apply(request, data_dir, outbox_dir)
        except ValueError as e:
            result = {"status": "not changed", "reason": str(e)}
        else:
            result["reason"] = reason
    else:
        result = {"status": "waiting for you", "reason": reason}
    log.event("act", "act_" + request["type"], request, result, subject)
    return result


def parse(argv):
    """Command-line words -> a request dict. Raises ValueError with a usage hint."""
    try:
        if argv[0] == "set" and len(argv) == 3:
            return {"type": "change_setting", "gate": argv[1], "value": ON_OFF[argv[2].lower()]}
        if argv[0] == "contact" and argv[1] == "add" and len(argv) in (5, 6):
            consent = argv[5:] == ["--consent"]
            if len(argv) == 6 and not consent:
                raise KeyError
            return {"type": "change_contact", "op": "add",
                    "contact": {"name": argv[2], "channel": argv[3], "address": argv[4], "consent": consent}}
        if argv[0] == "contact" and argv[1] == "remove" and len(argv) == 3:
            return {"type": "change_contact", "op": "remove", "contact": {"address": argv[2]}}
        if argv[0] == "contact" and argv[1] == "consent" and len(argv) == 4:
            return {"type": "change_contact", "op": "consent",
                    "contact": {"address": argv[2], "consent": ON_OFF[argv[3].lower()]}}
        if argv[0] == "unlock" and len(argv) == 2:
            return {"type": "unlock_card", "card": argv[1]}
        if argv[0] == "release" and len(argv) == 2:
            return {"type": "release_quarantine", "email": argv[1]}
    except (IndexError, KeyError):
        pass
    raise ValueError(__doc__.split("\n\n")[1])


if __name__ == "__main__":
    try:
        req = parse(sys.argv[1:])
    except ValueError as e:
        sys.exit("usage:\n" + str(e))
    out = handle(req)
    print(out["status"], "-", out["reason"])
    sys.exit(0 if out["status"] != "waiting for you" else 2)
