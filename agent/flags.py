"""Feature gates. Statsig decides when STATSIG_SERVER_SECRET is set; data/gates.json decides otherwise.

Every gate records its source ("statsig" or "local"), so the audit trail and Amplitude show which
setting was live for each run. That is Amplitude + Statsig's "complete the loop" challenge: flip a gate
in Statsig, run again, and compare the two groups of events in Amplitude.

The HTTP endpoint below follows Statsig's server API as we understand it; confirm on the first live call.
"""
import json
import os
import urllib.request

STATSIG_CHECK_GATE = "https://api.statsig.com/v1/check_gate"

# Gate name -> where its local default comes from.
GATES = ("senior_protection", "auto_quarantine", "auto_block_numbers", "auto_lock_card",
         "notify_trusted_contacts", "dispute_needs_approval", "kill_switch")


def _statsig(gate, user_id, secret):
    """One live gate check. Returns True/False. Raises on any failure."""
    body = json.dumps({"user": {"userID": user_id}, "gateName": gate}).encode()
    req = urllib.request.Request(STATSIG_CHECK_GATE, data=body, headers={
        "Content-Type": "application/json", "statsig-api-key": secret})
    with urllib.request.urlopen(req, timeout=5) as resp:
        out = json.loads(resp.read())
    if not isinstance(out.get("value"), bool):
        raise ValueError("unexpected Statsig response")
    return out["value"]


def local_default(gate, local_gates, profile):
    if gate == "senior_protection":
        return profile.get("protection") == "senior"
    return bool(local_gates.get(gate, False))


def snapshot(local_gates, profile, user_id="demo-user", check=None):
    """Every gate's value for this run: {name: {"value": bool, "source": str}}.

    `check` replaces the live Statsig call (tests pass a stub).
    """
    secret = os.environ.get("STATSIG_SERVER_SECRET", "")
    live = check or (lambda gate, user: _statsig(gate, user, secret))
    use_live = bool(check or secret)
    out = {}
    for gate in GATES:
        fallback = local_default(gate, local_gates, profile)
        if not use_live:
            out[gate] = {"value": fallback, "source": "local"}
            continue
        try:
            out[gate] = {"value": live(gate, user_id), "source": "statsig"}
        except Exception as e:  # a failed gate check must never stop protection
            out[gate] = {"value": fallback, "source": "local (statsig error: %s)" % type(e).__name__}
    return out


def values(snap):
    return {k: v["value"] for k, v in snap.items()}
