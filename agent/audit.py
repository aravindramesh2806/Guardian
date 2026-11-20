"""Audit trail: every tool call is an event. Written locally, and sent to Amplitude when a key is set."""
import hashlib
import json
import os
import time
import urllib.request

AMPLITUDE_URL = "https://api2.amplitude.com/2/httpapi"


def analytics_properties(rec):
    """What may leave the machine for analytics: kinds, numbers, outcomes and gate values.

    Never message text, transcripts, summaries, names, phone numbers or email addresses. The full
    evidence stays in the local audit file and the store. The subject is a short one-way hash, so events
    for the same threat can still be grouped.
    """
    out = rec["output"] if isinstance(rec["output"], dict) else {}
    subject = str(rec["subject_id"])
    props = {"run_id": rec["run_id"], "step": rec["step"], "subject_kind": subject.split(":")[0],
             "subject_ref": hashlib.sha256(subject.encode()).hexdigest()[:12], "gates": rec["gates"]}
    if rec["step"] == "gates":
        return props  # the gate values are already in props
    for k, v in out.items():
        if isinstance(v, (bool, int, float)):
            props[k] = v
    ev = out.get("evidence")
    if isinstance(ev, dict) and isinstance(ev.get("score"), (int, float)):
        props["score"] = ev["score"]
    status = out.get("status")
    if isinstance(status, str):
        props["outcome"] = ("done" if status.endswith(("(simulated)", "(firedrill)"))
                            else "held" if status == "waiting for you"
                            else "failed" if status.startswith("failed")
                            else "repeat" if status.startswith("already done") else "other")
    if isinstance(out.get("drafted_by"), str):
        props["drafted_by"] = out["drafted_by"].split(" ")[0]
    return props


class AuditLog:
    def __init__(self, run_dir, run_id, user_id="demo-user"):
        os.makedirs(run_dir, exist_ok=True)
        self.run_id = run_id
        self.user_id = user_id  # a random id, never a name or address
        self.path = os.path.join(run_dir, run_id + ".jsonl")
        self.key = os.environ.get("AMPLITUDE_API_KEY", "")
        self.gates = {}  # gate values for this run, attached to every event

    def event(self, step, tool, inputs, output, subject_id=""):
        rec = {"run_id": self.run_id, "step": step, "tool": tool, "subject_id": subject_id,
               "inputs": inputs, "output": output, "gates": self.gates, "ts": int(time.time() * 1000)}
        with open(self.path, "a") as f:
            f.write(json.dumps(rec, default=str) + "\n")
        if self.key:
            self._send_amplitude(rec)
        return rec

    def _send_amplitude(self, rec):
        body = {"api_key": self.key, "events": [{
            "user_id": self.user_id, "event_type": "agent_" + rec["tool"],
            "event_properties": analytics_properties(rec), "time": rec["ts"]}]}
        req = urllib.request.Request(AMPLITUDE_URL, data=json.dumps(body, default=str).encode(),
                                     headers={"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(req, timeout=5).read()
        except Exception as e:  # the audit file is still written if Amplitude is unreachable
            with open(self.path + ".errors", "a") as f:
                f.write("amplitude: %s\n" % e)
