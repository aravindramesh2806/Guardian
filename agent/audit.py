"""Audit trail: every tool call is an event. Written locally, and sent to Amplitude when a key is set."""
import json
import os
import time
import urllib.request

AMPLITUDE_URL = "https://api2.amplitude.com/2/httpapi"


class AuditLog:
    def __init__(self, run_dir, run_id):
        os.makedirs(run_dir, exist_ok=True)
        self.run_id = run_id
        self.path = os.path.join(run_dir, run_id + ".jsonl")
        self.key = os.environ.get("AMPLITUDE_API_KEY", "")

    def event(self, step, tool, inputs, output, subject_id=""):
        rec = {"run_id": self.run_id, "step": step, "tool": tool, "subject_id": subject_id,
               "inputs": inputs, "output": output, "ts": int(time.time() * 1000)}
        with open(self.path, "a") as f:
            f.write(json.dumps(rec, default=str) + "\n")
        if self.key:
            self._send_amplitude(rec)
        return rec

    def _send_amplitude(self, rec):
        body = {"api_key": self.key, "events": [{
            "user_id": "demo-user", "event_type": "agent_" + rec["tool"],
            "event_properties": {"run_id": rec["run_id"], "step": rec["step"],
                                 "subject_id": rec["subject_id"], "output": rec["output"]},
            "time": rec["ts"]}]}
        req = urllib.request.Request(AMPLITUDE_URL, data=json.dumps(body, default=str).encode(),
                                     headers={"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(req, timeout=5).read()
        except Exception as e:  # the audit file is still written if Amplitude is unreachable
            with open(self.path + ".errors", "a") as f:
                f.write("amplitude: %s\n" % e)
