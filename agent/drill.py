"""Guardian as a Firedrill target (the jsonl-process.v1 driver).

Firedrill starts this process once per drill and writes one JSON line per step to stdin:
    {"id": ..., "session": ..., "kind": "message" | "task", "input": ...}
Each step runs one Guardian pass over the synthetic Gmail and Stripe (see agent/firedrill.py) and
answers on stdout with {"id": ..., "output": <the daily brief>} or {"id": ..., "error": ...}.

The person can reply in plain words. A clear yes to the dispute ("yes, dispute it") approves disputes
for the rest of the session; nothing else they say changes a gate. Stdout carries only protocol lines.
"""
import json
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent import brief, run as runner
from agent import store as st

YES = re.compile(r"\b(yes|yeah|yep|approve|approved|confirm|confirmed|go ahead|please do|do it)\b")
NO = re.compile(r"\b(no|not|don't|dont|do not|never|wait|hold|stop|cancel)\b")


def text_of(value):
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for k in ("text", "message", "content", "instruction"):
            if isinstance(value.get(k), str):
                return value[k]
    return json.dumps(value) if value is not None else ""


def approves_dispute(text):
    t = text.lower()
    return "dispute" in t and bool(YES.search(t)) and not NO.search(t)


class Session:
    """State for one drill: its own store, run folder and outbox, and what the person has approved."""

    def __init__(self, root):
        self.root = root
        self.store = st.LocalStore(os.path.join(root, "guardian.sqlite3"))
        self.overrides = {}

    def step(self, value):
        said = text_of(value)
        if approves_dispute(said):
            self.overrides["dispute_needs_approval"] = False
        summary = runner.run(run_dir=os.path.join(self.root, "runs"), outbox_dir=os.path.join(self.root, "outbox"),
                             store=self.store, overrides=self.overrides)
        lines = brief.brief_lines(summary)
        if self.overrides.get("dispute_needs_approval") is False:
            filed = [a for r in summary["results"] for a in r["actions"]
                     if a["action"] == "dispute" and a["status"].endswith("simulated)")]
            if filed:
                lines.append("Done: you said yes, so the dispute is filed.")
        return "\n".join(lines)


def main(stdin=sys.stdin, stdout=sys.stdout):
    runner.load_env()
    real_stdout, sys.stdout = stdout, sys.stderr  # nothing but protocol lines on stdout
    sessions = {}
    try:
        for line in stdin:
            if not line.strip():
                continue
            msg_id = None
            try:
                msg = json.loads(line)
                msg_id = msg.get("id")
                key = msg.get("session") or "default"
                if key not in sessions:
                    sessions[key] = Session(tempfile.mkdtemp(prefix="guardian-drill-"))
                out = {"id": msg_id, "output": sessions[key].step(msg.get("input"))}
            except Exception as e:
                out = {"id": msg_id, "error": "%s: %s" % (type(e).__name__, e)}
            real_stdout.write(json.dumps(out) + "\n")
            real_stdout.flush()
    finally:
        sys.stdout = real_stdout


if __name__ == "__main__":
    main()
