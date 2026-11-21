"""Replay synthetic people through the real agent and send its audit trail to Amplitude.

    python3 agent/replay.py            # dry run: writes runs/replay/events.jsonl, sends nothing
    python3 agent/replay.py --send     # also sends the events to Amplitude (needs AMPLITUDE_API_KEY)

Every event comes from Guardian actually running: one run per evening over 30 days of each synthetic
person's fictional email, calls, texts, card charges and breaches (agent/synthetic.py). Nothing is typed
into Amplitude by hand. The dates are shifted so the month ends today, and each event is stamped with the
simulated time of its run.

Events are clearly labelled so nobody mistakes them for real users: user ids start with "synthetic:", and
every event carries dataset="synthetic replay". The event names are the same ones the live agent sends
(agent/audit.py), so the charts work unchanged when real runs arrive.

People:
  rose              Rose, 78, senior protection on (the demo persona)
  rose-senior-off   the same month for Rose with senior protection off, for the gate comparison
  jordan            Jordan, 34, standard protection, partner has NOT consented to alerts
  walt              Walt, 71, senior protection, held-out scam phrasings
  maya              Maya, 46, runs a small business, held-out scam phrasings
"""
import json
import os
import shutil
import sys
import tempfile
import urllib.request
from datetime import date, datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent import evaluate, synthetic
from agent import run as runner
from agent.audit import AuditLog

BATCH_URL = "https://api2.amplitude.com/batch"
DAYS = 30
DATASET = "synthetic replay"

_base_persona = synthetic.persona


def persona(name):
    if name == "walt":
        return {
            "name": "Walt (synthetic, 71)", "emails": ["walt.synth@example.org"],
            "cards": [{"id": "card-w1", "last4": "4444", "issuer": "Lakeside Credit Union", "issuer_lock_api": True}],
            "accounts": [{"name": "Lakeside Credit Union", "domain": "lakesidecu.example"},
                         {"name": "HomeMart", "domain": "homemart.example"},
                         {"name": "NewsDaily", "domain": "newsdaily.example"},
                         {"name": "PayLink", "domain": "paylink.example"}],
            "usual_merchants": ["Main St Diner", "Hardware Hub", "NewsDaily", "Corner Pharmacy"],
            "started_actions": [], "protection": "senior",
            "trusted_contacts": [{"name": "Dana (son)", "channel": "sms", "address": "+1-555-0181", "consent": True}],
            "phone_contacts": [{"name": "Lakeside Credit Union", "number": "+1-555-0191"},
                               {"name": "Corner Pharmacy", "number": "+1-555-0150"},
                               {"name": "Dana (son)", "number": "+1-555-0181"}],
            "_family": "Dana (son)", "_errand": "Corner Pharmacy", "_shop_merchant": "HomeMart",
        }
    if name == "maya":
        return {
            "name": "Maya (synthetic, 46)", "emails": ["maya.synth@example.com"],
            "cards": [{"id": "card-m1", "last4": "5555", "issuer": "Harbor Business Bank", "issuer_lock_api": True},
                      {"id": "card-m2", "last4": "6666", "issuer": "Metro Credit", "issuer_lock_api": False}],
            "accounts": [{"name": "Harbor Business Bank", "domain": "harborbiz.example"},
                         {"name": "SupplyHub", "domain": "supplyhub.example"},
                         {"name": "InvoiceFlow", "domain": "invoiceflow.example"},
                         {"name": "PayLink", "domain": "paylink.example"}],
            "usual_merchants": ["Print Shop", "Office Depot Lite", "SupplyHub", "Bean There Cafe"],
            "started_actions": [], "protection": "standard",
            "trusted_contacts": [{"name": "Lee (business partner)", "channel": "sms", "address": "+1-555-0171", "consent": True}],
            "phone_contacts": [{"name": "Harbor Business Bank", "number": "+1-555-0197"},
                               {"name": "Lee (business partner)", "number": "+1-555-0171"},
                               {"name": "Print Shop", "number": "+1-555-0134"}],
            "_family": "Lee (business partner)", "_errand": "Print Shop", "_shop_merchant": "SupplyHub",
        }
    return _base_persona(name)


# (user key, synthetic person, variant, protection override, seed)
PEOPLE = [
    ("rose", "rose", "dev", None, 7),
    ("rose-senior-off", "rose", "dev", "standard", 7),
    ("jordan", "jordan", "dev", None, 7),
    ("walt", "walt", "holdout", None, 11),
    ("maya", "maya", "holdout", None, 13),
]


def _flat(prefix, obj, out, depth=0):
    """Scalar fields from a nested dict, so they can be charted directly."""
    if not isinstance(obj, dict) or depth > 1:
        return
    for k, v in obj.items():
        if isinstance(v, (str, int, float, bool)) or v is None:
            out[prefix + k] = v
        elif isinstance(v, dict):
            _flat(prefix + k + "_", v, out, depth + 1)


class ReplayLog(AuditLog):
    """AuditLog that stamps simulated time and collects Amplitude events instead of sending one by one."""
    user = None
    user_props = {}
    clock = None
    sink = []

    def __init__(self, run_dir, run_id):
        super().__init__(run_dir, run_id)
        self.key = ""  # never send from inside the run
        self.seq = 0

    def event(self, step, tool, inputs, output, subject_id=""):
        rec = super().event(step, tool, inputs, output, subject_id)
        self.seq += 1
        ts = ReplayLog.clock + timedelta(seconds=self.seq * 2)
        props = {"dataset": DATASET, "persona": ReplayLog.user, "run_id": self.run_id, "step": step,
                 "subject_id": subject_id, "output": output, "gates": self.gates}
        for g, v in self.gates.items():
            props["gate_" + g] = v
        _flat("out_", output if isinstance(output, dict) else {}, props)
        if tool.startswith(("detect_", "guard_", "act_")):
            props["kind"] = tool.split("_", 1)[1]
        ReplayLog.sink.append({
            "user_id": "synthetic:" + ReplayLog.user, "event_type": "agent_" + tool,
            "time": int(ts.timestamp() * 1000), "session_id": int(ReplayLog.clock.timestamp() * 1000),
            "insert_id": "%s-%s-%d" % (ReplayLog.user, self.run_id, self.seq),
            "event_properties": props, "user_properties": ReplayLog.user_props,
            "platform": "Guardian agent", "app_version": "hackathon"})
        return rec


def replay(user, name, variant, protection, seed, workdir):
    world = synthetic.generate(name, seed, DAYS, variant)
    if protection:
        world["profile"]["protection"] = protection
    p = world["profile"]
    ReplayLog.user = user
    ReplayLog.user_props = {"dataset": DATASET, "persona_name": p["name"], "protection": p["protection"],
                            "cards": len(p["cards"]),
                            "trusted_contact_consent": any(c.get("consent") for c in p["trusted_contacts"]),
                            "scenario_set": variant}
    store = runner.st.LocalStore(os.path.join(workdir, "store.sqlite3"))
    run_dir, outbox, folder = (os.path.join(workdir, d) for d in ("runs", "outbox", "data"))
    totals = {"threats_new": 0, "stopped": 0, "family_told": 0, "waiting": 0}
    for d_i in range(DAYS):
        day = synthetic.START + timedelta(days=d_i)
        evaluate._day_files(world, folder, day)
        ReplayLog.clock = datetime.combine(day, datetime.min.time()) + timedelta(hours=21)
        s = runner.run(data_dir=folder, run_dir=run_dir, outbox_dir=outbox, store=store,
                       now=day.isoformat() + "T21:00:00")
        log = ReplayLog(run_dir, s["run_id"])  # same run id, continues the sequence for the summary event
        log.seq, log.gates = 900, {k: v["value"] for k, v in s["gates"].items()}
        log.event("summary", "run_summary", {}, {
            "threats": s["threats"], "new_threats": s["new_threats"], "stopped": s["stopped"],
            "alerts": s["alerts"], "family_told": s["family_told"], "waiting_for_you": s["waiting_for_you"],
            "failed": s["failed"], "day": day.isoformat()}, "run")
        totals["threats_new"] += s["new_threats"]
        totals["stopped"] += s["stopped"]
        totals["family_told"] += s["family_told"]
        totals["waiting"] += s["waiting_for_you"]
    return totals


def send(key, events):
    for i in range(0, len(events), 500):
        body = json.dumps({"api_key": key, "events": events[i:i + 500]}, default=str).encode()
        req = urllib.request.Request(BATCH_URL, data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            out = json.loads(resp.read())
        if out.get("code") != 200:
            raise RuntimeError("Amplitude: %s" % out)
        print("  sent %d-%d: %s events ingested" % (i + 1, i + len(events[i:i + 500]), out.get("events_ingested")))


def main():
    do_send = "--send" in sys.argv
    runner.load_env()
    key = os.environ.get("AMPLITUDE_API_KEY", "")
    if do_send and not key:
        sys.exit("AMPLITUDE_API_KEY is not set in .env")
    saved = {k: os.environ.pop(k) for k in evaluate.OFFLINE if k in os.environ}  # runs stay offline
    synthetic.START = date.today() - timedelta(days=DAYS - 1)
    synthetic.persona = persona
    runner.AuditLog = ReplayLog
    out_dir = os.path.join(runner.ROOT, "runs", "replay")
    os.makedirs(out_dir, exist_ok=True)
    try:
        for user, name, variant, protection, seed in PEOPLE:
            workdir = tempfile.mkdtemp(prefix="guardian-replay-")
            try:
                before = len(ReplayLog.sink)
                t = replay(user, name, variant, protection, seed, workdir)
                print("%-16s %5d events  %3d new threats  %3d stopped  %2d contact told  %2d waiting" % (
                    user, len(ReplayLog.sink) - before, t["threats_new"], t["stopped"], t["family_told"], t["waiting"]))
            finally:
                shutil.rmtree(workdir, ignore_errors=True)
    finally:
        os.environ.update(saved)
        synthetic.persona = _base_persona
    path = os.path.join(out_dir, "events.jsonl")
    with open(path, "w") as f:
        for e in ReplayLog.sink:
            f.write(json.dumps(e, default=str) + "\n")
    print("%d events from %s to %s -> %s" % (len(ReplayLog.sink), synthetic.START, date.today(), path))
    if do_send:
        send(key, ReplayLog.sink)
    else:
        print("dry run: nothing sent (add --send)")


if __name__ == "__main__":
    main()
