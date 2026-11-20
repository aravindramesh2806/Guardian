"""One command before going on stage: reset, run, and build both pages.

    python3 agent/demo.py

It clears the store (SingleStore when configured, so the first run shows every threat as new again),
deletes runs/ and outbox/, runs the agent, writes the brief and report, and builds the live-call page.
A Persona stand-in older than 20 hours is re-dated, so the card lock is not held on stage; a result
written by the real Persona sidecar is never touched.
"""
import json
import os
import shutil
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent import brief, live, respond
from agent import run as runner
from agent import store as st

ROOT = runner.ROOT


def refresh_stand_in(path, now):
    """Re-date the Persona stand-in if it would expire soon. Returns what it did."""
    with open(path) as f:
        v = json.load(f)
    if "stand-in" not in v.get("source", ""):
        return "real Persona result kept (%s, checked %s)" % (v.get("result"), v.get("checked_at"))
    try:
        age = now - respond._parse_time(v["checked_at"])
    except (KeyError, ValueError):
        age = timedelta(days=999)
    if age < timedelta(hours=20):
        return "Persona stand-in is fresh (checked %s)" % v["checked_at"]
    v["checked_at"] = now.isoformat(timespec="seconds")
    with open(path, "w") as f:
        json.dump(v, f, indent=2)
        f.write("\n")
    return "Persona stand-in re-dated to %s (it is a stand-in until the sidecar runs)" % v["checked_at"]


def main():
    runner.load_env()
    runs, outbox = os.path.join(ROOT, "runs"), os.path.join(ROOT, "outbox")
    store = st.open_store(os.path.join(runs, "guardian.sqlite3"))
    st.reset(store)
    print("store cleared:", store.name)
    if "unreachable" in store.name:
        print("WARNING: SingleStore was not reached, so it was NOT cleared. This run uses local SQLite.\n"
              "         If SingleStore comes back, run this command again or the opening shows 0 new threats.")
    shutil.rmtree(runs, ignore_errors=True)
    shutil.rmtree(outbox, ignore_errors=True)
    print(refresh_stand_in(os.path.join(ROOT, "data", "verification.json"), datetime.now()))
    s = runner.run()
    print("run: %d threats, %d new, %d stopped, %d family told, %d waiting for you (store: %s)" % (
        s["threats"], s["new_threats"], s["stopped"], s["family_told"], s["waiting_for_you"], s["store"]))
    print("\n".join(brief.brief_lines(s)))
    print(brief.report(s, runs, os.path.join(ROOT, "web", "report.html")))
    print(live.build()[1])
    print("\nNow: python3 -m http.server 8000 -d web")
    print("  http://localhost:8000/report.html   the morning brief and evidence")
    print("  http://localhost:8000/live.html     the live call warning")


if __name__ == "__main__":
    main()
