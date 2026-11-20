"""The daily brief (a few plain lines) and the report page with the evidence behind every action."""
import glob
import html
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def latest(run_dir):
    paths = sorted(glob.glob(os.path.join(run_dir, "*.summary.json")))
    if not paths:
        raise SystemExit("no run found; run agent/run.py first")
    with open(paths[-1]) as f:
        return json.load(f)


def brief_lines(summary):
    """Three to five lines a person reads in ten seconds. Only threats new in this run."""
    new = [r for r in summary["results"] if r["new"]]
    if not new:
        # Nothing new, but an approved action may have just run (for example the dispute).
        done = ["- %s -> %s" % (r["summary"], a["status"]) for r in summary["results"] for a in r["actions"]
                if a["status"].endswith("(simulated)")]
        if done:
            return (["Nothing new since your last check. Done for you since then:"] + done)[:5]
        return ["All clear: nothing new since your last check."]
    family = summary.get("family_told", 0)
    lines = ["%d new threat%s today. %d stopped for you, %d need%s you%s." % (
        len(new), "" if len(new) == 1 else "s", summary["stopped"],
        summary["waiting_for_you"], "s" if summary["waiting_for_you"] == 1 else "",
        (", and your family was told about %d" % family) if family else "")]
    for r in new[:3]:
        done = [a["status"] for a in r["actions"] if a["status"].endswith("(simulated)") and a["action"] != "alert"]
        lines.append("- " + r["summary"] + (" -> " + "; ".join(done) if done else ""))
    for r in summary["results"]:
        for a in r["actions"]:
            if a.get("ask"):
                lines.append("Needs you: " + a["ask"])
    return lines[:5] if len(lines) > 5 else lines


STATSIG_SCRIPT = """<script src="vendor/statsig.min.js"></script>
<script>
// Statsig web SDK: session replay, auto-capture (web analytics) and two custom events.
(async () => {
  const { StatsigClient, StatsigSessionReplayPlugin, StatsigAutoCapturePlugin } = window.Statsig;
  const client = new StatsigClient(%s, { userID: "demo-user" }, {
    plugins: [new StatsigSessionReplayPlugin(), new StatsigAutoCapturePlugin()],
  });
  await client.initializeAsync();
  window.guardianStatsig = client;
  client.logEvent("guardian_report_viewed", %s, %s);
  await client.flush();
  document.querySelectorAll("details[data-kind]").forEach((d) => d.addEventListener("toggle", async () => {
    if (!d.open) return;
    client.logEvent("guardian_threat_opened", d.dataset.kind, { threat: d.dataset.threat });
    await client.flush();
  }));
})().catch((e) => console.error("Statsig failed to start", e));
</script>"""


def statsig_script(summary, client_key):
    """The Statsig tag for the page, or nothing when no client key is set."""
    if not client_key:
        return ""
    meta = {"threats": str(summary["threats"]), "stopped": str(summary["stopped"]),
            "waiting_for_you": str(summary["waiting_for_you"]),
            "family_told": str(summary.get("family_told", 0))}
    return STATSIG_SCRIPT % (json.dumps(client_key), json.dumps(summary["run_id"]), json.dumps(meta))


def gate_badge(summary):
    """One line showing which gates were on for this run and who decided."""
    gates = summary.get("gates") or {}
    if not gates:
        return ""
    parts = ["%s %s (%s)" % (name, "on" if g["value"] else "off", g["source"].split(" ")[0])
             for name, g in gates.items()]
    return "<p class='ev'>Gates: %s</p>" % html.escape(" · ".join(parts))


def messages_html(actions):
    """The messages Guardian sent for this threat, shown as they arrived on each person's phone."""
    seen, out = set(), []
    for a in actions:
        m = a.get("message")
        if not m or (m["to"], m["text"]) in seen:
            continue
        seen.add((m["to"], m["text"]))
        out.append("<div class='msg'><div class='msg-head'>To %s · %s%s</div><div class='msg-body'>%s</div></div>" % (
            html.escape(m["to"]), html.escape(m["channel"]),
            (" · drafted by %s" % html.escape(m["drafted_by"])) if m.get("drafted_by") else "",
            html.escape(m["text"])))
    return ("<div class='msgs'>%s</div>" % "".join(out)) if out else ""


def approvals_html(actions):
    """A box for each action that waits for the person, with the exact way to say yes."""
    return "".join(
        "<div class='ask'><b>Needs you:</b> %s<br><span class='ev'>To approve, run</span> "
        "<code class='cmd'>python3 agent/run.py --approve %s</code></div>" % (
            html.escape(a["ask"]), html.escape(a["approve"]))
        for a in actions if a.get("ask") and a.get("approve"))


def report(summary, run_dir, out, client_key=None):
    """Static page: the brief, then each threat with its actions and the logged steps behind them."""
    if client_key is None:
        client_key = os.environ.get("STATSIG_CLIENT_KEY", "")
    steps = {}
    log = os.path.join(run_dir, summary["run_id"] + ".jsonl")
    if os.path.exists(log):
        with open(log) as f:
            for line in f:
                row = json.loads(line)
                steps.setdefault(row["subject_id"], []).append(row)
    colour = {"high": "#9b2c2c", "medium": "#b7791f"}
    cards = []
    for r in summary["results"]:
        acts = "".join("<li><b>%s</b>: %s%s</li>" % (
            html.escape(a["action"]), html.escape(a["status"]),
            (" <i>(%s)</i>" % html.escape(a["reason"])) if a["status"] == "waiting for you" else "")
            for a in r["actions"])
        trail = "".join("<li><code>%s</code> %s</li>" % (
            html.escape(s["tool"]), html.escape(json.dumps(s["output"], default=str)[:200]))
            for s in steps.get(r["threat"], []))
        cards.append(
            "<section><h2><span class='tag' style='background:%s'>%s</span> %s</h2>"
            "<p class='ev'>Evidence: <code>%s</code></p><ul>%s</ul>%s%s"
            "<details data-kind='%s' data-threat='%s'><summary>Audit trail (%d steps)</summary>"
            "<ol>%s</ol></details></section>" % (
                colour.get(r["severity"], "#4a5568"), html.escape(r["severity"]), html.escape(r["summary"]),
                html.escape(json.dumps(r["evidence"], default=str)), acts,
                messages_html(r["actions"]), approvals_html(r["actions"]), html.escape(r["kind"]),
                html.escape(r["threat"]), len(steps.get(r["threat"], [])), trail))
    page = """<!doctype html><html><head><meta charset="utf-8"><title>Guardian report</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>:root{--bg:#fff;--fg:#1a202c;--line:#e2e8f0;--muted:#4a5568;--bubble:#edf2f7}
@media (prefers-color-scheme: dark){:root{--bg:#171923;--fg:#e2e8f0;--line:#2d3748;--muted:#a0aec0;--bubble:#2d3748}}
body{font-family:system-ui,sans-serif;margin:0 auto;padding:16px;max-width:880px;background:var(--bg);color:var(--fg)}
section{border:1px solid var(--line);border-radius:8px;padding:12px 16px;margin:12px 0}
h2{font-size:17px}.tag{color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;text-transform:uppercase}
.ev,code{font-size:12px;color:var(--muted);word-break:break-word}.brief{white-space:pre-line;font-size:16px}
.msgs{display:flex;flex-wrap:wrap;gap:10px;margin:8px 0}
.msg{flex:1 1 260px;max-width:400px;background:var(--bubble);border-radius:14px;padding:10px 14px}
.msg-head{font-size:12px;color:var(--muted);margin-bottom:4px}.msg-body{white-space:pre-line;font-size:14px}
.ask{border:2px solid #b7791f;border-radius:8px;padding:10px 14px;margin:8px 0}
code.cmd{display:inline-block;font-size:13px;color:var(--fg);background:var(--bubble);padding:2px 6px;border-radius:4px}</style>
</head><body><h1>Guardian</h1><p class="brief">%s</p>
<p class="ev">Run %s · data: %s · Persona check: %s</p>%s%s%s</body></html>""" % (
        html.escape("\n".join(brief_lines(summary))), html.escape(summary["run_id"]),
        html.escape(summary["store"]), html.escape(str(summary["persona"])), gate_badge(summary),
        "".join(cards), statsig_script(summary, client_key))
    with open(out, "w") as f:
        f.write(page)
    return out


if __name__ == "__main__":
    from agent.run import load_env
    load_env()
    run_dir = os.path.join(ROOT, "runs")
    s = latest(run_dir)
    print("\n".join(brief_lines(s)))
    print(report(s, run_dir, os.path.join(ROOT, "web", "report.html")))
