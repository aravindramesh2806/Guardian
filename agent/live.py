"""Live call warning: rescore a call after every turn, so the warning lands before the money moves.

Only the caller's words are scored (what the person says back is not evidence). Rules only: a live
warning cannot wait for a model call. The scoring is detect.call_score, the same rules as voicemails.

`python3 agent/live.py` replays data/live_call.json and writes web/live.html, a phone-shaped page
whose Dynamic Island shows "Guardian is listening" and turns into a warning when the score crosses.
"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent import detect
from agent.audit import AuditLog

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Most telling reason first; the first one found becomes the line on the island.
HEADLINES = (
    ("asks for money", "They are asking for money or gift cards."),
    ("keep it secret", "They want you to keep this secret."),
    ("claims to be family", "Someone claiming to be family, from a number you don't know."),
    ("caller ID says", "The caller ID doesn't match the real number."),
    ("link", "They want you to pay through a link."),
)


def headline(reasons):
    for needle, line in HEADLINES:
        if any(needle in r for r in reasons):
            return line
    return reasons[0] if reasons else ""


def thresholds(senior):
    """(scam, watch) bars; the same ones scam_calls uses."""
    return (0.5, 0.3) if senior else (0.6, 0.4)


def score_stream(call, turns, contacts, senior=True):
    """One row per turn: the running score, its reasons and a level (safe, watch or scam).

    The first row at level "scam" has alert=True; later rows keep the warning up.
    """
    scam, watch = thresholds(senior)
    caller_words, rows, alerted = [], [], False
    for turn in turns:
        if turn["speaker"] == "caller":
            caller_words.append(turn["text"])
        score, reasons = detect.call_score(dict(call, transcript=" ".join(caller_words)), contacts)
        level = "scam" if score >= scam else "watch" if score >= watch else "safe"
        first = level == "scam" and not alerted
        alerted = alerted or level == "scam"
        rows.append({"t": turn["t"], "speaker": turn["speaker"], "text": turn["text"], "score": score,
                     "reasons": reasons, "level": level, "alert": first,
                     "headline": headline(reasons) if level == "scam" else ""})
    return rows


def outcome(call, profile):
    """What Guardian does once the warning has fired: block, and tell family who agreed to be told."""
    told = [c["name"] for c in profile.get("trusted_contacts", []) if c.get("consent")]
    return {"blocked": call["from"], "told": told}


PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>Guardian live call</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
:root{--bg:#f4f5f7;--fg:#1a202c;--muted:#4a5568;--line:#e2e8f0}
@media (prefers-color-scheme: dark){:root{--bg:#10131a;--fg:#e2e8f0;--muted:#a0aec0;--line:#2d3748}}
body{margin:0;padding:16px;background:var(--bg);color:var(--fg);font-family:system-ui,sans-serif}
.wrap{max-width:380px;margin:0 auto}
.phone{background:#000;border-radius:44px;padding:12px;box-shadow:0 8px 30px rgba(0,0,0,.35)}
.screen{background:#0b0d12;border-radius:34px;height:640px;position:relative;overflow:hidden;color:#e2e8f0}
.island{position:absolute;top:10px;left:50%%;transform:translateX(-50%%);background:#000;color:#fff;
 border-radius:22px;width:120px;height:34px;transition:all .35s ease;display:flex;align-items:center;
 justify-content:center;gap:8px;font-size:13px;overflow:hidden;z-index:2;box-sizing:border-box;padding:0 12px}
.island.listen{width:230px}
.island.scam{width:338px;height:92px;border-radius:30px;background:#9b2c2c;align-items:flex-start;
 padding:14px 16px;justify-content:flex-start;flex-direction:column;gap:4px}
.island.done{width:338px;height:74px;border-radius:30px;background:#22543d;align-items:flex-start;
 padding:14px 16px;justify-content:flex-start;flex-direction:column;gap:4px}
.dot{width:9px;height:9px;border-radius:50%%;background:#48bb78;animation:pulse 1.2s infinite}
@keyframes pulse{50%%{opacity:.25}}
@media (prefers-reduced-motion: reduce){.dot{animation:none}.island{transition:none}}
.island b{font-size:14px}.island small{font-size:12px;opacity:.9;line-height:1.3}
.call{padding:70px 14px 14px;height:100%%;box-sizing:border-box;display:flex;flex-direction:column;transition:padding .35s}
.island.scam ~ .call{padding-top:120px}.island.done ~ .call{padding-top:100px}
.who{text-align:center;margin-bottom:8px}.who b{display:block;font-size:18px}.who span{font-size:13px;color:#a0aec0}
.log{flex:1;overflow-y:auto;display:flex;flex-direction:column;gap:6px}
.msg{max-width:82%%;padding:7px 11px;border-radius:14px;font-size:14px}
.caller{background:#2d3748;align-self:flex-start}.rose{background:#2b6cb0;align-self:flex-end}
.meter{height:8px;background:#2d3748;border-radius:4px;margin:10px 0 4px;overflow:hidden}
.meter i{display:block;height:100%%;width:0;background:#48bb78;transition:width .4s,background .4s}
.cap{font-size:12px;color:#a0aec0;display:flex;justify-content:space-between}
button{margin:14px 0 0;width:100%%;padding:10px;border-radius:8px;border:1px solid var(--line);
 background:transparent;color:var(--fg);font-size:15px;cursor:pointer}
.why{font-size:13px;color:var(--muted);margin-top:12px}
button.primary{background:#9b2c2c;border-color:#9b2c2c;color:#fff;font-weight:600;padding:14px}
.ask{font-weight:600;margin:16px 0 0}
.island.ok{width:338px;height:74px;border-radius:30px;background:#2d3748;align-items:flex-start;
 padding:14px 16px;justify-content:flex-start;flex-direction:column;gap:4px}
.island.ok ~ .call{padding-top:100px}
</style></head><body><div class="wrap">
<div class="phone"><div class="screen">
<div class="island" id="island"></div>
<div class="call"><div class="who"><b id="name"></b><span id="num"></span></div>
<div class="log" id="log"></div>
<div class="meter"><i id="bar"></i></div>
<div class="cap"><span>Scam score</span><span id="score">0.00</span></div></div>
</div></div>
<div id="choice" hidden>
<p class="ask">Guardian thinks this is a scam. What would you like to do?</p>
<button id="block" class="primary">Block this number and hang up</button>
<button id="keep">I know this caller</button>
</div>
<button id="play">Replay the call</button>
<p class="why" id="why">Replay of a fictional call. Guardian scores only the caller's words, after every turn.</p>
</div>
<script>
const DATA = %s;
const $ = (id) => document.getElementById(id);
let timers = [];
function island(state, html) { const el = $("island"); el.className = "island " + state; el.innerHTML = html; }
function islandText(state, title, small) {
  const el = $("island"); el.className = "island " + state;
  const b = document.createElement("b"); b.textContent = title;
  const s = document.createElement("small"); s.textContent = small;
  el.replaceChildren(b, s);
}
function reset() {
  timers.forEach(clearTimeout); timers = [];
  $("log").innerHTML = ""; $("bar").style.width = "0"; $("bar").style.background = "#48bb78";
  $("score").textContent = "0.00"; $("name").textContent = DATA.caller_id; $("num").textContent = DATA.from;
  island("", "");
  $("choice").hidden = true;
  $("why").textContent = "Replay of a fictional call. Guardian scores only the caller's words, after every turn.";
}
function step(row) {
  const m = document.createElement("div");
  m.className = "msg " + row.speaker; m.textContent = row.text;
  $("log").appendChild(m); $("log").scrollTop = 1e6;
  $("score").textContent = row.score.toFixed(2);
  $("bar").style.width = Math.round(row.score * 100) + "%%";
  $("bar").style.background = row.level === "scam" ? "#e53e3e" : row.level === "watch" ? "#ecc94b" : "#48bb78";
  if (row.alert) {
    // First tell the person, then offer to block: Guardian never blocks a caller on its own mid-call.
    islandText("scam", "Hang up. This looks like a scam.", row.headline);
    $("why").textContent = "Why: " + row.reasons.join("; ") + ".";
    $("choice").hidden = false;
  }
}
function play() {
  reset();
  island("listen", '<span class="dot"></span>Guardian is listening');
  const t0 = DATA.rows[0].t;
  DATA.rows.forEach((row) => timers.push(setTimeout(() => step(row), (row.t - t0 + 1) * 700)));
}
$("block").addEventListener("click", () => {
  timers.forEach(clearTimeout); timers = [];
  const told = DATA.outcome.told.length ? " " + DATA.outcome.told.join(", ") + " was told." : "";
  islandText("done", "Blocked.", DATA.outcome.blocked + " blocked." + told);
  $("choice").hidden = true;
});
$("keep").addEventListener("click", () => {
  islandText("ok", "Not blocked.", "Guardian keeps listening. Never share a code or pay by gift card.");
  $("choice").hidden = true;
});
$("play").addEventListener("click", play);
play();
</script></body></html>"""


def page(call, rows, result):
    data = {"caller_id": call.get("caller_id", "Unknown"), "from": call["from"], "rows": rows, "outcome": result}
    # "</" is escaped so no transcript text can close the script tag.
    blob = json.dumps(data).replace("</", "<\\/")
    return PAGE % blob


def build(data_dir=None, out=None, run_dir=None):
    """Score the replay, record it in the audit trail like every other step, and write the page."""
    scenario = detect.load("live_call.json", data_dir)
    profile = detect.load("profile.json", data_dir)
    call = scenario["call"]
    rows = score_stream(call, scenario["turns"], profile.get("phone_contacts", []),
                        senior=profile.get("protection") == "senior")
    result = outcome(call, profile)
    subject = "live:" + call["id"]
    log = AuditLog(run_dir or os.path.join(ROOT, "runs"), "live-" + time.strftime("%Y%m%d-%H%M%S"))
    log.event("listen", "live_listening", {"call": call["id"]}, {"turns": len(rows)}, subject)
    for r in rows:
        if r["alert"]:
            log.event("warn", "live_warning", {"call": call["id"], "t": r["t"]},
                      {"score": r["score"], "headline": r["headline"], "reasons": r["reasons"]}, subject)
    # Live, Guardian warns first and then offers the block: the person decides, mid-call.
    log.event("act", "live_offer_block", {"call": call["id"]},
              {"offered": "block_number", "number": result["blocked"], "family_told_if_blocked": result["told"]}, subject)
    out = out or os.path.join(ROOT, "web", "live.html")
    with open(out, "w") as f:
        f.write(page(call, rows, result))
    return rows, out


if __name__ == "__main__":
    from agent.run import load_env
    load_env()
    rows, out = build()
    for r in rows:
        mark = "  <-- WARNING: " + r["headline"] if r["alert"] else ""
        print("%4ds %-6s score %.2f %-5s %s%s" % (r["t"], r["speaker"], r["score"], r["level"], r["text"], mark))
    print(out)
