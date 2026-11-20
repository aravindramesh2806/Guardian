"use strict";
// The Persona check inside the app. The browser only ever gets a short-lived access token; the app
// server asks the local Persona sidecar for the result and keeps it in this person's store.
const statusEl = document.getElementById("status");
const again = document.getElementById("again");
let widget = null;

function say(text, cls) { statusEl.textContent = text; statusEl.className = cls || "muted"; }

async function post(path, body) {
  const r = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body || {}) });
  const data = await r.json().catch(() => ({}));
  if (r.status === 401) { location.href = "/"; throw new Error("Please sign in."); }
  if (!r.ok) throw new Error(data.error || "Something went wrong. Please try again.");
  return data;
}

async function begin() {
  again.hidden = true;
  say("Starting…");
  if (widget) { widget.destroy(); widget = null; }
  const Relay = window.Relay && (window.Relay.default || window.Relay);
  if (!Relay) { say("The Persona check couldn't load. Run npm install in the persona folder.", "error"); return; }
  try {
    const { flow, accessToken } = await post("/api/persona/begin");
    widget = new Relay(document.getElementById("relay-container"), {
      accessToken, theme: "auto",
      onComplete: async () => {
        say("Checking…");
        try {
          const out = await post("/api/persona/finish", { flow });
          if (out.result === "passed") { say("Verified. Guardian may now lock a card for you.", "status ok"); }
          else { say("Not verified. Card locks will keep waiting for you.", "error"); again.hidden = false; }
        } catch (e) { say(e.message, "error"); again.hidden = false; }
      },
      onExpire: () => { say("That took too long. Starting a new check…"); begin(); },
      onError: () => { say("Something went wrong with the check.", "error"); again.hidden = false; },
    });
    say("Follow the steps above.");
  } catch (e) { say(e.message, "error"); again.hidden = false; }
}

again.addEventListener("click", begin);
begin();
