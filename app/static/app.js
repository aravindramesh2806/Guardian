"use strict";
// Guardian app. Every piece of text from messages goes in through textContent, never innerHTML.

const app = document.getElementById("app");
let feedCache = null, pollTimer = null, seenThreats = null;

// ---------- small helpers ----------
function el(tag, attrs, ...kids) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else if (v === true) node.setAttribute(k, "");
    else if (v !== false && v != null) node.setAttribute(k, v);
  }
  for (const kid of kids.flat()) if (kid != null && kid !== false) node.append(kid.nodeType ? kid : String(kid));
  return node;
}
function show(...nodes) { app.replaceChildren(...nodes.filter((n) => n != null && n !== false)); window.scrollTo(0, 0); }
function errorBox(msg) { return el("p", { class: "error", role: "alert" }, msg); }
function ago(iso) {
  if (!iso) return "not yet";
  const mins = Math.round((Date.now() - new Date(iso).getTime()) / 60000);
  return mins < 1 ? "just now" : mins === 1 ? "1 minute ago" : mins < 60 ? mins + " minutes ago"
    : Math.round(mins / 60) + " hours ago";
}
async function busy(button, fn) {
  const label = button.textContent;
  button.disabled = true; button.textContent = "One moment…";
  try { return await fn(); } finally { button.disabled = false; button.textContent = label; }
}

// ---------- API and passkeys ----------
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));

function credentialJSON(cred) {
  if (typeof cred.toJSON === "function") return cred.toJSON();
  const r = cred.response, out = { id: cred.id, rawId: b64u(cred.rawId), type: cred.type,
    clientExtensionResults: cred.getClientExtensionResults(), authenticatorAttachment: cred.authenticatorAttachment, response: {
      clientDataJSON: b64u(r.clientDataJSON) } };
  if (r.attestationObject) { out.response.attestationObject = b64u(r.attestationObject);
    if (r.getTransports) out.response.transports = r.getTransports(); }
  if (r.authenticatorData) { out.response.authenticatorData = b64u(r.authenticatorData);
    out.response.signature = b64u(r.signature);
    if (r.userHandle) out.response.userHandle = b64u(r.userHandle); }
  return out;
}

async function call(path, body) {
  const res = await fetch(path, body === undefined ? {} : { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body) });
  const data = await res.json().catch(() => ({}));
  if (res.status === 403 && data.step_up) { await stepUp(); return call(path, body); }
  if (!res.ok) throw new Error(data.error || "Something went wrong. Please try again.");
  return data;
}

async function passkeyGet(begin, finish) {
  const { flow, options } = await call(begin, {});
  options.challenge = unb64u(options.challenge);
  (options.allowCredentials || []).forEach((c) => (c.id = unb64u(c.id)));
  const cred = await navigator.credentials.get({ publicKey: options });
  return call(finish, { flow, credential: credentialJSON(cred) });
}
const stepUp = () => passkeyGet("/api/stepup/begin", "/api/stepup/finish");

async function register(name) {
  const { flow, options } = await call("/api/register/begin", { name });
  options.challenge = unb64u(options.challenge);
  options.user.id = unb64u(options.user.id);
  (options.excludeCredentials || []).forEach((c) => (c.id = unb64u(c.id)));
  const cred = await navigator.credentials.create({ publicKey: options });
  return call("/api/register/finish", { flow, credential: credentialJSON(cred) });
}

// ---------- notifications ----------
async function notify(title, body) {
  if (!("Notification" in window) || Notification.permission !== "granted") return;
  const reg = await navigator.serviceWorker?.getRegistration();
  if (reg) reg.showNotification(title, { body, icon: "/icon.svg" });
  else new Notification(title, { body });
}

// ---------- screens ----------
async function start() {
  if ("serviceWorker" in navigator) navigator.serviceWorker.register("/sw.js").catch(() => {});
  let me;
  try { me = await call("/api/me"); } catch (e) { return show(errorBox(e.message)); }
  if (!me.signed_in) return welcome();
  if (!me.setup_done) return setupWizard();
  return home();
}

function welcome() {
  if (!window.PublicKeyCredential) {
    return show(el("h1", {}, "Guardian"), errorBox("This browser can't use passkeys. Please open Guardian in Safari, Chrome or Edge."));
  }
  const err = el("div");
  const signIn = el("button", { class: "secondary", onclick: () => busy(signIn, async () => {
    try { await passkeyGet("/api/login/begin", "/api/login/finish"); start(); }
    catch (e) { err.replaceChildren(errorBox(e.name === "NotAllowedError" ? "Sign-in was cancelled." : e.message)); }
  }) }, "I already use Guardian");
  show(
    el("h1", {}, "Your money, accounts and identity, watched over."),
    el("p", {}, "Guardian spots scam calls, fake emails and card misuse, acts before they cost you, and tells you in plain words."),
    el("p", { class: "muted" }, "Set it up once, in about five minutes."),
    el("button", { onclick: createAccount }, "Get started"), signIn, err);
}

function createAccount() {
  const name = el("input", { type: "text", id: "name", autocomplete: "given-name", maxlength: "60" });
  const err = el("div");
  const go = el("button", { type: "submit" }, "Create my account with Face ID or fingerprint");
  const form = el("form", { onsubmit: (e) => { e.preventDefault(); busy(go, async () => {
    try { await register(name.value); setupWizard(); }
    catch (ex) { err.replaceChildren(errorBox(ex.name === "NotAllowedError" ? "That was cancelled. Try again when you're ready." : ex.message)); }
  }); } },
    el("label", { for: "name" }, "What should we call you?"), name, go, err);
  show(el("h1", {}, "Create your account"),
    el("p", {}, "Guardian uses a passkey instead of a password: your face or fingerprint on this device. Nothing to remember, nothing for a scammer to steal."),
    form, el("button", { class: "secondary", onclick: welcome }, "Back"));
  name.focus();
}

function choice(name, value, title, text, checked) {
  const input = el("input", { type: "radio", name, value, checked });
  const box = el("label", { class: "choice" + (checked ? " on" : "") }, input, el("span", {}, el("b", {}, title), text ? el("span", { class: "muted" }, text) : null));
  input.addEventListener("change", () => document.querySelectorAll(`input[name=${name}]`).forEach((i) =>
    i.closest(".choice").classList.toggle("on", i.checked)));
  return box;
}
const picked = (name) => document.querySelector(`input[name=${name}]:checked`)?.value;

function setupWizard() {
  const s = { who: "me", protected_name: "", family_name: "", family_phone: "", mode: "tell", senior: false };
  const total = 5;
  const step = (n, title, ...body) => show(el("p", { class: "progress" }, `Step ${n} of ${total}`), el("h1", {}, title), ...body);

  const one = () => {
    const theirName = el("input", { type: "text", id: "pname", maxlength: "60", value: s.protected_name });
    const extra = el("div", {}, el("label", { for: "pname" }, "Their first name"), theirName,
      el("p", { class: "muted small" }, "They need to be with you now, to agree to Guardian watching over them."));
    extra.hidden = s.who !== "family";
    const err = el("div");
    step(1, "Who is Guardian for?",
      choice("who", "me", "Me", null, s.who === "me"),
      choice("who", "family", "Someone in my family", "For example a parent you help look after.", s.who === "family"),
      extra, err,
      el("button", { onclick: () => {
        s.who = picked("who"); s.protected_name = theirName.value.trim();
        if (s.who === "family" && !s.protected_name) return err.replaceChildren(errorBox("Please enter their first name."));
        two();
      } }, "Continue"));
    document.querySelectorAll("input[name=who]").forEach((i) => i.addEventListener("change", () => (extra.hidden = picked("who") !== "family")));
  };

  const two = () => step(2, "Connect email",
    el("div", { class: "card" }, el("b", {}, "Gmail, read-only"),
      el("p", { class: "muted" }, "Guardian will read new emails to spot scams. It will never send, delete or change your email without asking."),
      el("p", { class: "muted small" }, "You can connect Gmail from your home screen after setup. Until then, Guardian shows sample data so you can see how it works."),
      el("a", { href: "/privacy" }, "What Guardian reads and keeps")),
    el("button", { onclick: three }, "Continue with sample data for now"),
    el("button", { class: "secondary", onclick: one }, "Back"));

  const three = () => {
    const name = el("input", { type: "text", id: "fname", maxlength: "60", value: s.family_name });
    const phone = el("input", { type: "tel", id: "fphone", autocomplete: "tel", value: s.family_phone });
    step(3, "Who should we tell if a scammer targets you?",
      el("p", { class: "muted" }, "Optional. We'll text them to ask if they agree. Nothing reaches them until they say YES."),
      el("label", { for: "fname" }, "Their name"), name,
      el("label", { for: "fphone" }, "Their mobile number"), phone,
      el("button", { onclick: () => { s.family_name = name.value.trim(); s.family_phone = phone.value.trim(); four(); } }, "Continue"),
      el("button", { class: "secondary", onclick: () => { s.family_name = s.family_phone = ""; four(); } }, "Skip for now"));
  };

  const four = () => {
    const senior = el("input", { type: "checkbox", id: "senior", checked: s.senior });
    const err = el("div");
    const go = el("button", {}, "Continue");
    go.addEventListener("click", () => busy(go, async () => {
      s.mode = picked("mode"); s.senior = senior.checked;
      try { await call("/api/setup", s); five(); } catch (e) { err.replaceChildren(errorBox(e.message)); }
    }));
    step(4, "How should Guardian help?",
      choice("mode", "tell", "Just tell me", "Guardian alerts you and asks first. A good way to start.", s.mode === "tell"),
      choice("mode", "act", "Act for me, then tell me", "Guardian blocks scam numbers, moves fake emails aside and locks a misused card. Disputes always wait for you.", s.mode === "act"),
      el("label", { class: "check" }, senior, el("span", {}, el("b", {}, "Extra protection from phone scams"), el("span", { class: "muted" }, "Recommended for anyone 65 or over."))),
      err, go);
  };

  const five = () => {
    const out = el("div");
    const send = el("button", {}, "Send me a test alert");
    send.addEventListener("click", () => busy(send, async () => {
      if ("Notification" in window && Notification.permission === "default") await Notification.requestPermission();
      const a = await call("/api/test-alert", {});
      notify(a.title, a.body);
      out.replaceChildren(el("div", { class: "card" }, el("span", { class: "tag done" }, "Test alert"), el("h3", {}, a.title), el("p", {}, a.body)));
    }));
    step(5, "See it work",
      el("p", {}, "Here's what an alert looks like. Allow notifications when asked, so alerts reach you."),
      send, out, el("button", { class: "secondary", onclick: home }, "Go to my Guardian"));
  };
  one();
}

function statusBox(f) {
  if (f.last_error) return el("div", { class: "status bad" }, "Guardian hit a problem on its last check.", el("span", {}, "Tap Check now. If it keeps happening, it will tell you."));
  if (f.paused) return el("div", { class: "status warn" }, "Guardian's actions are paused.", el("span", {}, "You'll still get alerts. Last check: " + ago(f.last_run) + "."));
  if (!f.checking) return el("div", { class: "status warn" }, "Background checks aren't running.", el("span", {}, "Tap Check now. Last check: " + ago(f.last_run) + "."));
  return el("div", { class: "status ok" }, "You're protected.", el("span", {}, "Last check: " + ago(f.last_run) + "."));
}

function itemCard(it) {
  const tag = it.marked_real ? el("span", { class: "tag done" }, "You said this was real")
    : el("span", { class: "tag " + (it.severity === "high" ? "high" : "medium") }, it.severity === "high" ? "Scam or attack" : "Heads up");
  const card = el("div", { class: "card item" }, tag, el("h3", {}, it.summary));
  if (it.did.length && !it.marked_real) card.append(el("p", { class: "did" }, "Guardian: " + it.did.join(" · ")));
  if (!it.marked_real && (it.would || []).length) card.append(el("p", { class: "muted" },
    (feedCache && feedCache.shadow ? "Shadow mode. Guardian would have: " : "Paused. Guardian would have: ") + it.would.join(" · ")));
  if (!it.marked_real) it.waiting.forEach((w) => card.append(el("p", { class: "muted" }, "Waiting: " + w)));
  if (!it.did.length && !it.waiting.length && !(it.would || []).length && !it.marked_real) card.append(el("p", { class: "muted" }, "Nothing done by itself. Just letting you know."));
  if (it.steps) card.append(el("details", {}, el("summary", {}, "What to do"), el("pre", { class: "steps" }, it.steps)));
  if (!it.marked_real) {
    const real = el("button", { class: "secondary" }, "This was real, not a scam");
    real.addEventListener("click", () => busy(real, async () => {
      const r = await call("/api/real", { threat: it.threat });
      feedCache = r.feed; render();
      notify("Thanks, noted", r.undone.length ? "Guardian undid: " + r.undone.join(", ") : "Guardian won't act on it.");
    }));
    card.append(real);
  }
  return card;
}

let notice = null;
{
  const q = new URLSearchParams(location.search);
  if (q.get("gmail") === "connected") notice = { ok: true, text: "Gmail connected, in shadow mode." };
  if (q.get("gmail_error")) notice = { ok: false, text: q.get("gmail_error") };
  if (notice) history.replaceState(null, "", "/");
}

function render() {
  const f = feedCache, err = el("div");
  const banner = notice ? (notice.ok ? el("div", { class: "status ok" }, notice.text) : errorBox(notice.text)) : null;
  const act = (button, fn) => button.addEventListener("click", () => busy(button, async () => {
    try { feedCache = await fn(); render(); } catch (e) { err.replaceChildren(errorBox(e.name === "NotAllowedError" ? "That was cancelled." : e.message)); }
  }));
  const checkNow = el("button", { class: "secondary" }, "Check now");
  act(checkNow, () => call("/api/check-now", {}));

  const needs = f.needs_you.map((n) => {
    const yes = el("button", {}, "Yes, do it");
    act(yes, () => call("/api/approve", { key: n.key }));
    return el("div", { class: "card" }, el("span", { class: "tag medium" }, "Needs you"), el("h3", {}, n.ask),
      el("p", { class: "muted small" }, "You'll confirm with Face ID or fingerprint."), yes);
  });
  const open = f.items.filter((i) => !i.marked_real), done = f.items.filter((i) => i.marked_real);

  const family = f.family ? el("div", { class: "card" }, el("b", {}, f.family.name),
    el("p", { class: "muted" }, f.family.status === "agreed" ? "Agreed to be told about serious scams." : "Waiting for them to reply YES."),
    f.family.status !== "agreed" ? (() => { const b = el("button", { class: "secondary" }, "Simulate their YES (no SMS account yet)");
      act(b, async () => { await call("/api/family/yes", {}); return call("/api/check-now", {}); }); return b; })() : null) : null;

  const tell = el("button", { class: f.mode === "tell" ? "" : "secondary", "aria-pressed": String(f.mode === "tell") }, "Just tell me");
  const doIt = el("button", { class: f.mode === "act" ? "" : "secondary", "aria-pressed": String(f.mode === "act") }, "Act for me");
  act(tell, () => call("/api/mode", { mode: "tell" }));
  act(doIt, () => call("/api/mode", { mode: "act" }));
  const pause = el("button", { class: "secondary" }, f.paused ? "Resume Guardian's actions" : "Pause Guardian's actions");
  act(pause, () => call("/api/pause", { paused: !f.paused }));
  const signOut = el("button", { class: "secondary" }, "Sign out");
  signOut.addEventListener("click", async () => { await call("/api/logout", {}); clearInterval(pollTimer); welcome(); });
  const del = el("button", { class: "danger" }, "Delete my data");
  let armed = false;
  del.addEventListener("click", () => {
    if (!armed) { armed = true; del.textContent = "Tap again to delete everything. This can't be undone."; return; }
    busy(del, async () => { try { await call("/api/delete", {}); clearInterval(pollTimer); welcome(); }
      catch (e) { err.replaceChildren(errorBox(e.message)); } });
  });

  let source = null;
  if (f.data_source === "gmail" && f.gmail) {
    const accounts = el("input", { type: "text", id: "accounts", value: (f.accounts || []).join(", "),
      placeholder: "e.g. mybank.com, amazon.com" });
    const save = el("button", { class: "secondary" }, "Save my accounts");
    act(save, () => call("/api/accounts", { accounts: accounts.value.split(/[\s,]+/).filter(Boolean) }));
    const off = el("button", { class: "secondary" }, "Disconnect Gmail");
    act(off, () => call("/api/gmail/disconnect", {}));
    source = el("div", { class: "card" }, el("span", { class: "tag done" }, "Shadow mode"),
      el("h3", {}, "Watching " + (f.gmail.email || "your Gmail")),
      el("p", { class: "muted" }, "Guardian reads new mail and tells you what it would do. It acts on nothing until you're ready. Last sync: " + ago(f.gmail.last_sync) + "."),
      f.gmail.last_error ? errorBox("Last sync failed: " + f.gmail.last_error) : null,
      el("label", { for: "accounts" }, "Your bank and main accounts (website addresses)"),
      el("p", { class: "muted small" }, "Emails pretending to be these get flagged."), accounts, save, off);
  } else if (f.gmail_available) {
    source = el("div", { class: "card" }, el("h3", {}, "Connect your Gmail"),
      el("p", { class: "muted" }, "Read-only: Guardian can't send, delete or move your mail. It starts in shadow mode, saying what it would do without doing it."),
      el("a", { class: "button", href: "/oauth/google/start" }, "Connect Gmail (read-only)"));
  }
  const v = f.verified || {};
  const verify = v.fresh ? null : el("div", { class: "card" }, el("span", { class: "tag medium" }, "Quick check"),
    el("h3", {}, v.result === "passed" ? "Your check that it's really you has expired" : "Let Guardian lock a card for you"),
    el("p", { class: "muted" }, "Before Guardian may lock a card, Persona checks that a real person is behind it. Guardian only learns passed or failed, never your ID or face. It lasts 24 hours."),
    el("a", { class: "button", href: "/verify" }, "Verify with Persona"));
  show(
    el("h1", {}, "Hello, " + f.name),
    statusBox(f), err,
    banner,
    f.data_source === "sample" ? el("p", { class: "notice" }, "Showing sample data until you connect Gmail.") : null,
    f.data_source === "none" ? el("p", { class: "notice" }, "Guardian isn't watching any email right now.") : null,
    checkNow,
    needs.length ? el("h2", {}, "Needs you") : null, ...needs, verify,
    el("h2", {}, open.length ? "What Guardian found" : "Nothing new"),
    ...open.map(itemCard),
    done.length ? el("details", {}, el("summary", {}, `You marked ${done.length} as real`), ...done.map(itemCard)) : null,
    el("hr"),
    source ? el("h2", {}, "Your email") : null, source,
    el("h2", {}, "How Guardian helps"), el("div", { class: "row" }, tell, doIt),
    family ? el("h2", {}, "Who we tell") : null, family,
    el("h2", {}, "Settings"), pause, el("a", { class: "button secondary", href: "/privacy" }, "What Guardian reads and keeps"), signOut, del);
}

async function home() {
  try { feedCache = await call("/api/feed"); } catch (e) { return welcome(); }
  seenThreats = new Set(feedCache.items.map((i) => i.threat));
  render();
  clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    try {
      const f = await call("/api/feed");
      const fresh = f.items.filter((i) => !seenThreats.has(i.threat) && !i.marked_real);
      fresh.forEach((i) => { seenThreats.add(i.threat); notify(i.severity === "high" ? "Guardian: scam stopped" : "Guardian: heads up", i.summary); });
      if (JSON.stringify(f) !== JSON.stringify(feedCache)) { feedCache = f; if (!document.activeElement || document.activeElement === document.body) render(); }
    } catch (e) { /* offline: try again next time */ }
  }, 30000);
}

start();
