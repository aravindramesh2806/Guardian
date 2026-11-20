"use strict";
// Guardian app: one-time setup, then the home screen.
// Every piece of text from the server or a message goes in through textContent (el()), never innerHTML.
// Icons are the only markup set directly, and they come from the constant PATHS table below.

const app = document.getElementById("app");
let me = null, feedCache = null, pollTimer = null, seenThreats = null, notice = null, intent = null;

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
const PATHS = {
  back: '<path d="M15 18l-6-6 6-6"/>',
  shield: '<path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6l8-3z"/><path d="M8.5 12l2.5 2.5 4.5-5"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  eye: '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
  people: '<path d="M17 20v-2a4 4 0 0 0-4-4H7a4 4 0 0 0-4 4v2"/><circle cx="10" cy="7" r="4"/><path d="M21 20v-2a4 4 0 0 0-3-3.9M16 3.1a4 4 0 0 1 0 7.8"/>',
  person: '<circle cx="12" cy="8" r="4"/><path d="M4 21v-1a6 6 0 0 1 6-6h4a6 6 0 0 1 6 6v1"/>',
  lock: '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
  phone: '<rect x="7" y="2" width="10" height="20" rx="2"/><path d="M11 18h2"/>',
  face: '<path d="M7 3H5a2 2 0 0 0-2 2v2M17 3h2a2 2 0 0 1 2 2v2M7 21H5a2 2 0 0 1-2-2v-2M17 21h2a2 2 0 0 0 2-2v-2M9 9v1M15 9v1M12 9v4h-1M9 16c1.5 1 4.5 1 6 0"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 8h.01M11 12h1v4h1"/>',
  check: '<path d="M20 6L9 17l-5-5"/>',
  x: '<path d="M18 6L6 18M6 6l12 12"/>',
  mail: '<rect x="3" y="5" width="18" height="14" rx="2"/><path d="M3 7l9 6 9-6"/>',
  bell: '<path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.9 1.9 0 0 0 3.4 0"/>',
  alert: '<path d="M12 3l9.5 17h-19z"/><path d="M12 10v4M12 17h.01"/>',
};
function icon(name, size) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("class", "i" + (size ? " s" + size : ""));
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("aria-hidden", "true");
  svg.innerHTML = PATHS[name];   // constant markup only
  return svg;
}
function show(...nodes) {
  app.replaceChildren(el("section", { class: "screen" }, ...nodes));
  const h = app.querySelector("h1");
  if (h) { h.setAttribute("tabindex", "-1"); h.focus({ preventScroll: true }); }
  window.scrollTo(0, 0);
}
function errorBox(msg) { return el("p", { class: "error", role: "alert" }, msg); }
function errorSlot() { return el("div", { "aria-live": "polite" }); }
function ago(iso) {
  if (!iso) return "not yet";
  const mins = Math.round((Date.now() - new Date(iso).getTime()) / 60000);
  return mins < 1 ? "just now" : mins === 1 ? "1 minute ago" : mins < 60 ? mins + " minutes ago"
    : Math.round(mins / 60) === 1 ? "1 hour ago" : Math.round(mins / 60) + " hours ago";
}
function when(iso) {
  const d = new Date(iso);
  return isNaN(d) ? "" : d.toLocaleString(undefined, { weekday: "short", hour: "numeric", minute: "2-digit" });
}
function problem(e) {
  if (e && e.name === "NotAllowedError") return "That was cancelled or timed out. Try again when you're ready.";
  if (e && e.name === "InvalidStateError") return "This phone already has a Guardian passkey. Use “I already have an account”.";
  return (e && e.message) || "Something went wrong. Please try again.";
}
async function busy(button, fn) {
  button.disabled = true;
  try { return await fn(); } finally { button.disabled = false; }
}
// A button that runs fn and shows any error in `slot`.
function action(button, slot, fn) {
  button.addEventListener("click", () => busy(button, async () => {
    slot.replaceChildren();
    try { await fn(); } catch (e) { slot.replaceChildren(errorBox(problem(e))); }
  }));
  return button;
}

// The setup answers live in sessionStorage, so the Persona page (a separate page) can come back to them.
const SETUP_KEY = "guardian-setup";
function setupState() {
  try { return JSON.parse(sessionStorage.getItem(SETUP_KEY) || "{}"); } catch (e) { return {}; }
}
function saveSetup(s) { try { sessionStorage.setItem(SETUP_KEY, JSON.stringify(s)); } catch (e) { /* private mode */ } }
function clearSetup() { try { sessionStorage.removeItem(SETUP_KEY); } catch (e) { /* private mode */ } }

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
  if (res.status === 403 && data.verify_email) { verifyEmail(me && me.email); throw new Error(data.error); }
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
// How this person confirms risky changes, in words.
const confirmWith = () => (me && me.demo ? "your demo PIN" : "Face ID or fingerprint");

// Risky changes need a fresh "it's you": Face ID, or the PIN on the demo account (it has no passkey).
const stepUp = () => (me && me.demo ? askPin() : passkeyGet("/api/stepup/begin", "/api/stepup/finish"));

// A small sheet over the current screen that asks for the demo PIN. Resolves once the server accepts it.
function askPin() {
  return new Promise((resolve, reject) => {
    const pin = el("input", { type: "password", id: "stepup-pin", inputmode: "numeric", autocomplete: "off", maxlength: "8" });
    const err = errorSlot();
    const close = () => sheet.remove();
    const ok = action(el("button", { class: "btn" }, "Confirm"), err, async () => {
      const res = await fetch("/api/stepup/pin", { method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ pin: pin.value }) });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) { pin.value = ""; setTimeout(() => pin.focus(), 0); throw new Error(data.error || "That PIN isn't right."); }
      close(); resolve();
    });
    pin.addEventListener("keydown", (e) => { if (e.key === "Enter") ok.click(); });
    const cancel = el("button", { class: "link", onclick: () => { close(); reject(new Error("Cancelled. Nothing was changed.")); } }, "Cancel");
    const sheet = el("div", { class: "sheet", role: "dialog", "aria-modal": "true", "aria-labelledby": "pin-title" },
      el("div", { class: "sheet-body stack g10" },
        el("h2", { id: "pin-title", class: "sheet-title" }, "Confirm it's you"),
        el("p", { class: "muted" }, "Enter your demo PIN to make this change."),
        el("label", { for: "stepup-pin" }, "PIN"), pin, err, ok, cancel));
    document.body.append(sheet);
    pin.focus();
  });
}

// Demo sign-in (username and PIN). Only offered when the server has it switched on, on localhost.
function pinSignIn() {
  const user = el("input", { type: "text", id: "demo-user", autocomplete: "username", autocapitalize: "none", maxlength: "40" });
  const pin = el("input", { type: "password", id: "demo-pin", inputmode: "numeric", autocomplete: "current-password", maxlength: "8" });
  const err = errorSlot();
  const go = action(el("button", { class: "btn" }, "Sign in"), err, async () => {
    if (!user.value.trim() || !pin.value.trim()) throw new Error("Type the username and the PIN.");
    try { await call("/api/demo/login", { username: user.value.trim(), pin: pin.value.trim() }); }
    catch (e) { pin.value = ""; setTimeout(() => pin.focus(), 0); throw e; }
    clearSetup();
    start();
  });
  pin.addEventListener("keydown", (e) => { if (e.key === "Enter") go.click(); });
  show(
    topBar(null, welcome),
    el("h1", {}, "Sign in"),
    el("p", { class: "lead" }, "Use the demo username and PIN."),
    el("div", { class: "stack mt" },
      el("div", { class: "field" }, el("label", { for: "demo-user" }, "Username"), user),
      el("div", { class: "field" }, el("label", { for: "demo-pin" }, "PIN"), pin)),
    el("div", { class: "mt-s" }, note("warn", "info", "Demo only. Real Guardian accounts sign in with Face ID or fingerprint, never a PIN.")),
    el("div", { class: "foot" }, err, go));
  user.focus();
}

async function register(name, email) {
  const { flow, options } = await call("/api/register/begin", { name, email });
  options.challenge = unb64u(options.challenge);
  options.user.id = unb64u(options.user.id);
  (options.excludeCredentials || []).forEach((c) => (c.id = unb64u(c.id)));
  const cred = await navigator.credentials.create({ publicKey: options });
  return call("/api/register/finish", { flow, credential: credentialJSON(cred) });
}

// ---------- notifications ----------
async function notify(title, body) {
  if (!("Notification" in window) || Notification.permission !== "granted") return false;
  const reg = await navigator.serviceWorker?.getRegistration();
  if (reg) await reg.showNotification(title, { body, icon: "/icon-192.png", badge: "/icon-192.png" });
  else new Notification(title, { body });
  return true;
}

// ---------- shared pieces ----------
const STEPS = 6;
function topBar(step, back) {
  const kids = [];
  if (back) kids.push(el("button", { class: "back", "aria-label": "Back", onclick: back }, icon("back", 24)));
  if (step) {
    const bar = el("div", { class: "bar", "aria-hidden": "true" });
    for (let i = 1; i <= STEPS; i++) bar.append(el("span", { class: i <= step ? "on" : "" }));
    kids.push(bar, el("span", { class: "muted small" }, `Step ${step} of ${STEPS}`));
  }
  return el("div", { class: "top" }, ...kids);
}
function note(kind, iconName, ...text) {
  return el("div", { class: "note" + (kind ? " " + kind : "") }, icon(iconName), el("p", {}, ...text));
}
function radio(selected, value, title, text, tag, onpick) {
  return el("button", { class: "opt", role: "radio", "aria-checked": String(selected === value), onclick: () => onpick(value) },
    el("span", { class: "dot" }),
    el("span", {}, el("b", {}, title, tag ? el("span", { class: "tag" }, tag) : null), el("span", { class: "d" }, text)));
}
function switchRow(id, title, text, on, onflip) {
  return el("div", { class: "card switch-row" },
    el("span", { class: "grow" }, el("b", { id }, title), el("span", { class: "muted small" }, text)),
    el("button", { class: "switch", role: "switch", "aria-checked": String(on), "aria-labelledby": id, onclick: onflip }));
}

// ---------- start ----------
async function start() {
  if ("serviceWorker" in navigator) navigator.serviceWorker.register("/sw.js").catch(() => {});
  try { me = await call("/api/me"); } catch (e) { return show(errorBox(e.message)); }
  if (!me.signed_in) return welcome();
  if (!me.email_verified) return verifyEmail(me.email);
  const s = setupState();
  if (!me.setup_done) return SETUP[s.step && s.step !== "sample" ? s.step : "verify"]();
  if (s.step === "sample" && !intent) return SETUP.sample();  // an alert's button goes straight to its screen
  return home();
}

// ---------- before the account exists ----------
function welcome() {
  const err = errorSlot();
  const signIn = action(el("button", { class: "link" }, "I already have an account"), err, async () => {
    try { await passkeyGet("/api/login/begin", "/api/login/finish"); }
    catch (e) { throw new Error(e.name === "NotAllowedError" ? "Sign-in was cancelled." : problem(e)); }
    clearSetup();
    start();
  });
  const point = (name, strong, rest) => el("li", {}, el("span", { class: "chip" }, icon(name, 20)), el("span", {}, el("b", {}, strong), " " + rest));
  show(
    el("div", { class: "top" }, el("span", { class: "brand" }, el("span", { class: "mark" }, icon("shield")), "Guardian")),
    el("h1", { class: "big" }, "A quiet guard for your email, accounts, money and identity."),
    el("p", { class: "lead" }, "Guardian watches for scams, speaks up only when it matters, and always shows you why."),
    el("ul", { class: "points" },
      point("clock", "Set it up once.", "About 5 minutes, then nothing to tune."),
      point("eye", "It starts by watching.", "It acts for you only when you say so."),
      point("people", "Someone you trust can be told", "if a scammer targets you, only if they agree.")),
    el("div", { class: "foot" }, err,
      window.PublicKeyCredential ? el("button", { class: "btn", onclick: who }, "Get started")
        : errorBox("This browser can't use passkeys. Please open Guardian in Safari, Chrome or Edge."),
      window.PublicKeyCredential ? signIn : null,
      me && me.demo_login ? el("button", { class: "link", onclick: pinSignIn }, "Demo sign-in (username and PIN)") : null,
      el("a", { class: "link center", href: "/privacy" }, "What Guardian reads and keeps")));
}

function who() {
  const pick = (value) => { saveSetup({ who: value }); value === "family" ? handoff() : createAccount(); };
  const opt = (value, iconName, title, text) => el("button", { class: "opt", onclick: () => pick(value) },
    el("span", { class: "chip lg" }, icon(iconName, 26)), el("span", {}, el("b", {}, title), el("span", { class: "d" }, text)));
  show(
    topBar(1, welcome),
    el("h1", {}, "Who is Guardian for?"),
    el("p", { class: "lead" }, "You can add more people later."),
    el("div", { class: "stack mt" },
      opt("me", "person", "Me", "Protect my own email and accounts."),
      opt("family", "people", "Someone I look out for", "A parent, partner, teenager or friend. They need to be with you to agree.")),
    el("div", { class: "foot" }, note("", "lock", "Guardian never watches someone without their own yes. That's why they set up their own account.")));
}

function handoff() {
  show(
    topBar(1, who),
    el("div", { class: "chip xl mt" }, icon("phone", 44)),
    el("h1", {}, "Now hand the phone to the person you're protecting"),
    el("p", { class: "lead" }, "They'll make the account with their own Face ID and say yes to each step. You can stay and help them read."),
    el("div", { class: "card stack g8 mt" }, el("span", { class: "label" }, "For you, the helper"),
      el("p", {}, "Want to hear about it if a scammer targets them? They can add you as their trusted person in step 4.")),
    el("div", { class: "foot" },
      el("button", { class: "btn", onclick: createAccount }, "I'm the person being protected"),
      el("p", { class: "muted small center" }, "The next screens speak to them, not to you.")));
}

function createAccount() {
  const s = setupState();
  const name = el("input", { type: "text", id: "name", autocomplete: "given-name", maxlength: "60", value: s.name || "" });
  name.addEventListener("input", () => saveSetup(Object.assign(setupState(), { name: name.value })));
  const email = el("input", { type: "email", id: "email", autocomplete: "email", inputmode: "email", maxlength: "254", value: s.email || "" });
  email.addEventListener("input", () => saveSetup(Object.assign(setupState(), { email: email.value })));
  const err = errorSlot();
  const go = action(el("button", { class: "btn" }, icon("face", 24), "Continue with Face ID"), err, async () => {
    if (!name.value.trim()) throw new Error("Type the name Guardian should use for you.");
    if (!email.value.trim()) throw new Error("Type your email, so we can send you a code.");
    await register(name.value.trim(), email.value.trim());
    me = await call("/api/me");
    saveSetup(Object.assign(setupState(), { name: name.value.trim(), email: email.value.trim(), step: "verify" }));
    verifyEmail(email.value.trim());
  });
  show(
    topBar(2, s.who === "family" ? handoff : who),
    el("h1", {}, "Create your account"),
    el("p", { class: "lead" }, "No password to remember. You'll sign in with Face ID, the same way you unlock your phone."),
    el("div", { class: "field mt" }, el("label", { for: "name" }, "What should we call you?"), name,
      el("span", { class: "muted small" }, "Guardian uses this in alerts, so you know they're real.")),
    el("div", { class: "field mt-s" }, el("label", { for: "email" }, "Your email"), email,
      el("span", { class: "muted small" }, "We'll send a 6-digit code to check it's yours.")),
    el("div", { class: "mt" }, note("", "info", el("b", {}, "Why no password? "),
      "Passwords can be stolen by the same scams Guardian stops. Face ID can't be typed into a fake website.")),
    el("div", { class: "foot" }, err, go,
      el("p", { class: "muted small center" }, "Your phone may offer fingerprint or its PIN instead. Both are fine.")));
}

// The emailed 6-digit code. Nothing else works until it's entered (the server enforces this too).
function verifyEmail(address) {
  const code = el("input", { type: "text", id: "code", inputmode: "numeric", autocomplete: "one-time-code", maxlength: "6", pattern: "[0-9]*" });
  const err = errorSlot(), info = el("div", { "aria-live": "polite" });
  const go = action(el("button", { class: "btn" }, "Confirm"), err, async () => {
    if (!/^\d{6}$/.test(code.value.trim())) throw new Error("Type the 6 digits from the email.");
    await call("/api/email/verify", { code: code.value.trim() });
    me = await call("/api/me");
    SETUP.verify();
  });
  code.addEventListener("keydown", (e) => { if (e.key === "Enter") go.click(); });
  const resend = action(el("button", { class: "link" }, "Send me a new code"), err, async () => {
    await call("/api/email/resend", {});
    info.replaceChildren(note("soft", "mail", "A new code is on its way."));
  });
  const other = action(el("button", { class: "link" }, "Use a different email"), err, async () => {
    await call("/api/logout", {}); me = null; createAccount();
  });
  show(
    topBar(2),
    el("h1", {}, "Check your email"),
    el("p", { class: "lead" }, "We sent a 6-digit code to ", el("b", {}, address || "your email"), ". Enter it to finish signing up."),
    el("div", { class: "field mt" }, el("label", { for: "code" }, "6-digit code"), code),
    el("p", { class: "muted small mt-s" }, "Can't find it? Check your spam folder. Accounts that aren't confirmed are deleted after 24 hours."),
    info,
    el("div", { class: "foot" }, err, go, resend, other));
  code.focus();
}

// Alerts while Guardian is closed (Web Push). Returns true when this device is subscribed.
async function turnOnAlerts() {
  if (!("serviceWorker" in navigator) || !("PushManager" in window)) {
    throw new Error(/iPhone|iPad/.test(navigator.userAgent)
      ? "On iPhone, first add Guardian to your Home Screen (Share, then Add to Home Screen), then open it from there and try again."
      : "This browser can't receive alerts while Guardian is closed.");
  }
  if (await Notification.requestPermission() !== "granted") throw new Error("Alerts are blocked. You can allow them in your browser or phone settings.");
  const reg = await navigator.serviceWorker.ready;
  const { key } = await call("/api/push/key");
  const sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: unb64u(key) });
  await call("/api/push/subscribe", { subscription: sub.toJSON() });
  return true;
}

function alertsCard() {
  const out = el("div", { "aria-live": "polite" });
  const btn = action(el("button", { class: "btn2" }, icon("bell"), "Turn on alerts on this device"), out, async () => {
    await turnOnAlerts();
    out.replaceChildren(note("soft", "check", "Alerts are on for this device. We just sent a test."));
  });
  return el("div", { class: "card stack g10" },
    el("p", { class: "muted" }, "Get a heads-up even when Guardian is closed. Alerts say how many new things there are, never what your messages say."),
    out, btn);
}

// ---------- setup, after the account exists ----------
const SETUP = {
  verify() {
    const s = setupState(); s.step = "verify"; saveSetup(s);
    const v = me.verified || {};
    const status = v.fresh
      ? el("div", { class: "card done" }, el("div", { class: "big-check" }, icon("check", 36)),
          el("p", { class: "done-title", role: "status" }, "You're verified"),
          el("p", { class: "muted small" }, "Checked " + when(v.checked_at) + ". It counts for 24 hours."))
      : el("div", { class: "card stack g10" }, el("span", { class: "label" }, v.result === "passed" ? "Your last check has expired" : "Not checked yet"),
          el("p", {}, "It opens on the next page and brings you back here when it's done."),
          el("a", { class: "button secondary", href: "/verify" }, "Start the check"));
    show(
      topBar(2),
      el("h1", {}, "A quick check that you're really here"),
      el("p", { class: "lead" }, "About 30 seconds, done by Persona. Guardian only learns ", el("b", {}, "passed"), " or ",
        el("b", {}, "failed"), ". It never sees your ID or your face."),
      el("div", { class: "mt" }, status),
      el("p", { class: "muted small mt-s" }, "Before Guardian may lock a card, text the person you trust, or let you turn protection down, it needs this check from the last 24 hours. A scammer with your phone can\u2019t do those alone."),
      el("div", { class: "foot" },
        el("button", { class: "btn", onclick: SETUP.email }, v.fresh ? "Continue" : "Do this later")));
  },

  email() {
    const s = setupState(); s.step = "email"; saveSetup(s);
    show(
      topBar(3, SETUP.verify),
      el("h1", {}, "Your email"),
      el("p", { class: "lead" }, "Most scams arrive by email. Here's exactly what Guardian can and can't do."),
      el("div", { class: "card stack g12 mt" },
        el("span", { class: "label tint" }, "Guardian will"),
        el("div", { class: "yes" }, icon("check", 20), el("span", {}, "Read new emails to spot scams")),
        el("div", { class: "yes" }, icon("check", 20), el("span", {}, "Keep only its verdict, and delete the email text after 30 days")),
        el("div", { class: "rule" }),
        el("span", { class: "label tint-bad" }, "Guardian will never"),
        el("div", { class: "no" }, icon("x", 20), el("span", {}, "Send, delete or move your email")),
        el("div", { class: "no" }, icon("x", 20), el("span", {}, "Let a person at Guardian read your mail"))),
      el("div", { class: "mt-s" }, me.gmail_available
        ? note("soft", "mail", "You'll connect Gmail (read-only) from your home screen in a minute. It starts by only watching.")
        : note("warn", "info", "Gmail sign-in isn't switched on for this Guardian yet. Until it is, Guardian shows made-up sample emails so you can see how it works.")),
      el("a", { class: "link mt-s", href: "/privacy" }, "What Guardian reads and keeps"),
      el("div", { class: "foot" }, el("button", { class: "btn", onclick: SETUP.trusted }, "Continue")));
  },

  trusted() {
    const s = setupState(); s.step = "trusted"; saveSetup(s);
    const first = (me.name || "").split(" ")[0];
    const name = el("input", { type: "text", id: "fname", maxlength: "60", autocomplete: "off", value: s.family_name || "" });
    const phone = el("input", { type: "tel", id: "fphone", maxlength: "22", autocomplete: "off", value: s.family_phone || "" });
    const them = el("span", {}, (s.family_name || "").trim() || "them");
    name.addEventListener("input", () => { them.textContent = name.value.trim() || "them"; });
    const err = errorSlot();
    const next = () => {
      const fam = name.value.trim(), tel = phone.value.trim();
      if (!fam && !tel) return err.replaceChildren(errorBox("Add their name and mobile number, or skip this for now."));
      if (!fam || !tel) return err.replaceChildren(errorBox("Add both their name and their mobile number."));
      if (!/^\+?\d{7,15}$/.test(tel.replace(/[^\d+]/g, ""))) return err.replaceChildren(errorBox("Please enter a phone number with 7 to 15 digits."));
      saveSetup(Object.assign(setupState(), { family_name: fam, family_phone: tel }));
      SETUP.mode();
    };
    const skip = () => { saveSetup(Object.assign(setupState(), { family_name: "", family_phone: "" })); SETUP.mode(); };
    show(
      topBar(4, SETUP.email),
      el("h1", {}, "Add someone you trust"),
      el("p", { class: "lead" }, "If a scammer targets you, who should we tell? Optional."),
      el("div", { class: "stack mt" },
        el("div", { class: "field" }, el("label", { for: "fname" }, "Their name"), name),
        el("div", { class: "field" }, el("label", { for: "fphone" }, "Their mobile number"), phone)),
      el("div", { class: "stack g8 mt" }, el("span", { class: "label" }, "The text we send"),
        el("div", { class: "bubble" }, `${first} added you to Guardian. If a scammer targets ${first}, we'll text you. Reply YES to agree.`)),
      el("div", { class: "mt-s" }, note("", "lock", "You'll send it from your home screen with Face ID and the Persona check. Nothing else goes to ", them, " until they reply YES, and they never see your emails.")),
      el("div", { class: "foot" }, err,
        el("button", { class: "btn", onclick: next }, "Continue"),
        el("button", { class: "link", onclick: skip }, "Skip for now")));
  },

  mode() {
    const s = setupState(); s.step = "mode";
    if (!s.mode) s.mode = "tell";
    if (s.senior === undefined) s.senior = false;
    saveSetup(s);
    const err = errorSlot();
    const go = action(el("button", { class: "btn" }, "Continue"), err, async () => {
      const cur = setupState();
      await call("/api/setup", { who: cur.who || "me", protected_name: cur.who === "family" ? me.name : null,
        family_name: cur.family_name || "", family_phone: cur.family_phone || "", mode: cur.mode, senior: cur.senior });
      saveSetup(Object.assign(cur, { step: "sample" }));
      me = await call("/api/me");
      SETUP.sample();
    });
    const pick = (value) => { saveSetup(Object.assign(setupState(), { mode: value })); SETUP.mode(); };
    show(
      topBar(5, SETUP.trusted),
      el("h1", {}, "How should Guardian help?"),
      el("p", { class: "lead" }, "You can change this later. Alerts always reach you either way."),
      el("div", { class: "stack g12 mt", role: "radiogroup", "aria-label": "How Guardian helps" },
        radio(s.mode, "tell", "Just tell me", "Guardian warns you and shows the steps. You decide everything.", "Best to start", pick),
        radio(s.mode, "act", "Act for me, then tell me", "Guardian blocks scam numbers, moves fake emails aside and locks a misused card. Disputes always wait for you.", null, pick)),
      s.mode === "act" ? el("p", { class: "muted small mt-s" }, "You'll confirm this with Face ID. With real Gmail, Guardian only watches at first and tells you what it would have done.") : null,
      el("div", { class: "mt-s" }, switchRow("senior-label", "Extra care for calls and texts",
        "Speaks up sooner about gift cards, codes and “it's me” calls. Turn it on if you get a lot of scam calls or want a closer watch.", s.senior,
        () => { saveSetup(Object.assign(setupState(), { senior: !setupState().senior })); SETUP.mode(); })),
      el("div", { class: "foot" }, err, go));
  },

  sample() {
    const s = setupState(); s.step = "sample"; saveSetup(s);
    const canNotify = "Notification" in window && "serviceWorker" in navigator;
    const finish = () => { clearSetup(); home(); };
    const foot = el("div", { class: "foot" });
    const err = errorSlot();
    const missing = () => foot.replaceChildren(
      note("warn", "bell", "Check that notifications are allowed for Guardian in your phone's Settings. On iPhone, add Guardian to your Home Screen first (Share, then Add to Home Screen) and open it from there."),
      sendButton("Try again"),
      el("button", { class: "link", onclick: finish }, "Continue without alerts for now"));
    const sendButton = (label) => action(el("button", { class: "btn" }, icon("bell"), label), err, async () => {
      if (!canNotify) return missing();
      // Best: turn on real alerts for this device; the server sends a test push. Otherwise a local practice alert.
      let pushed = false;
      try { pushed = await turnOnAlerts(); } catch (e) { pushed = false; }
      if (!pushed) {
        if (Notification.permission === "default") await Notification.requestPermission();
        const a = await call("/api/test-alert", {});
        if (!(await notify(a.title, a.body))) return missing();
      }
      foot.replaceChildren(err, el("p", { class: "ask" }, "Did it show up on your lock screen or in your notifications?"),
        el("button", { class: "btn", onclick: finish }, "Yes, I got it"),
        el("button", { class: "link", onclick: missing }, "No, it didn't arrive"));
    });
    foot.append(...[err,
      canNotify ? null : note("warn", "bell", "This browser can't show alerts yet. On iPhone, add Guardian to your Home Screen (Share, then Add to Home Screen) and open it from there."),
      sendButton("Send me a practice alert"),
      canNotify ? null : el("button", { class: "link", onclick: finish }, "Continue without alerts for now")].filter(Boolean));
    show(
      topBar(6),
      el("h1", {}, "Here's what an alert looks like"),
      el("p", { class: "lead" }, "Every alert says what happened, what Guardian did, and the one thing to do. This one is practice. Nothing is wrong."),
      el("div", { class: "card mt" },
        el("div", { class: "alert-head" }, el("span", { class: "mark sm" }, icon("shield", 16)), el("b", {}, "Guardian"),
          el("span", { class: "muted" }, "now"), el("span", { class: "tag" }, "Practice")),
        el("p", { class: "alert-title" }, "Heads up: someone tried to reset your bank password."),
        el("div", { class: "facts" },
          el("div", {}, el("span", { class: "label" }, "What happened"), el("p", {}, "A reset email arrived, and you didn't ask for one.")),
          el("div", {}, el("span", { class: "label" }, "What Guardian did"), el("p", {}, "Nothing yet. It's waiting for you.")),
          el("div", {}, el("span", { class: "label tint" }, "Your one step"), el("p", {}, "Don't click the email. Open your bank's app and change your password.")))),
      foot);
  },
};

// ---------- home ----------
function hero(f) {
  const box = (kind, iconName, title, text) => el("div", { class: "hero" + (kind ? " " + kind : "") }, icon(iconName, 40), el("h1", {}, title), el("p", {}, text));
  if (f.last_error) return box("bad", "alert", "Guardian hit a problem", "Its last check didn't finish. Tap Check now. If it keeps happening, it will tell you.");
  if (f.paused) return box("warn", "clock", "Guardian's actions are paused", "You'll still get alerts. Last check: " + ago(f.last_run) + ".");
  if (!f.checking) return box("warn", "clock", "Background checks aren't running", "Tap Check now. Last check: " + ago(f.last_run) + ".");
  // Never say "protected" while Guardian is only looking at sample data.
  if (f.data_source !== "gmail") return box("warn", "mail", "Almost ready",
    f.data_source === "sample" ? "Guardian is showing made-up sample data. Connect Gmail below so it can watch your real email."
                               : "Guardian isn't watching any email right now. Connect Gmail below.");
  return box("", "shield", "You're protected", (f.shadow ? "Watch-only: Guardian says what it would do and acts on nothing yet. " : "")
    + "Last check: " + ago(f.last_run) + ".");
}

function itemCard(it, err) {
  const tag = it.marked_real ? el("span", { class: "tag" }, "You said this was real")
    : el("span", { class: "tag " + (it.severity === "high" ? "high" : "medium") }, it.severity === "high" ? "Scam or attack" : "Heads up");
  const card = el("div", { class: "card item", "data-threat": it.threat }, tag, el("h3", { class: "mt-s" }, it.summary));
  if (it.did.length && !it.marked_real) card.append(el("p", { class: "did" }, "Guardian: " + it.did.join(" · ")));
  if (!it.marked_real && (it.would || []).length) card.append(el("p", { class: "muted" },
    (feedCache && feedCache.shadow ? "Watch-only. Guardian would have: " : "Paused. Guardian would have: ") + it.would.join(" · ")));
  if (!it.marked_real) it.waiting.forEach((w) => card.append(el("p", { class: "muted" }, "Waiting: " + w)));
  if (!it.did.length && !it.waiting.length && !(it.would || []).length && !it.marked_real) card.append(el("p", { class: "muted" }, "Nothing done by itself. Just letting you know."));
  if (it.steps) card.append(el("details", {}, el("summary", {}, "What to do"), el("pre", { class: "steps" }, it.steps)));
  if (!it.marked_real && it.confirmed_scam) {
    card.append(el("p", { class: "did" }, "You confirmed it's a scam."),
      el("button", { class: "btn mt-s", onclick: () => solve(it.threat) }, "See how to deal with it"));
  } else if (!it.marked_real) {
    card.append(el("div", { class: "stack g10 mt-s" },
      action(el("button", { class: "btn" }, "Yes, it's a scam"), err, async () => {
        feedCache = await call("/api/scam", { threat: it.threat });
        solve(it.threat);
      }),
      action(el("button", { class: "btn2" }, "This was real, not a scam"), err, async () => {
        const r = await call("/api/real", { threat: it.threat });
        feedCache = r.feed; render();
        notify("Thanks, noted", r.undone.length ? "Guardian undid: " + r.undone.join(", ") : "Guardian won't act on it.");
      })));
  }
  return card;
}

// Why a fix hasn't happened yet, in the person's words.
function fixReason(x) {
  const r = x.reason || "";
  if (r.startsWith("kill switch")) return feedCache && feedCache.shadow
    ? "Guardian is only watching for now, so it won't do this yet." : "Guardian is paused, so it won't do this now.";
  if (x.needs_persona) return "Needs the quick Persona check first.";
  if (r.startsWith("you approved it")) return "You said yes. " + r.replace(/^you approved it, but /, "Still waiting: ") + ".";
  if (/is off$|wait for your confirmation/.test(r)) return "Waiting for your yes.";
  if (/no lock option/.test(r)) return "Your card issuer doesn't let Guardian lock it. Call the number on the back of the card.";
  return r ? r.charAt(0).toUpperCase() + r.slice(1) + "." : "";
}

// "Yes, it's a scam": what Guardian can do now (each with its own yes), and the person's own steps.
let solving = null;
function solve(threat) {
  const it = (feedCache.items || []).find((i) => i.threat === threat);
  if (!it) { solving = null; return render(); }
  solving = threat;
  const err = errorSlot();
  const back = () => { solving = null; render(); };
  const fixes = it.fixes.map((x) => {
    const row = el("div", { class: "card stack g10" }, el("h3", {}, x.label));
    if (x.done) row.append(el("p", { class: "did" }, "Done."));
    else if (x.can) row.append(el("p", { class: "muted small" }, "You'll confirm with " + confirmWith() + "."),
      action(el("button", { class: "btn" }, icon("face", 24), "Yes, do it"), err, async () => {
        feedCache = await call("/api/approve", { key: x.key });
        solve(threat);
      }));
    else {
      row.append(el("p", { class: "muted" }, fixReason(x)));
      if (x.needs_persona) row.append(el("a", { class: "button secondary", href: "/verify" }, "Do the Persona check"));
    }
    return row;
  });
  const how = it.how && it.how.length ? it.how : null;
  const fam = feedCache.family;
  show(
    topBar(null, back),
    el("h1", {}, "Let's deal with it"),
    el("p", { class: "lead" }, it.summary),
    it.did.length ? el("div", { class: "mt-s" }, note("soft", "check", "Already done: " + it.did.join(" · ") + ".")) : null,
    el("h2", {}, "What Guardian can do now"),
    fixes.length ? el("div", { class: "cards" }, ...fixes)
      : el("div", { class: "card" }, el("p", {}, "There's nothing here for Guardian to block or lock. Your steps below are what matters.")),
    err,
    el("h2", {}, "What you should do"),
    how ? el("ol", { class: "steps-list" }, ...how.map((s) => el("li", {}, s)))
      : it.steps ? el("div", { class: "card" }, el("pre", { class: "steps" }, it.steps))
      : el("div", { class: "card" }, el("p", {}, "Nothing more for you to do. Don't reply to it or click anything in it.")),
    fam && fam.status === "agreed" && it.severity === "high"
      ? el("div", { class: "mt-s" }, note("soft", "people", fam.name + " agreed to be told about serious scams like this one.")) : null,
    el("div", { class: "foot" }, el("button", { class: "btn2", onclick: back }, "Back to my Guardian")));
}

function render() {
  solving = null;
  const f = feedCache, err = errorSlot();
  const act = (button, fn) => action(button, err, async () => { feedCache = await fn(); render(); });
  const banner = notice ? (notice.ok ? note("soft", "check", notice.text) : errorBox(notice.text)) : null;
  notice = null;

  const needs = f.needs_you.map((n) => el("div", { class: "card" },
    el("h3", {}, n.ask), el("p", { class: "muted small" }, "You'll confirm with " + confirmWith() + "."),
    act(el("button", { class: "btn mt-s" }, "Yes, do it"), () => call("/api/approve", { key: n.key }))));

  const v = f.verified || {};
  const verify = v.fresh ? null : el("div", { class: "card" }, el("span", { class: "tag medium" }, "Quick check"),
    el("h3", { class: "mt-s" }, v.result === "passed" ? "Your check that it's really you has expired" : "Quick check that it's really you"),
    el("p", { class: "muted" }, "Before Guardian may lock a card or text the person you trust, Persona checks that a real person is behind it. Guardian only learns passed or failed, never your ID or face. It lasts 24 hours."),
    el("a", { class: "button secondary mt-s", href: "/verify" }, "Verify with Persona"));

  const open = f.items.filter((i) => !i.marked_real), done = f.items.filter((i) => i.marked_real);

  // Status rows: email, trusted person, mode.
  const rows = [];
  if (f.data_source === "gmail" && f.gmail) {
    rows.push(el("div", { class: "row" }, el("span", { class: f.gmail.last_error ? "wait" : "ok" }, icon(f.gmail.last_error ? "alert" : "check")),
      el("span", { class: "grow" }, f.gmail.email || "Your Gmail", el("br"), el("span", { class: "muted small" },
        f.gmail.last_error ? "Last sync failed: " + f.gmail.last_error : "Read-only. Last sync: " + ago(f.gmail.last_sync)))));
  } else {
    rows.push(el("div", { class: "row" }, el("span", { class: "wait" }, icon("clock")),
      el("span", { class: "grow" }, f.data_source === "sample" ? "Sample data, not your email" : "No email connected")));
  }
  if (f.family) {
    const agreed = f.family.status === "agreed";
    const said = { agreed: " agreed to be told about serious scams", waiting: " invited, waiting for YES" }[f.family.status] || " not invited yet";
    rows.push(el("div", { class: "row" }, el("span", { class: agreed ? "ok" : "wait" }, icon(agreed ? "check" : "clock")),
      el("span", { class: "grow" }, f.family.name + said)));
  }
  rows.push(el("div", { class: "row" }, el("span", { class: "ok" }, icon("check")),
    el("span", { class: "grow" }, f.mode === "act" ? "Acts for you, then tells you" : "Tells you, you decide")));

  let source = null;
  if (f.data_source === "gmail" && f.gmail) {
    const accounts = el("input", { type: "text", id: "accounts", value: (f.accounts || []).join(", "), placeholder: "e.g. mybank.com, amazon.com" });
    source = el("div", { class: "card stack g10" },
      el("h3", {}, "Watching " + (f.gmail.email || "your Gmail")),
      el("p", { class: "muted" }, "Guardian reads new mail and tells you what it would do. It acts on nothing until you're ready."),
      el("label", { for: "accounts" }, "Your bank and main accounts (website addresses)"),
      el("p", { class: "muted small" }, "Emails pretending to be these get flagged."), accounts,
      act(el("button", { class: "btn2" }, "Save my accounts"), () => call("/api/accounts", { accounts: accounts.value.split(/[\s,]+/).filter(Boolean) })),
      act(el("button", { class: "btn2" }, "Disconnect Gmail"), () => call("/api/gmail/disconnect", {})));
  } else if (f.gmail_available) {
    source = el("div", { class: "card stack g10" }, el("h3", {}, "Connect your Gmail"),
      el("p", { class: "muted" }, "Read-only: Guardian can't send, delete or move your mail. It starts by only watching, saying what it would do without doing it."),
      el("a", { class: "button", href: "/oauth/google/start" }, icon("mail"), "Connect Gmail (read-only)"));
  } else if (f.data_source !== "gmail") {
    source = note("warn", "info", "Gmail sign-in isn't switched on for this Guardian yet, so it shows sample data.");
  }

  // Trusted person: saved at setup, invited from here (fresh Face ID + Persona), then they reply YES.
  let family = null;
  if (f.family && f.family.status === "not invited") {
    family = el("div", { class: "card stack g10" },
      el("h3", {}, "Invite " + f.family.name),
      el("p", { class: "muted" }, "They get one text asking if they agree. Nothing else reaches them until they reply YES."),
      v.fresh ? act(el("button", { class: "btn" }, icon("face", 24), "Confirm with " + (me && me.demo ? "your PIN" : "Face ID") + " and send"), () => call("/api/family/invite", {}))
        : el("p", { class: "muted small" }, "First, do the Persona check above. It stops someone with your phone from pointing your alerts at their own number."));
  } else if (f.family && f.family.status === "waiting") {
    family = el("div", { class: "card stack g10" },
      el("p", {}, "No SMS account is set up yet, so the invite to " + f.family.name + " was written to the outbox, not really sent."),
      act(el("button", { class: "btn2" }, "Simulate their YES"), async () => { await call("/api/family/yes", {}); return call("/api/check-now", {}); }));
  } else if (f.family && f.family.status === "agreed") {
    family = el("div", { class: "card" }, el("b", {}, f.family.name),
      el("p", { class: "muted" }, "Agreed to be told about serious scams."));
  }

  const modeBtn = (value, label) => act(el("button", { class: "btn2" + (f.mode === value ? " on" : ""), "aria-pressed": String(f.mode === value) }, label),
    () => call("/api/mode", { mode: value }));

  const del = el("button", { class: "btn2 danger" }, "Delete my data");
  let armed = false;
  action(del, err, async () => {
    if (!armed) { armed = true; del.textContent = "Tap again to delete everything. This can't be undone."; return; }
    await call("/api/delete", {}); clearInterval(pollTimer); welcome();
  });
  const signOut = action(el("button", { class: "link" }, "Sign out"), err, async () => {
    await call("/api/logout", {}); clearInterval(pollTimer); me = await call("/api/me"); welcome();
  });

  show(
    el("div", { class: "top spread" }, el("span", { class: "brand" }, "Guardian"),
      el("span", { class: "who" }, el("span", { class: "muted small" }, "Hi, " + f.name),
        action(el("button", { class: "link small" }, "Sign out"), err, async () => {
          await call("/api/logout", {}); clearInterval(pollTimer); me = await call("/api/me"); welcome();
        }))),
    hero(f), banner ? el("div", { class: "mt-s" }, banner) : null, err,
    el("div", { class: "card rows mt-s" }, ...rows),
    act(el("button", { class: "btn2 mt-s" }, "Check now"), () => call("/api/check-now", {})),
    needs.length ? el("h2", {}, "Needs you") : null, needs.length ? el("div", { class: "cards" }, ...needs) : null,
    verify ? el("div", { class: "mt-s" }, verify) : null,
    el("h2", {}, open.length ? "What Guardian found" : "Recent"),
    open.length ? el("div", { class: "cards" }, ...open.map((it) => itemCard(it, err)))
      : el("div", { class: "card" }, el("p", {}, "Nothing yet. When Guardian spots something, it shows up here with what it did and why.")),
    done.length ? el("details", {}, el("summary", {}, `You marked ${done.length} as real`), el("div", { class: "cards" }, ...done.map((it) => itemCard(it, err)))) : null,
    source ? el("h2", {}, "Your email") : null, source,
    el("h2", {}, "How Guardian helps"), el("div", { class: "row-btns" }, modeBtn("tell", "Just tell me"), modeBtn("act", "Act for me")),
    family ? el("h2", {}, "Who we tell") : null, family,
    el("h2", {}, "Alerts"), alertsCard(),
    el("h2", {}, "Settings"),
    el("div", { class: "stack g10" },
      act(el("button", { class: "btn2" }, f.paused ? "Resume Guardian's actions" : "Pause Guardian's actions"), () => call("/api/pause", { paused: !f.paused })),
      el("a", { class: "button secondary", href: "/privacy" }, "What Guardian reads and keeps"),
      del, signOut));
}

async function home() {
  try { feedCache = await call("/api/feed"); } catch (e) { return welcome(); }
  seenThreats = new Set(feedCache.items.map((i) => i.threat));
  if (!openFromAlert()) render();
  clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    try {
      const f = await call("/api/feed");
      const fresh = f.items.filter((i) => !seenThreats.has(i.threat) && !i.marked_real);
      fresh.forEach((i) => { seenThreats.add(i.threat); notify(i.severity === "high" ? "Guardian: scam stopped" : "Guardian: heads up", i.summary); });
      if (JSON.stringify(f) !== JSON.stringify(feedCache)) {
        feedCache = f;
        if (!document.activeElement || document.activeElement === document.body) solving ? solve(solving) : render();
      }
    } catch (e) { /* offline: try again next time */ }
  }, 30000);
}

{
  const q = new URLSearchParams(location.search);
  if (q.get("gmail") === "connected") notice = { ok: true, text: "Gmail connected. Guardian starts by only watching." };
  if (q.get("gmail_error")) notice = { ok: false, text: q.get("gmail_error") };
  // From an alert's buttons: act (block, move aside, lock), undo ("It was real") or read (see details).
  for (const kind of ["act", "undo", "read"]) if (q.get(kind)) intent = { kind, threat: q.get(kind) };
  if (notice || intent) history.replaceState(null, "", "/");
}

// Open the screen an alert button asked for. Returns true when it showed one.
function openFromAlert() {
  if (!intent) return false;
  const { kind, threat } = intent;
  intent = null;
  const it = feedCache.items.find((i) => i.threat === threat);
  if (!it) { notice = { ok: true, text: "That one is no longer on your list. It may already be handled." }; return false; }
  if (kind === "act" && !it.marked_real) {
    // Tapping "Block number" (or move aside, lock) on the alert means they think it's a scam.
    call("/api/scam", { threat }).then((f) => { feedCache = f; solve(threat); }).catch(() => solve(threat));
    return true;
  }
  if (kind === "undo" && !it.marked_real) { wasItReal(it); return true; }
  if (kind === "read") {
    render();
    const card = app.querySelector('[data-threat="' + CSS.escape(threat) + '"]');
    if (card) {
      card.classList.add("focus");
      const d = card.querySelector("details");
      if (d) d.open = true;
      card.scrollIntoView({ block: "center" });
    }
    return true;
  }
  return false;
}

function wasItReal(it) {
  const err = errorSlot();
  const back = () => render();
  show(
    topBar(null, back),
    el("h1", {}, "Was this real?"),
    el("p", { class: "lead" }, it.summary),
    it.did.length ? el("div", { class: "mt-s" }, note("", "info", "Guardian: " + it.did.join(" · ") + ".")) : null,
    el("p", { class: "muted mt-s" }, "If it was real, Guardian undoes what it did and won't act on it again."),
    el("div", { class: "foot" }, err,
      action(el("button", { class: "btn" }, "Yes, it was real"), err, async () => {
        const r = await call("/api/real", { threat: it.threat });
        feedCache = r.feed;
        notice = { ok: true, text: r.undone.length ? "Guardian undid: " + r.undone.join(", ") + "." : "Noted. Guardian won't act on it." };
        render();
      }),
      action(el("button", { class: "btn2" }, "No, it was a scam"), err, async () => {
        feedCache = await call("/api/scam", { threat: it.threat });
        solve(it.threat);
      })));
}

start();
