// Builds presentation/Guardian.pptx. Run from the repo root:
//   (cd presentation && npm install pptxgenjs react-icons react react-dom sharp jszip) && node presentation/build_deck.js
// The .pptx is the file to edit for each client; this script is only needed to rebuild it from scratch.
const path = require("path");
const pptxgen = require("pptxgenjs");
const React = require("react");
const ReactDOMServer = require("react-dom/server");
const sharp = require("sharp");
const fa = require("react-icons/fa");

const OUT = path.join(__dirname, "Guardian.pptx");
const APPLY_THEME = process.env.APPLY_THEME_JS; // path to the pptx skill's apply_theme.js

const THEME = {
  name: "Guardian",
  headFontFace: "Cambria",
  bodyFontFace: "Calibri",
  colors: {
    dk1: "0F1E2E", lt1: "FFFFFF", dk2: "0B1F1A", lt2: "F2F5F4",
    accent1: "0B6E4F", accent2: "3FB98A", accent3: "E0A100", accent4: "B83232",
    accent5: "E3F1EB", accent6: "5A6875", hlink: "0B6E4F", folHlink: "08523B",
  },
};
const HEX = THEME.colors;

const pres = new pptxgen();
pres.layout = "LAYOUT_WIDE"; // 13.333 x 7.5 in
pres.title = "Guardian: a personal security agent";
pres.author = "Guardian team";
pres.theme = { headFontFace: THEME.headFontFace, bodyFontFace: THEME.bodyFontFace };
const C = pres.SchemeColor;

// ---------- icons ----------
async function icon(name, hex = "FFFFFF", px = 256) {
  const svg = ReactDOMServer.renderToStaticMarkup(React.createElement(fa[name], { color: "#" + hex, size: px }));
  const buf = await sharp(Buffer.from(svg)).resize(px, px).png().toBuffer();
  return "image/png;base64," + buf.toString("base64");
}
// The deck's motif: a white icon in a rounded green tile, like the app's brand mark.
async function tile(slide, name, x, y, s, fill = C.accent1, iconHex = "FFFFFF", id = name) {
  slide.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y, w: s, h: s, rectRadius: s * 0.28, fill: { color: fill }, line: { type: "none" }, objectName: "tile-" + id });
  slide.addImage({ data: await icon(name, iconHex), x: x + s * 0.24, y: y + s * 0.24, w: s * 0.52, h: s * 0.52, objectName: "icon-" + id, altText: id });
}
const shadow = () => ({ type: "outer", color: "0F1E2E", blur: 8, offset: 2, angle: 90, opacity: 0.12 });
function card(slide, x, y, w, h, id, fill = C.background1) {
  slide.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y, w, h, rectRadius: 0.12, fill: { color: fill }, line: { color: "D9E0E4", width: 0.75 }, shadow: shadow(), objectName: "card-" + id });
}
const T = (slide, text, opts) => slide.addText(text, { isTextBox: true, margin: 0, valign: "top", ...opts });

// ---------- layouts ----------
const footer = (color) => [
  { text: { text: "Guardian", options: { x: 0.6, y: 7.02, w: 3, h: 0.3, fontSize: 10, color, bold: true, margin: 0 } } },
];
pres.defineSlideMaster({
  title: "TITLE_DARK",
  background: { color: C.text2 },
  objects: [
    { placeholder: { options: { name: "title", type: "title", x: 0.8, y: 2.35, w: 11.4, h: 1.9, fontSize: 48, bold: true, color: C.background1, fontFace: THEME.headFontFace, valign: "bottom", align: "left", margin: 0 }, text: "" } },
    { placeholder: { options: { name: "subtitle", type: "body", x: 0.8, y: 4.45, w: 10.2, h: 1.2, fontSize: 20, color: C.accent5, valign: "top", margin: 0 }, text: "" } },
    { placeholder: { options: { name: "meta", type: "body", x: 0.8, y: 6.5, w: 11.4, h: 0.4, fontSize: 14, color: C.accent2, valign: "top", margin: 0 }, text: "" } },
  ],
});
for (const [nm, bg, ink, foot] of [["CONTENT_LIGHT", C.background1, C.text1, C.accent6], ["CONTENT_DARK", C.text2, C.background1, C.accent2]]) {
  pres.defineSlideMaster({
    title: nm,
    background: { color: bg },
    margin: [0.5, 0.6, 0.6, 0.6],
    objects: [
      ...footer(foot),
      { placeholder: { options: { name: "title", type: "title", x: 0.6, y: 0.42, w: 12.1, h: 0.85, fontSize: 34, bold: true, color: ink, fontFace: THEME.headFontFace, valign: "middle", align: "left", margin: 0 }, text: "" } },
    ],
    slideNumber: { x: 12.23, y: 7.02, w: 0.5, h: 0.3, fontSize: 10, color: foot, align: "right" },
  });
}

(async () => {
  // ================= 1. Title =================
  pres.addSection({ title: "Opening" });
  let s = pres.addSlide({ masterName: "TITLE_DARK", sectionTitle: "Opening" });
  await tile(s, "FaShieldAlt", 0.8, 0.8, 0.8, C.accent1, "FFFFFF", "brand");
  T(s, "GUARDIAN", { x: 1.8, y: 0.98, w: 4, h: 0.45, fontSize: 18, bold: true, color: C.background1, charSpacing: 4, objectName: "brand-name" });
  s.addText("Scams move fast. Guardian moves first.", { placeholder: "title" });
  s.addText("A personal security agent for anyone with a digital identity. It watches calls, texts, email and cards, acts before a threat costs money, tells someone you trust, and shows its work.", { placeholder: "subtitle" });
  s.addText("Personal Agents Hackathon  ·  tokens&  ·  November 20, 2026", { placeholder: "meta" });
  s.addNotes("Open with the line on the slide. Guardian is a personal agent for safety, built for anyone whose identity is online, at any age: it watches over their digital life every day, acts on threats before they cost money, tells someone they trust when something serious happens, and shows the evidence behind every step. For a client version, replace the event line at the bottom with the client's name and date.");

  // ================= 2. Problem =================
  pres.addSection({ title: "The problem" });
  s = pres.addSlide({ masterName: "CONTENT_LIGHT", sectionTitle: "The problem" });
  s.addText("Americans reported $20.9B lost to online crime", { placeholder: "title" });
  card(s, 0.6, 1.6, 5.5, 4.9, "stats", C.background2);
  T(s, "$20.9B", { x: 1.0, y: 1.95, w: 4.8, h: 1.2, fontSize: 72, bold: true, color: C.accent1, fontFace: THEME.headFontFace, objectName: "stat-loss" });
  T(s, "reported lost to internet crime in 2025, across every age group", { x: 1.0, y: 3.15, w: 4.7, h: 0.7, fontSize: 16, color: C.text1 });
  T(s, "+26%", { x: 1.0, y: 4.1, w: 4.8, h: 1.0, fontSize: 60, bold: true, color: C.accent4, fontFace: THEME.headFontFace, objectName: "stat-growth" });
  T(s, "more than the year before", { x: 1.0, y: 5.1, w: 4.7, h: 0.4, fontSize: 16, color: C.text1 });
  T(s, "Source: FBI IC3 2025 Internet Crime Report (1M+ complaints)", { x: 1.0, y: 5.85, w: 4.8, h: 0.3, fontSize: 10, color: C.accent6, italic: true });

  T(s, "Scams arrive on every channel", { x: 6.7, y: 1.6, w: 6, h: 0.45, fontSize: 20, bold: true, color: C.text1, fontFace: THEME.headFontFace });
  const chans = [
    ["FaPhoneAlt", "Calls and voicemail", "Spoofed bank caller ID, “move it to a safe account”, “it’s me, I’m in trouble”"],
    ["FaCommentDots", "Texts", "Parcel “pay to redeliver” links, codes, fake refunds"],
    ["FaEnvelope", "Email", "Lookalike senders, password resets you didn’t start, data leaks"],
  ];
  for (let i = 0; i < chans.length; i++) {
    const y = 2.3 + i * 1.12;
    await tile(s, chans[i][0], 6.7, y, 0.72, C.accent1, "FFFFFF", "chan" + i);
    T(s, chans[i][1], { x: 7.65, y: y - 0.02, w: 5.1, h: 0.36, fontSize: 16, bold: true, color: C.text1 });
    T(s, chans[i][2], { x: 7.65, y: y + 0.34, w: 5.1, h: 0.6, fontSize: 14, color: C.accent6 });
  }
  card(s, 6.7, 5.75, 6.0, 0.75, "gap", C.accent5);
  T(s, "Anyone with an inbox, a phone and a card is a target. Today’s personal agents help people shop and schedule. None of them stand guard.", { x: 6.95, y: 5.85, w: 5.6, h: 0.6, fontSize: 15, bold: true, color: C.accent1, valign: "middle" });
  s.addNotes("Americans reported about $20.9 billion lost to internet crime in 2025, 26% more than the year before, across more than a million complaints, according to the FBI's IC3 report. This isn't one age group's problem: anyone whose email, phone number and card are out on the internet is a target. People aged 60 and over reported the most, about $7.7 billion of it, but students, professionals and parents get the same calls and phishing emails. The scams come by phone, text and email, and the agents people use today help them shop and schedule, not protect them.");

  // ================= 3. Rose + setup =================
  s = pres.addSlide({ masterName: "CONTENT_LIGHT", sectionTitle: "The problem" });
  s.addText("Set it up once. Protected every day", { placeholder: "title" });
  card(s, 0.6, 1.6, 3.9, 4.9, "persona", C.text2);
  await tile(s, "FaUserShield", 0.95, 1.95, 0.85, C.accent1, "FFFFFF", "rose");
  T(s, "Meet Rose, 78", { x: 0.95, y: 3.0, w: 3.3, h: 0.5, fontSize: 24, bold: true, color: C.background1, fontFace: THEME.headFontFace });
  T(s, "One of many people Guardian protects, from students to retirees. Rose set Guardian up once, and it has watched over her ever since.", { x: 0.95, y: 3.6, w: 3.25, h: 1.4, fontSize: 15, color: C.accent5 });
  T(s, "Sam is her trusted contact. She is told about serious scams, only because she agreed.", { x: 0.95, y: 5.1, w: 3.25, h: 1.1, fontSize: 14, color: C.accent2, italic: true });

  T(s, "Five-step setup", { x: 5.0, y: 1.6, w: 7.7, h: 0.45, fontSize: 20, bold: true, color: C.text1, fontFace: THEME.headFontFace });
  const steps = [
    ["FaUsers", "Who it’s for", "Anyone with a digital identity: me, or someone I look out for"],
    ["FaFingerprint", "Sign in with a passkey", "Face ID or Touch ID. No passwords"],
    ["FaInbox", "Connect email", "Read-only. Never sends or deletes"],
    ["FaUserCheck", "Add someone you trust", "They reply YES before anything is sent"],
    ["FaSlidersH", "Choose how it helps", "“Just tell me” or “Act for me”, then a test alert"],
  ];
  for (let i = 0; i < steps.length; i++) {
    const y = 2.2 + i * 0.84;
    s.addShape(pres.shapes.OVAL, { x: 5.0, y: y + 0.06, w: 0.52, h: 0.52, fill: { color: C.accent1 }, line: { type: "none" }, objectName: "step-dot" + i });
    T(s, String(i + 1), { x: 5.0, y: y + 0.06, w: 0.52, h: 0.52, fontSize: 16, bold: true, color: C.background1, align: "center", valign: "middle" });
    T(s, steps[i][1], { x: 5.75, y: y, w: 3.3, h: 0.36, fontSize: 16, bold: true, color: C.text1 });
    T(s, steps[i][2], { x: 5.75, y: y + 0.34, w: 6.9, h: 0.36, fontSize: 14, color: C.accent6 });
  }
  T(s, "Under 5 minutes  ·  sensible defaults  ·  nothing to tune afterwards", { x: 5.0, y: 6.45, w: 7.7, h: 0.36, fontSize: 14, bold: true, color: C.accent1 });
  s.addNotes("Guardian is for anyone with an online identity; our two test people are Rose, 78, and Jordan, 34, a busy professional. Today we follow Rose. Her daughter Sam is her trusted contact. Setup takes five steps and under five minutes: who it's for, a passkey instead of a password, connect email read-only, add a trusted person who must reply YES, and choose 'Just tell me' or 'Act for me'. A test alert proves notifications work before anything real happens.");

  // ================= 4. One morning =================
  pres.addSection({ title: "Guardian in action" });
  s = pres.addSlide({ masterName: "CONTENT_LIGHT", sectionTitle: "Guardian in action" });
  s.addText("One morning, eight threats handled", { placeholder: "title" });
  const stats = [["8", "new threats found", C.text1], ["5", "stopped automatically", C.accent1], ["1", "waits for Rose", C.accent3], ["3", "alerts to Sam, her trusted contact", C.accent4]];
  for (let i = 0; i < 4; i++) {
    const x = 0.6 + i * 3.075;
    T(s, stats[i][0], { x, y: 1.45, w: 0.9, h: 0.95, fontSize: 54, bold: true, color: stats[i][2], fontFace: THEME.headFontFace, valign: "middle" });
    T(s, stats[i][1], { x: x + 0.9, y: 1.62, w: 1.95, h: 0.62, fontSize: 15, color: C.text1, valign: "middle" });
  }
  const threats = [
    ["FaPhoneAlt", "Fake “Example Bank” voicemail", "Wrong number, a “safe account”, a code", "Blocked · Rose warned · Sam told"],
    ["FaPhoneAlt", "“Grandma, it’s me”", "Bail money, gift cards, “don’t tell mom”", "Blocked · Sam told"],
    ["FaCommentDots", "Parcel text with a pay link", "Pay-by-link from an unknown sender", "Blocked"],
    ["FaCreditCard", "$389 charge she never made", "No receipt, a merchant she never uses", "Card locked · dispute waits for Rose"],
    ["FaEnvelope", "“PayLinc” refund email", "Lookalike sender, link to another domain", "Quarantined"],
    ["FaKey", "Reset, leak and store breach", "A reset she didn’t start, two data leaks", "Exact steps for each"],
  ];
  for (let i = 0; i < threats.length; i++) {
    const col = i % 3, row = Math.floor(i / 3);
    const x = 0.6 + col * 4.1, y = 2.65 + row * 2.05, w = 3.85, h = 1.8;
    card(s, x, y, w, h, "threat" + i);
    await tile(s, threats[i][0], x + 0.25, y + 0.25, 0.55, C.accent5, HEX.accent1, "threat" + i);
    T(s, threats[i][1], { x: x + 0.95, y: y + 0.22, w: w - 1.15, h: 0.62, fontSize: 15, bold: true, color: C.text1, valign: "middle" });
    T(s, threats[i][2], { x: x + 0.25, y: y + 0.92, w: w - 0.45, h: 0.36, fontSize: 13, color: C.accent6 });
    T(s, threats[i][3], { x: x + 0.25, y: y + 1.3, w: w - 0.45, h: 0.36, fontSize: 14, bold: true, color: C.accent1 });
  }
  s.addNotes("The daily brief reads: 8 new threats, 5 stopped for you, 1 needs you, someone you trust was told about 3. A spoofed bank voicemail is blocked, Rose is warned and Sam is told. The 'Grandma, it's me' bail call is blocked. A parcel text with a payment link is blocked. A $389 charge she never made locks the card, and the dispute waits for Rose's yes. A lookalike PayLinc refund email is quarantined. A password reset she didn't ask for, a forum leak and a breach at a store she used each get exact steps.");

  // ================= 5. Live call =================
  s = pres.addSlide({ masterName: "CONTENT_DARK", sectionTitle: "Guardian in action" });
  s.addText("When the scammer calls, it warns live", { placeholder: "title" });
  // phone "island" mockup
  s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: 0.6, y: 1.55, w: 12.1, h: 0.95, rectRadius: 0.47, fill: { color: "000000" }, line: { color: HEX.accent4, width: 2 }, objectName: "island" });
  s.addShape(pres.shapes.OVAL, { x: 0.9, y: 1.77, w: 0.5, h: 0.5, fill: { color: C.accent4 }, line: { type: "none" }, objectName: "island-dot" });
  T(s, "Hang up. They are asking for money or gift cards.", { x: 1.6, y: 1.55, w: 10.8, h: 0.95, fontSize: 22, bold: true, color: C.background1, valign: "middle", objectName: "island-text" });
  // timeline
  const tx = (t) => 0.9 + (t / 30) * 11.5;
  s.addShape(pres.shapes.LINE, { x: tx(0), y: 4.2, w: tx(30) - tx(0), h: 0, line: { color: HEX.accent6, width: 2 }, objectName: "timeline" });
  // risk band: listening -> yellow -> red
  s.addShape(pres.shapes.RECTANGLE, { x: tx(0), y: 4.08, w: tx(2) - tx(0), h: 0.24, fill: { color: C.accent2 }, line: { type: "none" }, objectName: "band-green" });
  s.addShape(pres.shapes.RECTANGLE, { x: tx(2), y: 4.08, w: tx(17) - tx(2), h: 0.24, fill: { color: C.accent3 }, line: { type: "none" }, objectName: "band-amber" });
  s.addShape(pres.shapes.RECTANGLE, { x: tx(17), y: 4.08, w: tx(30) - tx(17), h: 0.24, fill: { color: C.accent4 }, line: { type: "none" }, objectName: "band-red" });
  const turns = [[2, "“Grandma, it’s me.”", "Unknown caller claims family", C.accent3], [9, "“I’m in trouble, I need help right now.”", "Urgency", C.accent3], [17, "“I need bail money today. Please don’t tell mom.”", "Money + secrecy: warning fires", C.accent4], [26, "“Go buy gift cards and read me the numbers.”", "Rose already warned", C.accent4]];
  for (let i = 0; i < turns.length; i++) {
    const [t, q, why, col] = turns[i];
    const x = tx(t);
    s.addShape(pres.shapes.OVAL, { x: x - 0.13, y: 4.07, w: 0.26, h: 0.26, fill: { color: C.background1 }, line: { color: col, width: 3 }, objectName: "turn-dot" + i });
    T(s, "0:" + String(t).padStart(2, "0"), { x: x - 0.5, y: 3.6, w: 1.0, h: 0.3, fontSize: 13, bold: true, color: C.accent5, align: "center" });
    const bx = Math.min(x - 0.13, 12.7 - 2.5);
    T(s, q, { x: bx, y: 4.6, w: 2.5, h: 0.75, fontSize: 14, bold: true, color: C.background1, italic: true });
    T(s, why, { x: bx, y: 5.3, w: 2.5, h: 0.3, fontSize: 12, color: col });
  }
  T(s, "Live call replay", { x: 0.6, y: 2.95, w: 4, h: 0.35, fontSize: 14, bold: true, color: C.accent2 });
  // big callout
  T(s, "9 s", { x: 0.6, y: 6.0, w: 1.6, h: 0.85, fontSize: 48, bold: true, color: C.accent2, fontFace: THEME.headFontFace, valign: "middle" });
  T(s, "The warning lands nine seconds before the gift-card ask. The call ends with: Blocked. Sam (daughter) was told.", { x: 2.25, y: 6.05, w: 10.4, h: 0.8, fontSize: 16, color: C.background1, valign: "middle" });
  s.addNotes("Guardian doesn't only clean up afterwards. In the replay, the Dynamic Island reads 'Guardian is listening'. After 'Grandma, it's me' the score turns yellow. At 'bail money, don't tell mom' it turns red: Hang up. They are asking for money or gift cards. That lands nine seconds before the gift-card ask. Be clear with clients: this is a replay today; a live call path needs a telephony provider and legal review, and is on the roadmap.");

  // ================= 6. Threat table =================
  s = pres.addSlide({ masterName: "CONTENT_LIGHT", sectionTitle: "Guardian in action" });
  s.addText("Five threats, one rule: act when it’s safe", { placeholder: "title" });
  const hdr = (t) => ({ text: t, options: { bold: true, color: C.background1, fill: { color: C.accent1 }, fontSize: 14 } });
  const cell = (t, o = {}) => ({ text: t, options: { color: C.text1, fontSize: 13, ...o } });
  const rows = [
    [hdr("Threat"), hdr("How it is spotted"), hdr("Guardian does on its own"), hdr("Waits for the person")],
    [cell("Scam calls and texts", { bold: true }), cell("Spoofed caller ID; gift cards, codes, “safe accounts”; secrecy; pay-by-link"), cell("Blocks the number, warns with exact steps, tells a trusted contact (with consent)"), cell("Nothing")],
    [cell("Card misuse", { bold: true }), cell("A charge with no receipt at a merchant they never use"), cell("Locks the card, only after a verified-human check"), cell("Confirming the dispute")],
    [cell("Account takeover", { bold: true }), cell("A reset, sign-in or code email they did not start"), cell("Alert with exact steps"), cell("Changing the password")],
    [cell("Phishing", { bold: true }), cell("Lookalike sender, pressure, a link to another domain, a login request"), cell("Quarantines the email"), cell("Nothing")],
    [cell("Data leaks", { bold: true }), cell("Their email in a breach, or a breach at a store they used"), cell("Alert with steps; locks a card used at a breached store"), cell("Changing passwords")],
  ];
  s.addTable(rows, { x: 0.6, y: 1.6, w: 12.1, colW: [2.3, 4.0, 3.6, 2.2], rowH: 0.72, border: { type: "solid", color: "D9E0E4", pt: 0.75 }, valign: "middle", margin: [0.06, 0.12, 0.06, 0.12], fill: { color: C.background1 }, objectName: "threat-table" });
  card(s, 0.6, 6.15, 12.1, 0.65, "extra-care", C.accent5);
  T(s, "Built for everyone. Extra-care mode lowers the bar for calls and texts for anyone who wants a closer watch.", { x: 0.85, y: 6.15, w: 11.6, h: 0.65, fontSize: 15, bold: true, color: C.accent1, valign: "middle" });
  s.addNotes("Guardian acts on its own only where acting is safe and reversible: blocking, quarantining, warning. Anything with money or passwords waits for the person. Card locks need a verified-human check first.");

  // ================= 7. How it works =================
  pres.addSection({ title: "How it works" });
  s = pres.addSlide({ masterName: "CONTENT_LIGHT", sectionTitle: "How it works" });
  s.addText("How Guardian thinks and acts", { placeholder: "title" });
  const pipe = [
    ["FaInbox", "Read", "Inbox, calls, card charges, receipts and a breach feed"],
    ["FaSearch", "Detect", "Rules score each item and explain why. Borderline cases get an AI second look"],
    ["FaUserLock", "Guard", "Feature gates, a live-human check, trusted-contact consent"],
    ["FaShieldAlt", "Act or hold", "Block, quarantine, lock, alert. Money waits for a yes"],
    ["FaClipboardList", "Record", "Every threat and action saved, so nothing repeats"],
  ];
  const pw = 2.15, gap = 0.34;
  for (let i = 0; i < pipe.length; i++) {
    const x = 0.6 + i * (pw + gap);
    card(s, x, 1.75, pw, 3.4, "pipe" + i, i === 3 ? C.accent5 : C.background1);
    await tile(s, pipe[i][0], x + 0.25, 2.0, 0.7, C.accent1, "FFFFFF", "pipe" + i);
    T(s, pipe[i][1], { x: x + 0.25, y: 2.9, w: pw - 0.4, h: 0.45, fontSize: 18, bold: true, color: C.text1, fontFace: THEME.headFontFace });
    T(s, pipe[i][2], { x: x + 0.25, y: 3.4, w: pw - 0.42, h: 1.65, fontSize: 14, color: C.accent6 });
    if (i < pipe.length - 1) s.addImage({ data: await icon("FaArrowRight", HEX.accent2, 128), x: x + pw + 0.06, y: 3.33, w: 0.22, h: 0.22, objectName: "arrow" + i, altText: "then" });
  }
  card(s, 0.6, 5.5, 12.1, 1.25, "audit", C.text2);
  await tile(s, "FaChartLine", 0.85, 5.75, 0.75, C.accent1, "FFFFFF", "audit");
  T(s, "Shows its work", { x: 1.85, y: 5.68, w: 10.6, h: 0.4, fontSize: 18, bold: true, color: C.background1 });
  T(s, "Every detect, guard and act step is an audit event. A 3–5 line daily brief and an evidence page show the reasons behind every action.", { x: 1.85, y: 6.08, w: 10.6, h: 0.6, fontSize: 14, color: C.accent5 });
  s.addNotes("The pipeline: read the person's data, detect with explainable rules (and a model's second look on borderline cases), guard every action with gates, a Persona live-human check and trusted-contact consent, act or hold, and record everything so nothing repeats. Run it twice and the second run repeats nothing. Every step goes to the audit trail.");

  // ================= 8. Trust =================
  s = pres.addSlide({ masterName: "CONTENT_LIGHT", sectionTitle: "How it works" });
  s.addText("Built to be trusted with your identity", { placeholder: "title" });
  const trust = [
    ["FaBrain", "AI can raise concern, never clear it", "An email telling the AI “this is safe” cannot hide a threat"],
    ["FaSlidersH", "Remote settings only tighten", "A stolen console key cannot make Guardian less careful"],
    ["FaUserCheck", "A live human before a card lock", "Persona check, under 24 hours old"],
    ["FaUsers", "Trusted contact told only with consent", "Sam replies YES first. Disputes always wait for Rose"],
    ["FaEyeSlash", "Analytics never see content", "No message text, names, numbers or emails leave"],
    ["FaLock", "Data sealed per person", "Passkeys, per-person encryption, 30-day retention, delete = shred"],
  ];
  for (let i = 0; i < trust.length; i++) {
    const col = i % 3, row = Math.floor(i / 3);
    const x = 0.6 + col * 4.1, y = 1.6 + row * 2.1, w = 3.85, h = 1.85;
    card(s, x, y, w, h, "trust" + i);
    await tile(s, trust[i][0], x + 0.25, y + 0.27, 0.62, C.accent1, "FFFFFF", "trust" + i);
    T(s, trust[i][1], { x: x + 1.05, y: y + 0.22, w: w - 1.25, h: 0.72, fontSize: 15, bold: true, color: C.text1, valign: "middle" });
    T(s, trust[i][2], { x: x + 0.25, y: y + 1.05, w: w - 0.45, h: 0.7, fontSize: 14, color: C.accent6 });
  }
  T(s, [{ text: "We attacked it ourselves: ", options: { bold: true, color: C.accent1 } }, { text: "13 loopholes found and fixed, each pinned by a test. 107 automated tests in all.", options: { color: C.text1 } }], { x: 0.6, y: 5.95, w: 12.1, h: 0.5, fontSize: 16, valign: "middle" });
  s.addNotes("We attacked it ourselves. An email that tells the AI to call it safe? The AI can only raise concern, never clear it. Remote settings can make Guardian more careful, never less. Card locks need Persona to confirm a live human within 24 hours. Sam is told only because she agreed. Analytics never see a message, a name or a number. Each person's data is encrypted with their own key; 'Delete my data' destroys the key first.");

  // ================= 9. Measured =================
  pres.addSection({ title: "Proof" });
  s = pres.addSlide({ masterName: "CONTENT_LIGHT", sectionTitle: "Proof" });
  s.addText("Measured, not claimed", { placeholder: "title" });
  s.addChart(pres.charts.BAR, [
    { name: "Rules only", labels: ["Rose, 78", "Jordan, 34"], values: [44, 20] },
    { name: "Rules + AI second look", labels: ["Rose, 78", "Jordan, 34"], values: [100, 100] },
  ], {
    x: 0.6, y: 1.5, w: 7.3, h: 5.2, barDir: "col", barGrouping: "clustered", barGapWidthPct: 60,
    chartColors: [HEX.accent6, HEX.accent1],
    showTitle: true, title: "New scams caught (held-out set, never tuned on)", titleFontSize: 16, titleColor: HEX.dk1, titleFontFace: "+mn-lt",
    showValue: true, dataLabelPosition: "outEnd", dataLabelFormatCode: '0"%"', dataLabelFontSize: 14, dataLabelColor: HEX.dk1, dataLabelFontFace: "+mn-lt",
    valAxisMaxVal: 110, valAxisMinVal: 0, valAxisMajorUnit: 25, valAxisHidden: true,
    valGridLine: { color: "E6EBEE", size: 0.75 }, catGridLine: { style: "none" },
    catAxisLabelColor: HEX.accent6, catAxisLabelFontSize: 14, catAxisLabelFontFace: "+mn-lt",
    showLegend: true, legendPos: "b", legendFontSize: 13, legendFontFace: "+mn-lt", legendColor: HEX.dk1,
    objectName: "recall-chart",
  });
  const proof = [["0", "false actions", "on 460 legitimate messages per set"], ["< 2", "alerts a day", "1.10 for Rose, 1.03 for Jordan"], ["0", "repeated actions", "over a simulated 30-day month"]];
  for (let i = 0; i < proof.length; i++) {
    const y = 1.6 + i * 1.45;
    T(s, proof[i][0], { x: 8.4, y, w: 1.5, h: 1.0, fontSize: 48, bold: true, color: C.accent1, fontFace: THEME.headFontFace, valign: "middle" });
    T(s, proof[i][1], { x: 9.95, y: y + 0.12, w: 2.8, h: 0.4, fontSize: 16, bold: true, color: C.text1 });
    T(s, proof[i][2], { x: 9.95, y: y + 0.5, w: 2.8, h: 0.45, fontSize: 13, color: C.accent6 });
  }
  T(s, "Two fictional people of different ages, 30 days of labelled email, texts, calls and charges each. AI second look: Superlinked Qwen3.5-4B, about 0.5 s a message. Next real test: shadow mode on real mail.", { x: 8.4, y: 5.95, w: 4.3, h: 0.85, fontSize: 11, color: C.accent6, italic: true });
  s.addNotes("We built a quality bar before touching real data: two synthetic people, 30 days each, real-looking scams and lookalike legitimate messages. On scams the rules were never tuned on, keyword rules caught 44% and 20%. Adding the model's raise-only second look took that to 100% for both, still with zero actions on anything legitimate and under two alerts a day. Honest caveat: the held-out scams were written by the same author as the rules; shadow mode on real mail is the real test.");

  // ================= 10. Alerts =================
  s = pres.addSlide({ masterName: "CONTENT_LIGHT", sectionTitle: "Proof" });
  s.addText("Speaks up only when it matters", { placeholder: "title" });
  const alerts = [
    ["FaExclamationTriangle", "Hang up now", "A scam in progress", "Full screen or Dynamic Island, with sound", "“Hang up. They’re asking for gift cards.”", C.accent4],
    ["FaBell", "Heads up", "Needs action today", "Push notification, SMS if no app", "“Someone tried to reset your Example Bank password. Tap to see the 3 steps.”", C.accent3],
    ["FaCheck", "FYI", "Already handled", "In the daily brief only", "“Quarantined 1 fake PayLink email.”", C.accent1],
  ];
  for (let i = 0; i < alerts.length; i++) {
    const x = 0.6 + i * 4.1, y = 1.6, w = 3.85, h = 3.9;
    card(s, x, y, w, h, "alert" + i, C.background2);
    await tile(s, alerts[i][0], x + 0.3, y + 0.3, 0.7, alerts[i][5], "FFFFFF", "alert" + i);
    T(s, alerts[i][1], { x: x + 1.2, y: y + 0.3, w: w - 1.4, h: 0.4, fontSize: 20, bold: true, color: C.text1, fontFace: THEME.headFontFace });
    T(s, alerts[i][2], { x: x + 1.2, y: y + 0.7, w: w - 1.4, h: 0.32, fontSize: 13, color: C.accent6 });
    // notification bubble
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: x + 0.3, y: y + 1.35, w: w - 0.6, h: 1.55, rectRadius: 0.15, fill: { color: C.background1 }, line: { color: "D9E0E4", width: 0.75 }, shadow: shadow(), objectName: "bubble" + i });
    T(s, alerts[i][4], { x: x + 0.5, y: y + 1.5, w: w - 1.0, h: 1.3, fontSize: 15, color: C.text1, valign: "middle" });
    T(s, alerts[i][3], { x: x + 0.3, y: y + 3.1, w: w - 0.6, h: 0.6, fontSize: 13, color: C.accent6, italic: true });
  }
  const parts = ["What happened", "What Guardian did", "The one thing to do", "“This was real” undo"];
  T(s, "Every alert says", { x: 0.6, y: 5.85, w: 2.2, h: 0.55, fontSize: 15, bold: true, color: C.text1, valign: "middle" });
  for (let i = 0; i < parts.length; i++) {
    const x = 2.8 + i * 2.5;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x, y: 5.85, w: 2.3, h: 0.55, rectRadius: 0.27, fill: { color: C.accent5 }, line: { type: "none" }, objectName: "chip" + i });
    T(s, parts[i], { x, y: 5.85, w: 2.3, h: 0.55, fontSize: 14, bold: true, color: C.accent1, align: "center", valign: "middle" });
  }
  s.addNotes("Three alert levels. Hang up now for a scam in progress. Heads up for something that needs action today. FYI for what's already handled, which only appears in the daily brief. Every alert says what happened, what Guardian did, and the one thing to do, with a 'This was real' button that undoes the action and teaches Guardian. At most one unprompted notification a day apart from urgent ones.");

  // ================= 11. Built with =================
  s = pres.addSlide({ masterName: "CONTENT_LIGHT", sectionTitle: "Proof" });
  s.addText("Real integrations, verified live", { placeholder: "title" });
  const stack = [
    ["Amplitude", "Audit trail: every detect, guard and act step is an event", "Live and verified", C.accent1],
    ["Statsig", "Seven safety gates, plus report analytics and session replay", "Live and verified", C.accent1],
    ["SingleStore", "Threats and actions store: the “never repeat” check", "Live and verified", C.accent1],
    ["Persona", "Live-human check before card locks and risky changes", "Live (sandbox)", C.accent1],
    ["Superlinked", "AI second look on borderline calls, texts and emails", "Measured on held-out set", C.accent3],
    ["Firedrill", "Synthetic Gmail, Stripe and Slack for drills", "Wired in", C.accent3],
  ];
  for (let i = 0; i < stack.length; i++) {
    const col = i % 3, row = Math.floor(i / 3);
    const x = 0.6 + col * 4.1, y = 1.6 + row * 2.45, w = 3.85, h = 2.2;
    card(s, x, y, w, h, "stack" + i);
    T(s, stack[i][0], { x: x + 0.3, y: y + 0.28, w: w - 0.6, h: 0.5, fontSize: 22, bold: true, color: C.text1, fontFace: THEME.headFontFace });
    T(s, stack[i][1], { x: x + 0.3, y: y + 0.85, w: w - 0.6, h: 0.75, fontSize: 14, color: C.accent6 });
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, { x: x + 0.3, y: y + 1.62, w: 2.6, h: 0.38, rectRadius: 0.19, fill: { color: stack[i][3] }, line: { type: "none" }, objectName: "status" + i });
    T(s, stack[i][2], { x: x + 0.3, y: y + 1.62, w: 2.6, h: 0.38, fontSize: 12, bold: true, color: C.background1, align: "center", valign: "middle" });
  }
  T(s, "Every part also runs offline on fictional data, so the agent degrades to “alert only” and never acts blind.", { x: 0.6, y: 6.5, w: 12.1, h: 0.35, fontSize: 13, color: C.accent6, italic: true });
  s.addNotes("Amplitude, Statsig, SingleStore and Persona are live and verified. Superlinked's model second look is measured on the held-out set. Firedrill provides synthetic Gmail, Stripe and Slack for drills. If any service is down, Guardian falls back to local storage or alert-only, and never acts blind.");

  // ================= 12. Roadmap =================
  pres.addSection({ title: "Next" });
  s = pres.addSlide({ masterName: "CONTENT_LIGHT", sectionTitle: "Next" });
  s.addText("From demo to daily protection", { placeholder: "title" });
  const road = [
    ["FaCheck", "Built today", ["Agent on fictional data", "Web app: passkeys, setup, home screen", "Gmail connector in shadow mode", "Encryption, retention, privacy page"], C.accent1],
    ["FaInbox", "Next 2 weeks", ["Shadow mode on real Gmail", "Mark each brief right or wrong", "Prove the quality bar on real mail"], C.accent2],
    ["FaBell", "Weeks 3–4", ["Push and SMS alerts (HTTPS)", "“Act for me” for quarantine", "Usability test, 3–5 people across ages"], C.accent3],
    ["FaMobileAlt", "Later", ["Native iOS and Android call and text filters", "Live-call path (legal review)", "Bank and card partners"], C.accent6],
  ];
  s.addShape(pres.shapes.LINE, { x: 0.95, y: 2.0, w: 11.0, h: 0, line: { color: "D9E0E4", width: 2 }, objectName: "road-line" });
  for (let i = 0; i < road.length; i++) {
    const x = 0.6 + i * 3.075;
    await tile(s, road[i][0], x, 1.62, 0.76, road[i][3], "FFFFFF", "road" + i);
    T(s, road[i][1], { x, y: 2.6, w: 2.85, h: 0.45, fontSize: 20, bold: true, color: C.text1, fontFace: THEME.headFontFace });
    T(s, road[i][2].map((t, j, a) => ({ text: t, options: { bullet: { indent: 16 }, breakLine: j < a.length - 1 } })), { x, y: 3.15, w: 2.85, h: 2.6, fontSize: 14, color: C.text1, paraSpaceAfter: 8, margin: 0 });
  }
  card(s, 0.6, 5.85, 12.1, 0.9, "ask", C.accent5);
  T(s, [{ text: "Starts in shadow mode: ", options: { bold: true, color: C.accent1 } }, { text: "Guardian watches and says what it would have done, and acts only once the person turns that on.", options: { color: C.text1 } }], { x: 0.85, y: 5.85, w: 11.6, h: 0.9, fontSize: 15, valign: "middle" });
  s.addNotes("What exists today: the agent, the web app with passkey sign-in and five-step setup, and a Gmail connector in shadow mode. Next is one to two weeks of shadow mode on real mail, then push and SMS alerts, then 'Act for me' for quarantine only, and a usability test with people across ages, from a student to someone over 65. Native call and text filters, the live-call path and bank partners come later.");

  // ================= 13. Close =================
  s = pres.addSlide({ masterName: "TITLE_DARK", sectionTitle: "Next" });
  await tile(s, "FaShieldAlt", 0.8, 0.8, 0.8, C.accent1, "FFFFFF", "brand-close");
  T(s, "GUARDIAN", { x: 1.8, y: 0.98, w: 4, h: 0.45, fontSize: 18, bold: true, color: C.background1, charSpacing: 4 });
  s.addText("Set it up once. Guardian protects your identity, tells someone you trust, and shows its work.", { placeholder: "title" });
  s.addText("Thank you. Questions?", { placeholder: "subtitle" });
  s.addText("Built with Amplitude, Statsig, SingleStore, Persona and Superlinked", { placeholder: "meta" });
  s.addNotes("Close: Set it up once. Guardian protects your identity, tells someone you trust, and shows its work. It is for anyone whose identity is online, at any age. Next: real Gmail in shadow mode, then live calls. For a client version, replace the bottom line with contact details.");

  await pres.writeFile({ fileName: OUT });
  if (APPLY_THEME) await require(APPLY_THEME).applyTheme(OUT, THEME);
  console.log("wrote", OUT);
})();
