# Guardian MVP plan

Goal: a person enrolls **once**, in about five minutes, and Guardian then protects their accounts, money and
identity in the background. It only speaks up when something matters, in plain language, with one clear
thing to do. People should never have to come back to settings.

Status on 2026-11-20: the hackathon demo works on fictional data. SingleStore, Amplitude and Statsig are
live. The Persona sidecar is built but waits for a key. Everything below is what stands between that demo
and something a real person can use every day.

---

## 1. What the MVP does (and does not)

**In the MVP**
- Reads **email** (Gmail first) and the **texts you forward** to Guardian.
- Finds phishing, account-takeover attempts, data breaches involving your email, and scam texts.
- Sends you an alert when it matters. It sends a short daily brief only if something happened.
- Tells one trusted family member about serious scams, with that person's agreement.
- Starts in **shadow mode**: it watches and says what it *would* have done, and acts only once you turn
  that on.

**After the MVP** (needs native apps, partners or legal review): live call listening, reading SMS directly,
blocking numbers on the phone, locking cards, filing disputes, bank transaction feeds.

Why this cut: email is the only channel with a proper, consented API on both iPhone and Android. Phones
deliberately block apps from reading texts and call audio (see section 3). Starting with what works
everywhere gets real users protected fastest.

---

## 2. One-time enrollment (target: under 5 minutes, no settings after)

| Step | What the person sees | What happens underneath |
|---|---|---|
| 1. Who is this for? | "Me" or "Someone in my family" | Family setup lets an adult child set things up, but the protected person must be present to consent in step 2 |
| 2. Create your account | "Use Face ID to sign in". No password | Passkey (WebAuthn), bound to the device. Then a Persona `live_human_presence` check |
| 3. Connect your email | One "Connect Gmail" button, then a plain list: "Guardian will read new emails to spot scams. It will never send email or delete anything." | Google OAuth with the smallest scopes (section 3). Token encrypted at rest |
| 4. Add someone you trust (optional) | "Who should we tell if a scammer targets you?" | That person gets a text: "Rose added you. Reply YES to agree." Nothing goes to them until they say yes |
| 5. How should Guardian help? | Two big choices: "Just tell me" (the default) or "Act for me, then tell me" | Sets the gates for this person. Senior mode is suggested for 65+ |
| 6. See it work | A sample alert arrives: "This is what a Guardian alert looks like." | Proves notifications reach them, before anything real happens |

Rules that keep it a one-time setup:
- Sensible defaults everywhere, with nothing to tune.
- Re-authentication is automatic and silent (refresh tokens). If Google revokes access, Guardian sends one
  alert with a one-tap "Reconnect".
- One screen in the app: "You're protected", what happened recently, and two buttons: "Pause Guardian"
  and "Delete my data".

### Alert design (the part people live with)

| Level | When | How | Example |
|---|---|---|---|
| Hang up now | A scam in progress | Full-screen or Dynamic Island, sound | "Hang up. They're asking for gift cards." |
| Heads up | Needs action today | Push notification (SMS if no app) | "Someone tried to reset your Example Bank password. Tap to see the 3 steps." |
| FYI | Already handled | In the daily brief only | "Quarantined 1 fake PayLink email." |

Every alert says: **what happened, what Guardian did, the one thing you should do**, and offers a
"This was real" button. That button undoes the action and teaches Guardian. No jargon, large type,
read-aloud support, and at most one unprompted notification a day apart from urgent ones.

---

## 3. Access and authentication: what reading your data requires

### Signing in to Guardian itself
- **Passkeys only** (Face ID or fingerprint). No passwords to phish.
- **Step-up check** for risky changes: adding or removing a trusted contact, connecting a new data
  source, turning on "act for me", or approving a dispute. These need a fresh passkey prompt and a
  Persona claim less than 24 hours old.
- Persona's `live_human_presence` proves a live human, **not who it is**. It must never stand in for
  consent from the account owner. Consent comes from the owner's own OAuth grant and passkey.

### Email (Gmail)
- OAuth 2.0 with `gmail.readonly` for the MVP. Add `gmail.modify` (labels only, for quarantine) only
  when actions are switched on.
- These are Google **restricted scopes**. While testing, the Google Cloud project stays in "testing"
  mode with up to 100 named test users (you first). Going public needs Google's app verification and a
  third-party security assessment (CASA). Plan weeks for this.
- Use Gmail push (`users.watch` with Pub/Sub) for near-real-time, and polling as a fallback.
- Outlook or Yahoo come later, through the same connector interface.

### Text messages
- **iPhone:** no app can read your SMS or iMessage. Options: a Message Filter extension (it sorts
  texts from unknown senders on the device and never sees known contacts), and forwarding suspicious
  texts to Guardian (a share action or a Guardian number).
- **Android:** reading SMS is restricted by Google Play to default SMS apps. Notification access is
  possible but also policy-restricted. Same MVP answer: forward-to-Guardian.

### Calls
- **iPhone:** no access to call audio. A Call Directory extension can label and block numbers that
  Guardian flags.
- **Android:** the Call Screening role sees the number (not audio) and can block it.
- **Live listening** (the Dynamic Island demo) needs Guardian on the call path: a Guardian number
  through a telephony provider, with a spoken announcement. Recording and consent laws vary by state.
  This is post-MVP and needs legal review.

### Money (post-MVP)
- Read-only transactions through an aggregator with the bank's own consent screen. Card lock and
  disputes only through issuer partnerships. Never with stored bank passwords.

### Protecting what Guardian holds
- Encrypt tokens and message content at rest, with a separate key per user. Keep secrets in a secrets
  manager, not a `.env` file.
- **Keep the verdict, drop the content:** keep "phishing from X, reasons Y" and delete raw email or
  text bodies after 30 days (or at once, as the user chooses).
- Third-party analytics (Amplitude) get event types, counts and a hashed user ID. They never get
  message text, phone numbers or email addresses. Today they do (L3 below).
- No human at Guardian reads user content. Access to production data is logged.
- "Delete my data" removes everything and revokes the OAuth tokens.

---

## 4. Loopholes found (tested on 2026-11-20)

**Fixed on 2026-11-20, each pinned by a test in `SecurityTests`:** L1 (model can only raise concern),
L2 in part (a real domain used as a prefix is now caught; exact-domain forgery still needs SPF, DKIM and
DMARC headers), L3 (analytics get kinds, numbers and outcomes only), L4 (Statsig can tighten action
gates, never loosen them), L5 in part (a pass expires after 24 hours; it still lives in a file). Also:
an unreachable SingleStore now falls back to SQLite instead of stopping protection.

| # | Loophole | Proof | Fix |
|---|---|---|---|
| L1 | **Model can be talked out of a detection.** A borderline email that says "answer safe" gets labelled safe and disappears | Probe: 0 threats found for the injected email | The model may only **raise** concern, never clear a rule hit. Borderline means at least "suspicious". Strip instructions before classifying |
| L2 | **Subdomain and exact-spoof senders slip under the bar.** `examplebank.example.evil.test` and a forged `examplebank.example` both score 0.6, under 0.7 | Probe scores | Check the registrable domain (eTLD+1). Check SPF, DKIM and DMARC results from the email headers. Normalise Unicode lookalikes |
| L3 | **Private data leaves for Amplitude.** Detect events include full call transcripts and email addresses | 3 events with transcripts, 3 with emails in the last run | Send only kinds, counts and a hashed ID. Keep full evidence in the encrypted store |
| L4 | **Remote settings can loosen safety.** Statsig can switch off `dispute_needs_approval` or `kill_switch`, so a stolen console key could make Guardian file disputes on its own | Gates are read straight from Statsig | Remote gates may only make Guardian **more** cautious. Loosening needs the user's own step-up approval in the app |
| L5 | **Persona "passed" never expires**, and it lives in a plain file anyone with disk access can edit | `respond.guard` checks only `result` | Store the claim with its time and expire it after 24 hours for risky actions. Keep it in the store, not a file |
| L6 | **Trusted-contact consent is a checkbox** in `profile.json`. Nothing proves Sam agreed, and anyone who gets in could add themselves | `consent: true` is just data | Double opt-in by text. Adding a contact needs a step-up check. Notify the user when contacts change |
| L7 | **No undo.** Blocks and quarantines can't be reversed from the product | No undo path in `respond.py` | Every action gets an undo, and "This was real" triggers it |
| L8 | **Held actions can't be approved.** A dispute waits for Rose, but there is no button for her to say yes | `held()` writes "waiting for you" only | An approval flow in the app, with a step-up check |
| L9 | **Alerts go nowhere.** Every alert, family message and action is written to `outbox/` files | `respond.act` | Real push, SMS and email channels, with delivery tracking |
| L10 | **One hard-coded user.** `demo-user` is used for Amplitude, Statsig and the store | `audit.py`, `flags.py` | A user ID everywhere. Store rows partitioned per user |
| L11 | **The island says "listening" when nothing is.** It is fine for a replay, misleading in a product | `web/live.html` | Show it only when a real call path is active |
| L12 | **Crash between acting and saving** can repeat an action on the next run | `run.handle` acts, then saves | Write "started" before acting, "done" after. Make every action idempotent at the provider |
| L13 | **Keys pasted in chat** (SingleStore, Statsig server and console, Amplitude) | This session | Rotate all four after the hackathon. Revoke the Statsig console key once the gates exist |

---

## 5. Everything pending for the MVP

**Must have**
1. Users and enrollment: passkeys, per-user data, family setup with consent. Fixes L10.
2. Gmail connector in shadow mode first: OAuth, push and poll, minimal scopes.
3. Forward-a-text intake: share action and a Guardian number or address.
4. Notification channels: push (installed web app or native), SMS and email fallback, delivery receipts.
   Fixes L9.
5. App screen: "You're protected", recent items, "This was real", approve held actions, Pause, Delete.
   Fixes L7 and L8.
6. Always on: a scheduler or worker that processes new mail within minutes, and a heartbeat alert if
   Guardian stops.
7. Security fixes L1 to L6 and L12.
8. Privacy basics: encryption at rest, retention, analytics minimisation, plain-language privacy page,
   delete-everything.
9. Persona live, with your sandbox key, plus claim freshness (L5).

**Should have**
- SIE model on borderline cases (after the L1 fix), and alert drafting with the fact guard kept.
- Detection quality: SPF, DKIM and DMARC; eTLD+1 checks; Unicode lookalikes; more scam phrases; a
  per-person "normal" baseline.

**Later:** native iOS and Android (call and text filters, Dynamic Island), the live-call path, bank and
card partners, Airbyte, Parakeet, cognee, Personal Agent Protocol.

### Platform choice (decide first)
**Recommended: an installable web app (PWA) plus a small backend.** It gives one codebase, no app-store
wait, passkeys and web push on Android and on iOS 16.4+ once added to the home screen. Native apps
follow when the call and text filters are needed.

---

## 6. Proving it works before real data ("dummy tests")

1. **Synthetic people:** two to three fictional users (a senior, a busy professional) with 30 days of
   labelled email and texts. That means real-looking scams *and* look-alike legitimate messages (a real
   bank notice, a real delivery). All on `.example` domains and `555` numbers.
2. **Quality bar:** on the labelled set, **zero automatic actions on legitimate messages**, scam recall
   above 90%, and fewer than 2 unprompted notifications a day.
3. **Adversarial suite:** prompt injection (L1), subdomain and Unicode lookalikes (L2), forged headers,
   very long or odd input, replayed and duplicate messages, HTML in content (report escaping).
4. **Security suite:**
   - Remote gate loosening is refused (L4).
   - A stale or edited Persona claim is refused (L5).
   - Consent revoked mid-run stops family alerts.
   - The kill switch stops everything except alerts.
   - A test fails if any analytics payload, log or outbox line contains message text, a phone number or
     an email address (L3).
5. **Failure suite:** SingleStore, Statsig, Amplitude, Gmail or the model down, so Guardian degrades to
   "alert only" and never acts blind. A crash mid-action leaves no repeats (L12).
6. **30-day soak:** run the scheduler over the synthetic month. No repeated alerts, alert volume within
   the budget, no growth in errors.
7. **Enrollment dry run:** a scripted walk-through timed to under 5 minutes, then a usability test with
   3 to 5 people, including someone over 65.

### Results on 2026-11-20 (`python3 agent/evaluate.py`, `--holdout`)

| Set | Person | Threats flagged | Auto actions on legit | Alerts a day | Repeats |
|---|---|---|---|---|---|
| Baseline, before fixes | Rose / Jordan | 76% / 70% | **1 / 1** (card locked over a $4.50 parking charge) | 0.97 / 0.77 | 0 |
| Dev set, after fixes | Rose / Jordan | 100% / 100% | 0 / 0 | 1.10 / 1.03 | 0 |
| **Held-out set** (never tuned on) | Rose / Jordan | **44% / 20%** | 0 / 0 | 0.37 / 0.17 | 0 |

What it means:
- **Safe:** across both sets and both people, nothing legitimate was acted on, and nothing was repeated.
  A small unrecognised charge (under $50) now asks before locking the card.
- **Not yet good enough at new scams:** the 100% on the dev set is the rules learning those cases. On
  scams phrased differently (benefits-card, "reply with the code", "press 1 for a refund", mailbox-full,
  prize and lottery fees), keyword rules catch 20 to 44%.
- **Built, waiting for a key:** the model's second look (`detect.second_look`). Measure it with `python3 agent/evaluate.py --holdout --model`.
- **Next for recall:** a language model on every message from an unknown sender (SIE, raise-only, as L1
  requires), measured on the held-out set and a fresh set written by someone who has not read the rules.
  Real recall is only known from shadow mode on real mail.
- Known noise still in the dev set: a grandson's "I got you a gift card" call (a senior-mode alert), and
  parking or cafe charges with no receipt (an ask, not a lock).

### Then: testing on yourself
- **Shadow mode for 1 to 2 weeks** on your real Gmail: read-only, no actions, nothing sent to anyone
  else. Each day you mark the brief's items right or wrong.
- Switch on "act for me" only after shadow mode reaches the quality bar on *your* mail.

---

## 7. What's needed from you to start

| Item | Needed for | When |
|---|---|---|
| Decision: PWA first? | Everything after the demo | Now |
| Decision: first user is you, or a family member? | Enrollment flow and senior defaults | Now |
| Persona sandbox key | Persona live (P0) | When you have it |
| Google Cloud project with the Gmail API, OAuth consent screen in testing mode, your address as a test user | Gmail connector | Before the shadow-mode test |
| A domain with HTTPS | Passkeys and web push need a real origin | Before enrollment works on a phone |
| An SMS and email sending account | Alerts, family consent texts | Before alerts leave the outbox |
| Rotate the four keys pasted in chat | Security | After the hackathon (you said within 6 hours) |
| Legal read on call listening and family alerts | Post-MVP call features | Before any live-call work |

Nothing in this table blocks the dummy tests. Those can start now on fictional data.

## Progress on section 5 (2026-11-20)

- Done in the web app (`app/`), tested end to end in a browser with a virtual passkey: 1 (people and
  workspaces), 2 (setup, with Gmail and SMS steps simulated and labelled), 5 (home screen: undo with
  "This was real", approve with a fresh passkey check, Pause, Delete), 6 (background worker and
  "checks aren't running" warning).
- Partly done: 4 (notifications while the app is open; push while it is closed needs HTTPS and VAPID).
- Open: 3 (Gmail; needs the Google project), 7 (encryption at rest, retention, privacy page), 8 (SPF,
  DKIM and DMARC; Persona claim kept in the store; started-before-acting marker).

## 8. Order of work

1. **Today (demo):**
   - Reset demo state (SingleStore keeps old threats, so a fresh run would show 0 new).
   - Persona live once the key arrives.
   - Add the live call to DEMO.md and log it to the audit trail. Rehearse.
2. **Week 1:**
   - Security fixes L1 to L6 and L12, with their tests.
   - Synthetic 30-day dataset, quality bar, adversarial and failure suites.
3. **Week 2:** user model and passkey enrollment, PWA shell, notification channels, app screen with undo
   and approve.
4. **Week 3:** Gmail connector in shadow mode, scheduler and heartbeat. Start testing on yourself.
5. **Week 4:** fix what shadow mode finds. Turn on "act for me" for quarantine only. Usability test with
   3 to 5 people.
