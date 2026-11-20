# Guardian

A personal security agent that watches a person's digital life every day, acts on threats before they
cost money, tells their family when something serious happens, and shows the evidence behind every step.

Built for the Personal Agents Hackathon (tokens&, November 20, 2026). Brief: a personal agent that uses
reliable context, takes a meaningful action, and shows the information and steps behind what it did.

## What it protects against

| Threat | How it is spotted | What Guardian does on its own | What waits for the person |
|---|---|---|---|
| Scam calls, voicemails and texts | Spoofed caller ID, requests for gift cards, codes or "safe accounts", secrecy, "it's me, grandma" from unknown numbers, pay-by-link texts | Blocks the number, warns the person with exact steps, tells a trusted family member (with consent) | Nothing |
| Card misuse | A charge with no receipt at a merchant they never use | Locks the card (only after a verified-human check) | Confirming the dispute |
| Account takeover | A reset, sign-in or code email they did not start | Alert with exact steps | Changing the password |
| Phishing | Lookalike sender, pressure, a link to another domain, a login request | Quarantines the email | Nothing |
| Data leaks | Their email in a breach, or a breach at a store they bought from | Alert with steps; locks the card used at a breached store | Changing passwords |

Senior protection mode lowers the bar for calls, because older adults are targeted most.

## Run it

Python 3.9+ and the standard library only. No installs.

```bash
python3 agent/demo.py      # before a demo: reset the store, run, build both pages
npm install               # Statsig web SDK (only needed to refresh web/vendor/statsig.min.js)
python3 agent/run.py      # detect, decide, act, record
python3 agent/brief.py    # daily brief + web/report.html
python3 agent/live.py     # replay a live scam call + web/live.html (Dynamic Island warning)
(cd persona && npm install && npm test)   # Persona Relay sidecar; `node persona/server.js` with PERSONA_API_KEY set
python3 agent/run.py --approve dispute:tx-4   # say yes to one held action, then run
python3 agent/run.py --incoming demo/incoming_text.json   # a new scam text arrives, then run
python3 -m unittest discover -s tests -t .   # or: npm test
python3 agent/evaluate.py [--holdout]   # 30-day synthetic quality bar (PLAN.md section 6)
```

Open the report over http, so the Statsig web SDK works: `python3 -m http.server 8000 -d web`, then
<http://localhost:8000/report.html>. `web/report.html` is generated and not committed.

Run `agent/run.py` twice: the second run repeats nothing. Held actions (the dispute) wait until the person
approves that one action with `--approve` (or **Needs you** in the app); approvals live in the store, beside the
threats and actions. The report shows each
message Guardian sent (to the person and to family) and the command to approve anything waiting.
Calls and texts added with `--incoming` live in
`runs/incoming.json`. Threats are ranked critical (money or a scammer acting now), high (account attacks and risky leaks),
medium and low (leaks). Delete `runs/` and `outbox/` to start fresh.

## The app (set up once)

```bash
python3 -m venv .venv && .venv/bin/pip install -r app/requirements.txt
.venv/bin/python app/server.py      # open http://localhost:8800 (localhost, not 127.0.0.1: passkeys need it)
```

- **Sign in with a passkey** (Face ID, Touch ID, Windows Hello or a phone). No passwords.
- **Five-step setup:** who it's for, email (sample data until Gmail is connected), a trusted person (they must
  say YES; the app simulates the reply until an SMS account exists), "Just tell me" or "Act for me", and a test alert.
- **Home screen:** status, what Guardian found and did, what each held action is waiting for, **Needs you**
  (approve a dispute or card lock), **This was real** (undoes the action and never acts on it again),
  Pause, Sign out, **Delete my data**.
- **Always on:** a background worker checks everyone every 5 minutes (`GUARDIAN_CHECK_EVERY`); the app says
  so if it stops.
- **Security:** approving, deleting and turning on "Act for me" need a fresh passkey check (5 minutes).
  Posts must come from the app's own origin; the session cookie is HttpOnly and SameSite=Strict. Each
  person's data lives in `users/<random id>/` and "Delete my data" removes that folder.
- **Persona inside the app:** put `PERSONA_API_KEY` and a random `GUARDIAN_SIDECAR_SECRET` (16+ characters) in
  `.env`, then run `cd persona && npm install && node server.js` beside the app. The home screen offers
  "Verify with Persona" whenever card locks need it; each person's pass is kept in their own store for 24
  hours. Persona's page blocks headless browsers, so do the check in a normal browser.
- **Tests:** `.venv/bin/python -m unittest discover -s tests -t .` and the browser test `tests/e2e_app.js`.
- **Not yet:** real Gmail, push notifications while the app is closed (needs HTTPS and VAPID keys), real
  SMS for family consent, and a phone install (needs HTTPS on a real domain).

## How it works

```
data/ (inbox, calls, card charges, receipts, breach feed)
  -> agent/detect.py    rules score each item and explain why; borderline cases ask a model
  -> agent/respond.py   decide actions -> guard (gates, Persona check, consent) -> act or hold
  -> agent/store.py     write back every threat and action, so nothing repeats
  -> agent/audit.py     one event per step, locally and to Amplitude
  -> agent/brief.py     3-5 line daily brief and the evidence page
```

All actions are **simulated** into `outbox/` (blocked numbers, quarantine, card locks, alerts,
family alerts, disputes). Replacing one with a real integration changes only its branch in `respond.act`.

## Sponsor tools

| Tool | Role | Status |
|---|---|---|
| Amplitude | Audit trail: every detect, guard and act step is an event, with the run's gate values | **Live and verified** with `AMPLITUDE_API_KEY` |
| SingleStore | Threats and actions store (the "never repeat" check) | **Live and verified** when `SINGLESTORE_*` is set (Data API, two runs: 8 new threats, then 0); SQLite otherwise |
| Superlinked SIE | Borderline phishing and call checks; alert drafting with a fact guard | Live when `SIE_*` is set; rules and templates otherwise. Endpoint shape not yet verified |
| Persona Relay | `live_human_presence` check before Guardian may lock a card | **Live and verified** (sandbox, 2026-11-20): `persona/` sidecar, run on a laptop browser (Persona's widget blocks headless browsers), wrote `result: passed` to `data/verification.json`. A pass counts for 24 hours |
| Firedrill | Synthetic Gmail (inbox, quarantine), Stripe (card charges) and Slack (family alerts) for drills | Wired in (`agent/firedrill.py`) when `GUARDIAN_GMAIL_URL`, `GUARDIAN_STRIPE_URL`, `GUARDIAN_SLACK_URL` are set; tested against a local fake. Operation names not yet confirmed with `firedrill tools catalog-operations` |
| Statsig (web) | Report page: session replay, auto-capture analytics, `guardian_report_viewed` and `guardian_threat_opened` events | **Live and verified** with `STATSIG_CLIENT_KEY` (initialize 200, events 202) |
| Statsig (gates) | `senior_protection`, auto-block, auto-quarantine, auto-lock, disputes, family alerts, kill switch; every gate's value and source goes into each Amplitude event | **Live and verified** when `STATSIG_SERVER_SECRET` is set (`agent/flags.py`, all 7 gates read as `statsig`); `data/gates.json` otherwise |

Roadmap: Airbyte (live Gmail, phone and card sync), Parakeet on SIE (voicemail transcription),
cognee (what is normal for this person), Personal Agent Protocol (reaching banks and stores directly).

## Team setup

1. Copy `.env.example` to `.env` and fill in only the services you have keys for. Never commit `.env`.
2. All sample data is fictional and uses `.example` domains and `555` numbers. Keep it that way:
   no real people, numbers or emails in this repo.
3. Each module is small and owned by one person at a time:
   - `agent/detect.py`: detection rules (add a detector = one function + one line in `all_threats`)
   - `agent/respond.py`: actions and gates
   - `agent/store.py`, `agent/audit.py`, `agent/models.py`: sponsor integrations
   - `agent/brief.py`: brief and report page
   - `DEMO.md`: the 3-minute script
4. Run the tests before every push.
