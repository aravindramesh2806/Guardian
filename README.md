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
python3 -m unittest discover -s tests -t .
```

Open the report over http, so the Statsig web SDK works: `python3 -m http.server 8000 -d web`, then
<http://localhost:8000/report.html>. `web/report.html` is generated and not committed.

Run `agent/run.py` twice: the second run repeats nothing. Delete `runs/` and `outbox/` to start fresh.

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
| Persona Relay | `live_human_presence` check before Guardian may lock a card | Sidecar built in `persona/` (10 tests against a stub of the SDK's types); **not yet run against Persona**, needs `PERSONA_API_KEY`. Until then `data/verification.json` is a local stand-in |
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
