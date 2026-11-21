# Guardian: 3-minute demo

**Before going on stage**

```bash
python3 agent/demo.py
```

That resets the store (SingleStore too), clears approvals and any `--incoming` text, runs the agent, and
builds both pages. If it prints a
SingleStore WARNING, run it again once SingleStore is back. Then:

```bash
python3 -m http.server 8000 -d web
```

Open two tabs: <http://localhost:8000/report.html> and <http://localhost:8000/live.html>. Keep a terminal
ready for the second run, and the Statsig console open on `senior_protection`.

## 0:00 – 0:25 The problem
"People aged 60 and over reported about $7.7 billion lost to fraud in 2025, roughly 60% more than the
year before, according to AARP's summary of the FBI's internet crime report. The scams come by phone,
text and email, and the agents people use today help them shop and schedule, not protect them."

"Meet Rose, 78. Her daughter Sam worries about her. Rose set up Guardian once, and it has watched over
her ever since."

## 0:25 – 1:05 One morning, nine threats (report tab)
Point at the demo-mode banner and "4 critical · 4 high · 1 medium", then read the brief: "9 new threats today. 5 stopped for you, 1 needs you, and your family was told
about 3."
- A voicemail that shows "Example Bank" but comes from the wrong number, asking her to move money to a
  "safe account" and read out a code. **Blocked. Rose warned. Sam told.**
- "Grandma, it's me, I need bail, buy gift cards, don't tell mom." **Blocked. Sam told.**
- A parcel text with a payment link. **Blocked.**
- A $389 charge she never made. **Card locked. Dispute waiting for Rose's yes.**
- A lookalike "PayLinc" refund email. **Quarantined.**
- A bank password reset she didn't ask for, a forum leak with her email, a breach at a store she used.
  **Exact steps for each.**
- A vague "call back about your gift card" voicemail. **Flagged as possibly a scam** (senior protection).

Scroll to a scam voicemail: the cards show the exact message Rose got (with steps) and the text Sam got.

## 1:05 – 1:40 And when the scammer calls live (live tab, press Replay)
"Guardian doesn't only clean up afterwards." The island reads *Guardian is listening*. After "Grandma,
it's me" the score turns yellow. At "bail money, don't tell mom" it turns red: **Hang up. They are
asking for money or gift cards.** That lands nine seconds *before* the gift-card ask. It ends with
*Blocked. Sam (daughter) was told.*

## 1:40 – 2:25 Why you can trust it (report tab, open one threat's audit trail)
- The reasons: "caller ID says Example Bank, but the real number is +1-555-0199".
- Card locks only after **Persona** confirms a live human, and only if that check is under 24 hours old.
- Sam is told only because she agreed. Disputes always wait for Rose.
- "We attacked it ourselves. An email that tells the AI to call it safe? The AI can only raise
  concern, never clear it. Remote settings can make Guardian more careful, never less. And analytics
  never see a message, a name or a number."

## 2:25 – 2:45 Rose says yes, and it never nags twice
Point at the "Needs you" box on the $389 charge, then run live:
`python3 agent/run.py --approve dispute:tx-4 && python3 agent/brief.py` and refresh the report.
0 new threats, nothing repeated, and only that one dispute is filed: "Done for you since then:
dispute filed." The gate that holds disputes stays on; Rose approved this one, and the audit trail says so.

## Live beat, if time allows: a new scam arrives on stage
"While we've been talking, Rose just got a text." Run:
`python3 agent/run.py --incoming demo/incoming_text.json && python3 agent/brief.py` and refresh.
The brief reads "1 new threat today. 1 stopped for you, nothing needs you, and your family was told about 1":
a fake unpaid-toll text with a pay link, blocked, Rose warned, Sam told. Run it once more: nothing repeats.

## Optional beat: complete the loop (Amplitude + Statsig)
Turn `senior_protection` off in Statsig, start fresh and rerun: the borderline gift-card voicemail
(`c-206`) is no longer caught (8 threats instead of 9).
Show both groups in Amplitude (every event carries the gate values), turn it back on.

## 2:45 – 3:00 Close
"Set it up once. Guardian protects you, tells your family, and shows its work. Next: real Gmail in
shadow mode, then live calls. Built with Amplitude, Statsig, SingleStore and Persona."
(Name Superlinked only once SIE is actually wired up.)

## If something breaks on stage
- **SingleStore down:** the agent falls back to local storage and still runs. The report shows
  "sqlite (singlestore unreachable)". Say so, and carry on.
- **No network:** every part runs offline on fictional data. Only the Amplitude, Statsig and SingleStore
  beats need the internet.
