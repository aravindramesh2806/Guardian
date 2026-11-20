# Guardian: 3-minute demo

**Setup before going on stage:** `rm -rf runs outbox && python3 agent/run.py && python3 agent/brief.py`,
then `python3 -m http.server 8000 -d web` and open <http://localhost:8000/report.html>.
Starting fresh also clears approvals and the incoming text, so the live beats can be rehearsed.
Keep a terminal ready for the second run.

## 0:00 – 0:30 The problem
"People aged 60 and over reported about $7.7 billion lost to fraud in 2025, roughly 60% more than the
year before, according to AARP's summary of the FBI's internet crime report. The scams come by phone,
text and email, and the agents people use today help them shop and schedule, not protect them."

"Meet Rose, 78. Her daughter Sam worries about her. Guardian is Rose's personal security agent."

## 0:30 – 1:30 One morning, nine threats
Show the top of the report: the demo-mode banner, then "4 critical · 2 high · 3 medium", then the brief:
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

## 1:30 – 2:15 Why you can trust it
Open one scam voicemail in the report and expand its audit trail:
- the reasons ("caller ID says Example Bank, but the real number is +1-555-0199"),
- the gate that allowed the block, the Persona check that allowed the card lock,
- Sam was told only because she consented.

"Guardian locks cards only after Persona confirms a live human set it up. Disputes wait for Rose.
A kill switch stops every action but still lets alerts through."

## 2:15 – 2:45 Rose says yes, and it never nags twice
Point at the "Needs you" box on the $389 charge, then run live:
`python3 agent/run.py --approve dispute:tx-4 && python3 agent/brief.py` and refresh the report.
0 new threats, nothing repeated, and only that one dispute is filed: "Done for you since then:
dispute filed." The gate that holds disputes stays on; Rose approved this one, and the audit trail says so.

## Live beat: a new scam arrives on stage
"While we've been talking, Rose just got a text." Run:
`python3 agent/run.py --incoming demo/incoming_text.json && python3 agent/brief.py` and refresh.
The brief reads "1 new threat today. 1 stopped for you, nothing needs you, and your family was told about 1":
a fake unpaid-toll text with a pay link, blocked, Rose warned, Sam told. Run it once more: nothing repeats.

## Optional beat: complete the loop (Amplitude + Statsig)
Turn `senior_protection` off in Statsig, start fresh and rerun: the borderline gift-card voicemail
(`c-206`) is no longer caught (8 threats instead of 9).
Show both groups in Amplitude (every event carries the gate values), turn it back on.

## 2:45 – 3:00 Close
"Guardian: the personal agent that protects you, tells your family, and shows its work.
Built with Amplitude, Statsig, SingleStore, Superlinked and Persona."
