# Guardian: 3-minute demo

**Setup before going on stage:** `rm -rf runs outbox && python3 agent/run.py && python3 agent/brief.py`,
then open `web/report.html`. Keep a terminal ready for the second run.

## 0:00 – 0:30 The problem
"People aged 60 and over reported about $7.7 billion lost to fraud in 2025, roughly 60% more than the
year before, according to AARP's summary of the FBI's internet crime report. The scams come by phone,
text and email, and the agents people use today help them shop and schedule, not protect them."

"Meet Rose, 78. Her daughter Sam worries about her. Guardian is Rose's personal security agent."

## 0:30 – 1:30 One morning, eight threats
Show the brief at the top of the report:
- A voicemail that shows "Example Bank" but comes from the wrong number, asking her to move money to a
  "safe account" and read out a code. **Blocked. Rose warned. Sam told.**
- "Grandma, it's me, I need bail, buy gift cards, don't tell mom." **Blocked. Sam told.**
- A parcel text with a payment link. **Blocked.**
- A $389 charge she never made. **Card locked. Dispute waiting for Rose's yes.**
- A lookalike "PayLinc" refund email. **Quarantined.**
- A bank password reset she didn't ask for, a forum leak with her email, a breach at a store she used.
  **Exact steps for each.**

## 1:30 – 2:15 Why you can trust it
Open one scam voicemail in the report and expand its audit trail:
- the reasons ("caller ID says Example Bank, but the real number is +1-555-0199"),
- the gate that allowed the block, the Persona check that allowed the card lock,
- Sam was told only because she consented.

"Guardian locks cards only after Persona confirms a live human set it up. Disputes wait for Rose.
A kill switch stops every action but still lets alerts through."

## 2:15 – 2:45 It never nags twice
Run `python3 agent/run.py` again live: 0 new threats, nothing repeated, the dispute still waiting.

## 2:45 – 3:00 Close
"Guardian: the personal agent that protects you, tells your family, and shows its work.
Built with Amplitude, SingleStore, Superlinked and Persona."
