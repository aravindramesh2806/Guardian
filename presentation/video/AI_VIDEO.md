# Guardian: AI video package (60 seconds)

A short, live-action-style film made with an AI video tool (Sora, Veo, Runway, Kling or similar). Generate each
shot separately from the prompts below, then cut them together with the voiceover, music and on-screen text in
any editor (CapCut, Premiere, DaVinci Resolve, iMovie).

**Story in one line:** Rose, 78, gets a scam call from someone pretending to be her grandson. Guardian warns her
to hang up before she loses any money, and her daughter Sam is told.

**Why it works for judges and clients:** it opens on a real emotion (someone scared for a person they love),
shows the product doing one meaningful thing in real time, and ends on trust. Rose is one example: the opening
line makes clear Guardian is for anyone with a digital identity, at any age. For a second cut, the same story
works with Jordan, 34, getting a fake "your bank account is locked" call at work.

---

## Rules that keep it safe and consistent

- **Fictional only.** No real banks, brands, phone numbers or real people's faces. The bank is "Example Bank",
  numbers are 555 numbers. The same rule as the repo's sample data.
- **Don't let the AI write words.** AI video tools garble text on screens and signs. Ask for *blank* or *softly
  glowing* phone screens and add every word (alerts, captions, logo) in the edit. The on-screen text for each
  shot is listed below.
- **Keep Rose and Sam the same in every shot.** Paste the character block below into every prompt that features
  them. If your tool supports a reference image or "character" feature, generate Rose once (shot 1), then use
  that frame as the reference for the rest.
- **Same look everywhere.** Paste the style block at the end of every prompt.

### Character blocks (paste as written)

> **ROSE:** a warm 78-year-old woman with short silver hair, reading glasses on a beaded chain, a soft lavender
> cardigan over a cream blouse, gentle expressive face.

> **SAM:** a woman in her late 40s with shoulder-length dark brown hair, a navy blazer, focused and kind.

### Style block (paste at the end of every prompt)

> Cinematic, shallow depth of field, soft natural morning light, warm interior tones with deep green accents,
> 35mm film look, gentle handheld camera, realistic, no text, no logos, no captions.

---

## Shot list

Durations are targets; most tools generate 5–10 s clips, so trim in the edit.

| # | Time | Shot | Voiceover (VO) | On-screen text (add in edit) |
|---|---|---|---|---|
| 1 | 0:00–0:06 | Rose at her kitchen table with tea | "Anyone with a phone, an inbox or a card is a target. Today, it's Rose." | — |
| 2 | 0:06–0:12 | Phone rings; Rose picks it up | — (phone ring) | Caller: "Unknown · +1-555-0123" |
| 3 | 0:12–0:18 | Rose listening, worried | CALLER (tense, young male voice): "Grandma, it's me. I'm in trouble." | — |
| 4 | 0:18–0:24 | Close-up of the phone; the warning lights up | VO: "Guardian is listening for the signs." | Top of the screen: **Unknown caller claims family** (amber) |
| 5 | 0:24–0:30 | Rose hears the money ask; the warning turns red | CALLER: "I need bail money. Don't tell mom." | **Hang up. They are asking for money or gift cards.** (red) |
| 6 | 0:30–0:36 | Rose lowers the phone and hangs up, relieved | VO: "Nine seconds before the gift-card ask, Guardian tells her to hang up." | **Blocked.** |
| 7 | 0:36–0:43 | Sam at work gets a calm alert, smiles, calls her mother | VO: "Sam is told, because she agreed to be." | Notification: **Guardian: A scammer called Mom. The call was blocked. She's safe.** |
| 8 | 0:43–0:50 | Rose and Sam on a video call, laughing | VO: "It blocks scam calls, quarantines fake emails, and locks a card before a stranger can use it." | — |
| 9 | 0:50–0:56 | Slow push-in on Rose's phone face-down beside her tea | VO: "Set it up once. Guardian protects your identity, tells someone you trust, and shows its work." | — |
| 10 | 0:56–1:00 | End card (make this in the editor, not with AI) | — | Shield logo, **GUARDIAN**, "Scams move fast. Guardian moves first." |

Total voiceover: about 70 words, at a calm pace.

---

## Prompts (copy one per generation)

**Shot 1: Morning at home**
> Medium shot of ROSE sitting at a sunlit kitchen table in a cozy suburban home, holding a cup of tea with both
> hands, a smartphone lying face-down on the table beside a small plant, she looks out the window peacefully.
> Slow dolly-in. [ROSE block] [style block]

**Shot 2: The call**
> Close-up of an older woman's hand reaching for a ringing smartphone on a wooden kitchen table, the screen
> glowing softly with a blank incoming-call screen, morning light, ROSE picks it up and brings it to her ear.
> [ROSE block] [style block]

**Shot 3: Worry**
> Close-up of ROSE holding a phone to her ear, her expression shifting from curious to deeply worried, eyebrows
> raised, hand moving to her chest, kitchen softly blurred behind her. [ROSE block] [style block]

**Shot 4: The warning (amber)**
> Over-the-shoulder shot of ROSE holding a smartphone slightly away from her ear, the top of the phone screen
> glowing with a soft amber light, she glances at it, puzzled. Shallow focus on the phone. Screen content
> blank and glowing, no text. [ROSE block] [style block]

**Shot 5: The warning (red)**
> Extreme close-up of a smartphone screen glowing with a pulsing soft red light at the top edge, reflected in
> the lenses of an older woman's reading glasses, tension, shallow depth of field. Screen content blank, no
> text. [style block]

**Shot 6: Hang up**
> ROSE lowers the phone from her ear, taps to end the call, and exhales with relief, setting the phone down on
> the kitchen table, gentle smile returning, warm light. [ROSE block] [style block]

**Shot 7: Sam is told**
> SAM sitting at a desk in a bright modern office, her phone buzzes, she reads it, her face moves from concern
> to relief, she picks up the phone to make a call. [SAM block] [style block]

**Shot 8: Family**
> ROSE at her kitchen table on a video call on a tablet, laughing warmly; on the tablet screen a soft blurred
> image of SAM smiling. Warm, reassuring mood. [ROSE block] [SAM block] [style block]

**Shot 9: Peace**
> Slow cinematic push-in on a smartphone lying face-down next to a steaming cup of tea on a sunlit kitchen
> table, dust motes in the light, calm and safe mood. [style block]

---

## Voiceover and sound

- **Narrator:** warm, calm, mid-30s to 50s, trustworthy rather than salesy. Use ElevenLabs or a similar AI voice
  tool, or record it yourself. The lines are in the shot list.
- **Caller (shots 3 and 5):** a young male voice, urgent and slightly muffled, as if through a phone (add a
  telephone EQ in the edit). Keep it fictional; don't clone anyone's real voice.
- **Music:** soft piano with light strings. Let it drop out at shot 5 (the red warning), then come back warm at
  shot 6.
- **Sound effects:** phone ring (shot 2), a gentle two-tone alert chime when the warning appears (shots 4 and 5),
  a soft notification buzz (shot 7).

## On-screen text style (for the edit)

Match the deck and the animated video: dark green `#0B1F1A` panels, green `#0B6E4F`, mint `#3FB98A`, amber
`#E0A100`, red `#D0453F`, white text. Put the phone warnings in a black rounded pill at the top of the phone,
like the "Dynamic Island" in the animated video. End card: reuse the first or last frame of
`guardian-intro.mp4`.

## Tool tips

- Generate 3–4 versions of each shot and keep the best; faces and hands vary between takes.
- Generate at 16:9 for the pitch. For social posts, also make a 9:16 cut: the phone close-ups (shots 4–6) work
  well vertical.
- If the tool adds stray text or logos anyway, add "no text, no watermark" again at the start of the prompt.
- If one shot won't come out well, swap in the matching scene from `guardian-intro.mp4` (the live-call scene
  covers shots 4–6).

## Being honest in the cut

The live-call warning is a replay in today's demo; a real live-call path needs a telephony provider and legal
review (see `PLAN.md`). For a client version, add a small caption on shots 4–6: *"Concept: live call
protection is on the roadmap."*
