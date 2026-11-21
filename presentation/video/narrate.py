"""Records the intro narration with Kokoro, a free open-source AI voice that runs offline.

Needs Python 3.10+, `pip install kokoro-onnx soundfile`, and the model files kokoro-v1.0.onnx and
voices-v1.0.bin (github.com/thewh1teagle/kokoro-onnx releases). Pass the folder that holds them:
    python narrate.py /path/to/kokoro-model-folder
Writes narration/s1.wav ... s7.wav and prints each clip's length, for LENGTHS in render.js.
"""
import os
import sys

import soundfile as sf
from kokoro_onnx import Kokoro

VOICE = "af_heart"   # Kokoro's most natural American English voice: warm, calm, female
SPEED = 0.94         # a touch slower than default reads as more human

LINES = [
    "Scams move fast. Guardian moves first.",
    "Last year, Americans reported losing nearly twenty one billion dollars to online crime... "
    "by phone, by text, and by email. If you're online, you're a target.",
    "Guardian is for anyone with a digital identity. Meet Rose. She set it up once, in under five minutes, with no passwords. "
    "Her daughter, Sam, agreed to be her trusted contact.",
    "One morning, Guardian found eight threats. It blocked the scam calls, quarantined a fake refund email, "
    "and locked her card after a charge she never made. The dispute? That waits for Rose.",
    "And when a scammer calls live, Guardian tells Rose to hang up... "
    "nine seconds before the gift card ask.",
    "Every action comes with its reasons. The AI can raise concern, but never clear it. "
    "And Sam is told only because she agreed.",
    "Set it up once. Guardian protects your identity, tells someone you trust, and shows its work.",
]

here = os.path.dirname(os.path.abspath(__file__))
models = sys.argv[1]
kokoro = Kokoro(os.path.join(models, "kokoro-v1.0.onnx"), os.path.join(models, "voices-v1.0.bin"))
os.makedirs(os.path.join(here, "narration"), exist_ok=True)
for i, line in enumerate(LINES, 1):
    audio, rate = kokoro.create(line, voice=VOICE, speed=SPEED, lang="en-us")
    path = os.path.join(here, "narration", f"s{i}.wav")
    sf.write(path, audio, rate)
    print(f"s{i} {len(audio) / rate:.2f}s")
