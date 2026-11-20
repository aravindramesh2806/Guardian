"""Known-scam similarity on SIE embeddings, with the embedding call replaced by fixed vectors."""
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from agent import detect, models

SAMPLE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
REWORDED = {"id": "c-299", "kind": "voicemail", "from": "+1-555-0166", "caller_id": "Unknown",
            "at": "2026-11-20T11:00:00",
            "transcript": "Hi Nana, it's your grandson. I got arrested last night and need $2,000 for bail."}


def fake_encode(texts):
    """Grandparent-style texts point one way, everything else another."""
    return [[1.0, 0.0] if ("grand" in t.lower() or "nana" in t.lower()) else [0.0, 1.0] for t in texts]


class SimilarityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.data = os.path.join(self.tmp, "data")
        shutil.copytree(SAMPLE, self.data)
        path = os.path.join(self.data, "calls.json")
        with open(path) as f:
            calls = json.load(f)
        with open(path, "w") as f:
            json.dump(calls + [REWORDED], f)
        self.patterns = [{"id": "grandparent-bail", "name": "family emergency", "text": "Grandma, it's me, bail"}]

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_without_embeddings_nothing_matches(self):
        with mock.patch.dict(os.environ, {"SIE_BASE_URL": "", "SIE_API_KEY": ""}):
            found, by = models.scam_matches(["anything"], self.patterns)
        self.assertEqual((found, by), ([None], "no embeddings configured"))

    def test_close_text_matches_and_far_text_does_not(self):
        with mock.patch.dict(os.environ, {"SIE_BASE_URL": "http://x", "SIE_API_KEY": "k"}), \
                mock.patch.object(models, "encode", fake_encode):
            found, _ = models.scam_matches(["Nana, I need bail", "Dinner on Saturday?"], self.patterns)
        self.assertEqual(found[0]["id"], "grandparent-bail")
        self.assertIsNone(found[1])

    def test_embedding_error_falls_back_to_rules(self):
        def broken(texts):
            raise OSError("down")
        with mock.patch.dict(os.environ, {"SIE_BASE_URL": "http://x", "SIE_API_KEY": "k"}), \
                mock.patch.object(models, "encode", broken):
            found, by = models.scam_matches(["x"], self.patterns)
        self.assertEqual((found, by), ([None], "embedding error: OSError"))

    def test_reworded_scam_is_caught_with_the_reason_shown(self):
        env = {"SIE_BASE_URL": "http://x", "SIE_API_KEY": "k", "SIE_MODEL": ""}
        with mock.patch.dict(os.environ, env):
            without = {t["key"] for t in detect.all_threats(self.data)}
            with mock.patch.object(models, "encode", fake_encode):
                threats = {t["key"]: t for t in detect.all_threats(self.data)}
        self.assertNotIn("scam:c-299", without)  # rules alone: only "possibly a scam"
        self.assertIn("suspicious:c-299", without)
        reasons = threats["scam:c-299"]["evidence"]["reasons"]
        self.assertTrue(any("known scam: family emergency" in r for r in reasons))

    def test_known_contacts_are_never_compared(self):
        with mock.patch.dict(os.environ, {"SIE_BASE_URL": "http://x", "SIE_API_KEY": "k"}), \
                mock.patch.object(models, "encode", fake_encode):
            profile = detect.load("profile.json", self.data)
            calls = detect.load("calls.json", self.data)
            matches, _ = detect.scam_similarity(profile, [], calls, self.data)
        known = {c["number"] for c in profile["phone_contacts"]}
        self.assertFalse(any(c["id"] in matches for c in calls if c["from"] in known))
        self.assertIn("c-299", matches)


if __name__ == "__main__":
    unittest.main()
