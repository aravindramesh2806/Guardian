"""Model calls on Superlinked SIE. Every call has a fallback, so the agent works without a model.

Set SIE_BASE_URL (https://api.superlinked.com/v1) and SIE_API_KEY. Then:
  - SIE_MODEL (e.g. Qwen/Qwen3.5-4B) turns on chat: borderline labels and alert drafts (/chat/completions).
  - Embeddings are on with just the URL and key: scam_matches() compares messages to known scam types
    with SIE_EMBED_MODEL (default BAAI/bge-m3) on /encode/<model>. Both checked live 2026-11-20.
"""
import json
import math
import os
import urllib.request

EMBED_MODEL = "BAAI/bge-m3"
MATCH_AT = 0.70  # measured 2026-11-20 on bge-m3: scams 0.71-0.94, ordinary messages 0.44-0.59


def configured():
    return all(os.environ.get(k) for k in ("SIE_BASE_URL", "SIE_API_KEY", "SIE_MODEL"))


def chat(system, user, max_tokens=300):
    """One chat completion. Returns (text, model_name). Raises on any failure."""
    url = os.environ["SIE_BASE_URL"].rstrip("/") + "/chat/completions"
    model = os.environ["SIE_MODEL"]
    body = json.dumps({"model": model, "max_tokens": max_tokens, "temperature": 0,
                       "messages": [{"role": "system", "content": system},
                                    {"role": "user", "content": user}]}).encode()
    req = urllib.request.Request(url, data=body, headers={
        "Content-Type": "application/json", "Authorization": "Bearer " + os.environ["SIE_API_KEY"]})
    with urllib.request.urlopen(req, timeout=30) as resp:
        out = json.loads(resp.read())
    return out["choices"][0]["message"]["content"].strip(), model


def classify(text, default="suspicious"):
    """Label an email phishing, suspicious or safe. Returns (label, decided_by)."""
    if not configured():
        return default, "rules (no model configured)"
    system = ("You label emails for a personal security agent. Reply with exactly one word: "
              "phishing, suspicious or safe.")
    try:
        answer, model = chat(system, text, max_tokens=5)
    except Exception as e:  # a failed model call must not stop the run
        return default, "rules (model error: %s)" % type(e).__name__
    label = answer.strip().lower().strip(".")
    return (label if label in ("phishing", "suspicious", "safe") else default), model


def draft(facts, fallback_text, required):
    """Draft a message from facts only. Returns (text, drafted_by).

    The draft must contain every string in `required`, or the fallback is used.
    """
    if not configured():
        return fallback_text, "template"
    system = ("You write short, calm security alerts for a non-technical person. Use only the facts given. "
              "Do not add any fact, number or promise that is not in them.")
    try:
        text, model = chat(system, json.dumps(facts, default=str))
    except Exception as e:
        return fallback_text, "template (model error: %s)" % type(e).__name__
    if not all(r in text for r in required):
        return fallback_text, "template (model draft missed a required fact)"
    return text, model


def embeddings_configured():
    return all(os.environ.get(k) for k in ("SIE_BASE_URL", "SIE_API_KEY"))


def encode(texts):
    """Dense vectors for texts, one request. Raises on any failure."""
    model = os.environ.get("SIE_EMBED_MODEL", EMBED_MODEL)
    url = os.environ["SIE_BASE_URL"].rstrip("/") + "/encode/" + model
    body = json.dumps({"items": [{"text": t} for t in texts], "params": {"output_types": ["dense"]}}).encode()
    req = urllib.request.Request(url, data=body, headers={
        "Content-Type": "application/json", "Accept": "application/json",
        "Authorization": "Bearer " + os.environ["SIE_API_KEY"]})
    with urllib.request.urlopen(req, timeout=150) as resp:  # a cold model can take a while to load
        out = json.loads(resp.read())
    return [item["dense"]["values"] for item in out["items"]]


def _cosine(a, b):
    na, nb = math.sqrt(sum(x * x for x in a)), math.sqrt(sum(y * y for y in b))
    return sum(x * y for x, y in zip(a, b)) / (na * nb) if na and nb else 0.0


def scam_matches(texts, patterns):
    """For each text, the closest known scam type if it is close enough: {"id", "name", "similarity"} or None.

    Returns (matches, decided_by). Without embeddings or on any error every match is None.
    """
    if not texts or not patterns:
        return [None] * len(texts), "none"
    if not embeddings_configured():
        return [None] * len(texts), "no embeddings configured"
    try:
        vectors = encode([p["text"] for p in patterns] + list(texts))
    except Exception as e:  # a failed embedding call must not stop the run
        return [None] * len(texts), "embedding error: %s" % type(e).__name__
    known, mine = vectors[:len(patterns)], vectors[len(patterns):]
    out = []
    for v in mine:
        sim, best = max(((_cosine(v, k), p) for k, p in zip(known, patterns)), key=lambda pair: pair[0])
        out.append({"id": best["id"], "name": best["name"], "similarity": round(sim, 3)}
                   if best and sim >= MATCH_AT else None)
    return out, os.environ.get("SIE_EMBED_MODEL", EMBED_MODEL)
