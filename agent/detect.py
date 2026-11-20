"""Threat detectors. Each returns a list of threats with the evidence behind them and a stable key.

Rules decide first (free and explainable). Only a borderline phishing score asks a model.
"""
import difflib
import json
import os
import re
from datetime import datetime, timedelta

from agent import firedrill, models

DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")

URGENT = ("within 24 hours", "on hold", "suspended", "urgent", "immediately", "final notice", "verify")
CREDENTIAL_ASK = ("log in", "login", "password", "verify your account", "confirm your details")
TAKEOVER = ("password reset", "reset your password", "new sign-in", "sign-in attempt",
            "verification code", "login from a new device")
HIGH_RISK_DATA = ("password", "card")


def load(name, data_dir=None):
    with open(os.path.join(data_dir or DATA, name)) as f:
        return json.load(f)


def domain_of(address_or_url):
    """The host part of an email address or URL, lowercased."""
    s = address_or_url.lower()
    if "@" in s and "//" not in s:
        return s.split("@", 1)[1]
    s = re.sub(r"^[a-z]+://", "", s)
    return s.split("/", 1)[0]


def _threat(kind, key, severity, summary, evidence):
    return {"kind": kind, "key": key, "severity": severity, "summary": summary, "evidence": evidence}


def breaches(profile, breach_feed, receipts):
    """Leaks that include the person's email, and breaches at stores they bought from."""
    out = []
    emails = {e.lower() for e in profile["emails"]}
    merchants = {r["merchant"]: r for r in receipts}
    for b in breach_feed:
        hit = sorted(emails & {e.lower() for e in b.get("affected_emails", [])})
        risky = [d for d in b["data_types"] if any(h in d for h in HIGH_RISK_DATA)]
        severity = "high" if risky else "medium"
        if hit:
            out.append(_threat(
                "identity_breach", "breach:%s:%s" % (b["id"], ",".join(hit)), severity,
                "%s leaked %s for %s" % (b["name"], ", ".join(b["data_types"]), ", ".join(hit)),
                {"breach": b["id"], "disclosed": b["disclosed"], "emails": hit, "data_types": b["data_types"],
                 "domains": b["domains"]}))
        if b.get("merchant") in merchants:
            r = merchants[b["merchant"]]
            out.append(_threat(
                "merchant_breach", "merchant-breach:%s" % b["id"], severity,
                "%s, where you shopped on %s, was breached (%s)" % (b["merchant"], r["date"], ", ".join(b["data_types"])),
                {"breach": b["id"], "disclosed": b["disclosed"], "merchant": b["merchant"],
                 "your_order": r["order"], "card": r["card"], "data_types": b["data_types"]}))
    return out


def takeover(profile, inbox, window_hours=24):
    """Reset, sign-in or code emails from the person's accounts that they did not start themselves."""
    out = []
    accounts = {a["domain"]: a["name"] for a in profile["accounts"]}
    started = [(s["domain"], datetime.fromisoformat(s["at"])) for s in profile.get("started_actions", [])]
    for m in inbox:
        text = (m["subject"] + " " + m["body"]).lower()
        dom = domain_of(m["from"])
        if dom not in accounts or not any(t in text for t in TAKEOVER):
            continue
        received = datetime.fromisoformat(m["received"])
        mine = any(d == dom and timedelta(0) <= received - at <= timedelta(hours=window_hours) for d, at in started)
        if mine:
            continue
        out.append(_threat(
            "takeover", "takeover:%s" % m["id"], "high",
            "Someone tried to get into your %s account (\"%s\")" % (accounts[dom], m["subject"]),
            {"email": m["id"], "from": m["from"], "received": m["received"], "account": accounts[dom],
             "why": "you did not start a reset or sign-in for this account in the last %d hours" % window_hours}))
    return out


def phishing_score(message, known_domains):
    """Score 0-1 with the reasons behind it."""
    sender = domain_of(message["from"])
    text = (message["subject"] + " " + message["body"]).lower()
    score, reasons = 0.0, []
    if sender not in known_domains:
        best = max(known_domains, key=lambda d: difflib.SequenceMatcher(None, sender, d).ratio())
        ratio = difflib.SequenceMatcher(None, sender, best).ratio()
        if ratio >= 0.8:
            score += 0.5
            reasons.append("sender %s looks like %s but is not it" % (sender, best))
    if any(u in text for u in URGENT):
        score += 0.2
        reasons.append("pressure to act fast")
    foreign = [domain_of(l) for l in message.get("links", [])
               if domain_of(l) != sender and domain_of(l) not in known_domains]
    if foreign:
        score += 0.3
        reasons.append("link goes to %s" % foreign[0])
    if any(c in text for c in CREDENTIAL_ASK):
        score += 0.1
        reasons.append("asks you to log in or verify")
    return min(round(score, 2), 1.0), reasons


SIMILAR_BOOST = 0.3


def add_match(score, reasons, match):
    """A close match to a known scam type adds to the score, with the reason shown."""
    if not match:
        return score, reasons
    return (min(round(score + SIMILAR_BOOST, 2), 1.0),
            reasons + ["reads like a known scam: %s (similarity %.2f)" % (match["name"], match["similarity"])])


def phishing(profile, inbox, threshold=0.7, borderline=0.4, matches=None):
    """Phishing emails, with a model check only for borderline scores.

    `matches` maps an email id to its closest known scam type (see scam_similarity).
    """
    out = []
    known = {a["domain"] for a in profile["accounts"]}
    matches = matches or {}
    for m in inbox:
        score, reasons = add_match(*phishing_score(m, known), matches.get(m["id"]))
        verdict, model = None, "rules"
        if score >= threshold:
            verdict = "phishing"
        elif score >= borderline:
            verdict, model = models.classify(m["subject"] + "\n" + m["body"], default="suspicious")
        if verdict in ("phishing", "suspicious"):
            out.append(_threat(
                verdict, "%s:%s" % (verdict, m["id"]), "high" if verdict == "phishing" else "medium",
                "%s email from %s: \"%s\"" % ("Phishing" if verdict == "phishing" else "Suspicious",
                                             m["from"], m["subject"]),
                {"email": m["id"], "from": m["from"], "score": score, "reasons": reasons, "decided_by": model}))
    return out


PAYMENT_ASK = ("gift card", "wire", "bitcoin", "crypto", "safe account", "bail", "read me the code",
               "read me the numbers", "code we just texted")
SECRECY = ("don't tell", "do not tell", "keep this between us", "don't call")
PRESSURE = ("right now", "today", "immediately", "in trouble", "arrest", "compromised", "suspended", "held")
FAMILY_OPENERS = ("grandma, it's me", "grandpa, it's me", "mom, it's me", "dad, it's me", "it's me")


def call_score(call, contacts):
    """Score 0-1 for a call, voicemail or text, with the reasons behind it."""
    text = call.get("transcript", "").lower()
    by_name = {c["name"].lower(): c["number"] for c in contacts}
    known_numbers = set(by_name.values())
    score, reasons = 0.0, []
    real = by_name.get(call.get("caller_id", "").lower())
    if real and real != call["from"]:
        score += 0.5
        reasons.append("caller ID says %s, but %s's real number is %s" % (call["caller_id"], call["caller_id"], real))
    if call["from"] not in known_numbers and any(f in text for f in FAMILY_OPENERS):
        score += 0.3
        reasons.append("claims to be family from a number not in your contacts")
    asks = [p for p in PAYMENT_ASK if p in text]
    if asks:
        score += 0.3
        reasons.append("asks for money or codes in a way real banks and family don't (%s)" % ", ".join(asks[:2]))
    if any(s in text for s in SECRECY):
        score += 0.2
        reasons.append("asks you to keep it secret")
    if any(p in text for p in PRESSURE):
        score += 0.1
        reasons.append("pressure to act fast")
    if call.get("links") and call["from"] not in known_numbers:
        score += 0.3
        reasons.append("text from an unknown number with a link to %s" % domain_of(call["links"][0]))
        if "pay" in text:
            score += 0.3
            reasons.append("asks you to pay through a link")
    return min(round(score, 2), 1.0), reasons


def scam_calls(profile, calls, senior=None, matches=None):
    """Scam calls, voicemails and texts. Senior protection lowers the bar by 0.1.

    `senior` comes from the senior_protection gate; None falls back to the profile setting.
    """
    out = []
    if senior is None:
        senior = profile.get("protection") == "senior"
    threshold, borderline = (0.5, 0.3) if senior else (0.6, 0.4)
    contacts = profile.get("phone_contacts", [])
    matches = matches or {}
    for c in calls:
        score, reasons = add_match(*call_score(c, contacts), matches.get(c["id"]))
        verdict, model = None, "rules"
        if score >= threshold:
            verdict = "scam_call"
        elif score >= borderline:
            label, model = models.classify(c.get("transcript", ""), default="suspicious")
            verdict = {"phishing": "scam_call", "suspicious": "suspicious"}.get(label)
        if verdict == "scam_call":
            out.append(_threat(
                "scam_call", "scam:%s" % c["id"], "high",
                "Scam %s from %s (shows as \"%s\")" % (c["kind"], c["from"], c.get("caller_id", "Unknown")),
                {"call": c["id"], "kind": c["kind"], "from": c["from"], "caller_id": c.get("caller_id"),
                 "at": c["at"], "score": score, "reasons": reasons, "decided_by": model,
                 "senior_protection": senior, "transcript": c.get("transcript", "")}))
        elif verdict == "suspicious":
            out.append(_threat(
                "suspicious", "suspicious:%s" % c["id"], "medium",
                "Possibly a scam %s from %s" % (c["kind"], c["from"]),
                {"call": c["id"], "from": c["from"], "score": score, "reasons": reasons, "decided_by": model}))
    return out


def card_misuse(profile, transactions, receipts):
    """Charges with no matching receipt at a merchant the person does not usually use."""
    out = []
    usual = {u.lower() for u in profile["usual_merchants"]}
    matched = {(r["merchant"].lower(), round(r["amount"], 2)) for r in receipts}
    for t in transactions:
        if t["merchant"].lower() in usual or (t["merchant"].lower(), round(t["amount"], 2)) in matched:
            continue
        out.append(_threat(
            "card_misuse", "charge:%s" % t["id"], "high",
            "Unrecognised charge of $%.2f at %s on card ending %s" % (
                t["amount"], t["merchant"], t["card"].split("-")[-1]),
            {"transaction": t["id"], "card": t["card"], "merchant": t["merchant"], "amount": t["amount"],
             "date": t["date"], "why": "no receipt matches it and you have not used this merchant before"}))
    return out


def scam_similarity(profile, inbox, calls, data_dir=None):
    """Closest known scam type for each message from someone the person does not know.

    Known contacts and account domains are skipped: their real messages (a genuine bank reset email)
    can read like a scam, and a scammer spoofing them is caught by the other rules. Returns
    ({item id: match}, decided_by).
    """
    try:
        patterns = load("scam_patterns.json", data_dir)
    except FileNotFoundError:
        return {}, "no scam patterns"
    numbers = {c["number"] for c in profile.get("phone_contacts", [])}
    domains = {a["domain"] for a in profile["accounts"]}
    items = [(c["id"], c.get("transcript", "")) for c in calls if c["from"] not in numbers and c.get("transcript")]
    items += [(m["id"], m["subject"] + "\n" + m["body"]) for m in inbox if domain_of(m["from"]) not in domains]
    found, decided_by = models.scam_matches([t for _, t in items], patterns)
    return {i: f for (i, _), f in zip(items, found) if f}, decided_by


def _source(service, remote, local_name, data_dir, errors):
    """Read from Firedrill when it is set up, else the local file. A Firedrill failure skips that source
    (and is reported) rather than silently reading local demo data in its place."""
    if not firedrill.configured(service):
        return load(local_name, data_dir)
    try:
        return remote()
    except Exception as e:
        errors.append("could not read %s: %s" % (service, e))
        return []


def all_threats(data_dir=None, senior=None, errors=None):
    """Run every detector over the person's data. Inbox and charges come from Firedrill when it is set up.

    Sources that could not be read are appended to `errors`.
    """
    errors = [] if errors is None else errors
    profile = load("profile.json", data_dir)
    receipts = load("receipts.json", data_dir)
    inbox = _source("gmail", firedrill.inbox, "inbox.json", data_dir, errors)
    transactions = _source("stripe", lambda: firedrill.transactions(profile), "transactions.json", data_dir, errors)
    calls = load("calls.json", data_dir)
    matches, _ = scam_similarity(profile, inbox, calls, data_dir)
    found = (breaches(profile, load("breaches.json", data_dir), receipts)
             + takeover(profile, inbox)
             + phishing(profile, inbox, matches=matches)
             + scam_calls(profile, calls, senior, matches=matches)
             + card_misuse(profile, transactions, receipts))
    # Most urgent first: things a scammer is doing right now, then money, then accounts, then news.
    severity = {"high": 0, "medium": 1}
    urgency = {"scam_call": 0, "card_misuse": 1, "takeover": 2, "phishing": 3, "suspicious": 4,
               "merchant_breach": 5, "identity_breach": 6}
    return sorted(found, key=lambda t: (severity.get(t["severity"], 2), urgency.get(t["kind"], 9)))
