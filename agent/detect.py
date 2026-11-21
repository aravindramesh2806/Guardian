"""Threat detectors. Each returns a list of threats with the evidence behind them and a stable key.

Rules decide first (free and explainable). Only a borderline phishing score asks a model.
"""
import difflib
import json
import os
import re
from datetime import datetime, timedelta

from agent import models

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
    """The host part of an email address or URL, lowercased. Handles "Name <addr@host>" senders."""
    s = address_or_url.lower().strip()
    bracket = re.search(r"<([^>]*)>", s)
    if bracket:
        s = bracket.group(1).strip()
    if "@" in s and "//" not in s:
        return s.rsplit("@", 1)[1].strip(" >")
    s = re.sub(r"^[a-z]+://", "", s)
    host = s.split("/", 1)[0].split("?", 1)[0]
    # http://examplebank.example@evil.test/ goes to evil.test: everything before "@" is a username.
    return host.rsplit("@", 1)[-1].split(":", 1)[0]


def same_site(a, b):
    """One site and its own subdomains count as the same place: mail.shop.example and shop.example."""
    return bool(a and b) and (a == b or a.endswith("." + b) or b.endswith("." + a))


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
        # A real domain used as a prefix, e.g. examplebank.example.evil.test: the real owner is evil.test.
        hidden = next((d for d in known_domains if sender.startswith(d + ".")), None)
        # A real person's account list can start empty (before they name their bank): no lookalike check then.
        best = max(known_domains, key=lambda d: difflib.SequenceMatcher(None, sender, d).ratio()) if known_domains else ""
        ratio = difflib.SequenceMatcher(None, sender, best).ratio() if best else 0.0
        if hidden:
            score += 0.5
            reasons.append("sender %s starts with %s but belongs to someone else" % (sender, hidden))
        elif ratio >= 0.8:
            score += 0.5
            reasons.append("sender %s looks like %s but is not it" % (sender, best))
    if "xn--" in sender:
        score += 0.3
        reasons.append("sender %s uses an encoded international name that can imitate another" % sender)
    if any(u in text for u in URGENT):
        score += 0.2
        reasons.append("pressure to act fast")
    foreign = [domain_of(l) for l in message.get("links", [])
               if not same_site(domain_of(l), sender) and not any(same_site(domain_of(l), d) for d in known_domains)]
    if foreign:
        score += 0.3
        reasons.append("link goes to %s" % foreign[0])
    if any(c in text for c in CREDENTIAL_ASK):
        score += 0.1
        reasons.append("asks you to log in or verify")
    # The same scam language the call rules look for: it arrives by email too.
    asks = [p for p in PAYMENT_ASK if p in text]
    if asks:
        score += 0.3
        reasons.append("asks for gift cards, crypto or transfers (%s)" % ", ".join(asks[:2]))
    if any(s in text for s in SECRECY):
        score += 0.2
        reasons.append("asks you to keep it secret")
    if sender not in known_domains and "pay" in text and any(w in text for w in PAYMENT_DEMAND):
        score += 0.3
        reasons.append("demands payment, and you have no account with %s" % sender)
    return min(round(score, 2), 1.0), reasons


def _model_label(ask, key, text):
    """One model answer for a borderline message: through `ask` (cached and capped per run) when given."""
    if ask is None:
        return models.classify(text, default="suspicious")
    label, by = ask(key, text)
    return (label, by) if label else ("suspicious", "rules (%s)" % by)


def phishing(profile, inbox, threshold=0.7, borderline=0.4, ask=None):
    """Phishing emails, with a model check only for borderline scores."""
    out = []
    known = {a["domain"] for a in profile["accounts"]}
    for m in inbox:
        score, reasons = phishing_score(m, known)
        verdict, model = None, "rules"
        if score >= threshold:
            verdict = "phishing"
        elif score >= borderline:
            verdict, model = _model_label(ask, "email:" + m["id"], m["subject"] + "\n" + m["body"])
            if verdict not in ("phishing", "suspicious"):
                # The model may raise concern, never clear a rule hit: the email itself could have told it
                # to answer "safe". Borderline stays at least suspicious.
                verdict, model = "suspicious", "rules (model said %s; rules still flag it)" % verdict
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
PAYMENT_DEMAND = ("invoice", "overdue", "late fee", "unpaid", "outstanding balance")
REMOTE_ACCESS = ("remote access", "remote control", "anydesk", "teamviewer", "control of your computer")
LEGAL_THREAT = ("warrant", "arrest", "police will", "officers will", "deport", "lawsuit against you")
INVESTMENT_PITCH = ("invest", "doubled my", "guaranteed return", "trading strategy", "returns of")


def call_score(call, contacts, known_domains=()):
    """Score 0-1 for a call, voicemail or text, with the reasons behind it.

    `known_domains` are the person's own accounts: a text linking there (a real delivery or bank text) is
    not counted as a link to a stranger's site.
    """
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
    unknown = call["from"] not in known_numbers
    stranger_links = [domain_of(l) for l in call.get("links") or []
                      if not any(same_site(domain_of(l), d) for d in known_domains)]
    if stranger_links and unknown:
        score += 0.3
        reasons.append("text from an unknown number with a link to %s" % stranger_links[0])
        if "pay" in text:
            score += 0.3
            reasons.append("asks you to pay through a link")
    if unknown and any(r in text for r in REMOTE_ACCESS):
        score += 0.5
        reasons.append("an unknown caller wants remote access to your device")
    if unknown and any(t in text for t in LEGAL_THREAT):
        score += 0.2
        reasons.append("threatens arrest or legal action")
    if unknown and any(i in text for i in INVESTMENT_PITCH):
        score += 0.2
        reasons.append("an investment pitch from a number you don't know")
    return min(round(score, 2), 1.0), reasons


def scam_calls(profile, calls, senior=None, ask=None):
    """Scam calls, voicemails and texts. Senior protection lowers the bar by 0.1.

    `senior` comes from the senior_protection gate; None falls back to the profile setting.
    """
    out = []
    if senior is None:
        senior = profile.get("protection") == "senior"
    threshold, borderline = (0.5, 0.3) if senior else (0.6, 0.4)
    contacts = profile.get("phone_contacts", [])
    known = [a["domain"] for a in profile.get("accounts", [])]
    for c in calls:
        score, reasons = call_score(c, contacts, known)
        verdict, model = None, "rules"
        if score >= threshold:
            verdict = "scam_call"
        elif score >= borderline:
            label, model = _model_label(ask, "call:" + c["id"], c.get("transcript", ""))
            # As with email: a "safe" answer cannot clear a borderline call (the transcript is attacker text).
            verdict = "scam_call" if label == "phishing" else "suspicious"
        if verdict == "scam_call":
            out.append(_threat(
                "scam_call", "scam:%s" % c["id"], "critical",
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
        small = t["amount"] < SMALL_CHARGE
        out.append(_threat(
            "card_misuse", "charge:%s" % t["id"], "medium" if small else "critical",
            ("Did you make this $%.2f charge at %s on card ending %s?" if small
             else "Unrecognised charge of $%.2f at %s on card ending %s") % (
                t["amount"], t["merchant"], t["card"].split("-")[-1]),
            {"transaction": t["id"], "card": t["card"], "merchant": t["merchant"], "amount": t["amount"],
             "date": t["date"], "small": small,
             "why": "no receipt matches it and you have not used this merchant before"}))
    return out


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


# Below this, an unrecognised charge is usually parking, a cafe or a toll: Guardian asks before locking the card
# instead of locking it, because a wrong lock strands the person. Above it, the lock goes ahead.
SMALL_CHARGE = 50.0


def _source(name, service, sources, remote, local):
    """Read one source from Firedrill when its address is set, else from data/. Records which in `sources`.

    A Firedrill service that is down gives nothing for this run (and says so): Guardian never falls back to
    the sample files during a drill, because that would hide the outage.
    """
    from agent import firedrill
    if not firedrill.configured(service):
        sources[name] = "local"
        return local()
    try:
        items = remote()
    except Exception as e:
        sources[name] = "firedrill unavailable (%s)" % type(e).__name__
        return []
    sources[name] = "firedrill (%d)" % len(items)
    return items


def second_look(profile, inbox, calls, found, ask):
    """Ask a model about messages from unknown senders that the rules let through.

    Raise-only: a model answer can add a "suspicious" alert, which only ever alerts (respond.decide). It can
    never quarantine, block or lock anything, and never clears a rule hit. So a message that talks the model
    into anything costs at most one extra alert. `ask(key, text)` returns (label, decided_by) or (None, why).
    """
    seen = {t["evidence"].get(k) for t in found for k in ("email", "call")}
    known = [a["domain"] for a in profile.get("accounts", [])]
    numbers = {c["number"] for c in profile.get("phone_contacts", [])}
    out = []
    for m in inbox:
        sender = domain_of(m.get("from", ""))
        if m["id"] in seen or any(same_site(sender, d) for d in known):
            continue
        label, by = ask("email:" + m["id"], "Email from %s\nSubject: %s\n\n%s" % (
            m.get("from", ""), m.get("subject", ""), m.get("body", "")))
        if label in ("phishing", "suspicious"):
            out.append(_threat("suspicious", "suspicious:%s" % m["id"], "medium",
                               "Suspicious email from %s: \"%s\"" % (m.get("from", ""), m.get("subject", "")),
                               {"email": m["id"], "from": m.get("from", ""), "score": None,
                                "reasons": ["a language model flagged it; the rules did not"], "decided_by": by}))
    for c in calls:
        if c["id"] in seen or c.get("from") in numbers:
            continue
        label, by = ask("call:" + c["id"], "%s from %s (shows as %s)\n\n%s" % (
            c.get("kind", "call"), c.get("from", ""), c.get("caller_id", "Unknown"), c.get("transcript", "")))
        if label in ("phishing", "suspicious"):
            out.append(_threat("suspicious", "suspicious:%s" % c["id"], "medium",
                               "Possibly a scam %s from %s" % (c.get("kind", "call"), c.get("from", "")),
                               {"call": c["id"], "from": c.get("from", ""), "score": None,
                                "reasons": ["a language model flagged it; the rules did not"], "decided_by": by}))
    return out


def all_threats(data_dir=None, senior=None, sources=None, ask=None, extra_calls=()):
    """Run every detector over the person's data. `sources` (a dict) is filled with where each input came from.

    `extra_calls` are calls and texts that just arrived (run.py --incoming).

    `ask`, when given, is the model's second look at unknown senders the rules let through (second_look).
    """
    from agent import firedrill
    sources = {} if sources is None else sources
    profile = load("profile.json", data_dir)
    receipts = load("receipts.json", data_dir)
    inbox = _source("inbox", "gmail", sources, firedrill.inbox, lambda: load("inbox.json", data_dir))
    charges = _source("card_charges", "stripe", sources, lambda: firedrill.transactions(profile),
                      lambda: load("transactions.json", data_dir))
    found = (breaches(profile, load("breaches.json", data_dir), receipts)
             + takeover(profile, inbox)
             + phishing(profile, inbox, ask=ask)
             + scam_calls(profile, load("calls.json", data_dir) + list(extra_calls), senior, ask=ask)
             + card_misuse(profile, charges, receipts))
    calls = load("calls.json", data_dir) + list(extra_calls)
    if ask is not None:
        found += second_look(profile, inbox, calls, found, ask)
    # Most urgent first: things a scammer is doing right now, then money, then accounts, then news.
    severity = SEVERITY_ORDER
    urgency = {"scam_call": 0, "card_misuse": 1, "takeover": 2, "phishing": 3, "suspicious": 4,
               "merchant_breach": 5, "identity_breach": 6}
    return sorted(found, key=lambda t: (severity.get(t["severity"], 4), urgency.get(t["kind"], 9)))
