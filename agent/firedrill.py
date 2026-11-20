"""Firedrill: run Guardian against synthetic Gmail, Stripe and Slack instead of the files in data/.

Firedrill (docs.firedrill.run) gives each drill a local address per synthetic service. The local plan
hands those addresses to Guardian in these variables, each the service's HTTP `invoke` address:

    GUARDIAN_GMAIL_URL   inbox to read, and where phishing is quarantined (a label, INBOX removed)
    GUARDIAN_STRIPE_URL  card charges to check for misuse
    GUARDIAN_SLACK_URL   where family alerts go (GUARDIAN_FAMILY_CHANNEL, default "family")

A variable that is not set keeps the local stand-in (data/*.json, outbox/), like every other integration.
Guardian never holds a Firedrill token; the address is all it gets.

The docs give the envelope (POST {"operation", "arguments", "idempotency_key"}, body passed through
unchanged) but not each service's operations. The names in OPS follow the real Gmail, Stripe and Slack
APIs. Confirm them with `firedrill tools catalog-operations <release-id> --service gmail` (and stripe,
slack) before the first drill; a wrong name comes back as 403 operation_not_declared.
"""
import base64
import json
import os
import re
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

ENV = {"gmail": "GUARDIAN_GMAIL_URL", "stripe": "GUARDIAN_STRIPE_URL", "slack": "GUARDIAN_SLACK_URL"}

OPS = {
    "gmail": {"list": "messages.list", "get": "messages.get", "modify": "messages.modify",
              "labels": "labels.list", "create_label": "labels.create"},
    "stripe": {"charges": "charges.list"},
    "slack": {"post": "chat.postMessage"},
}

QUARANTINE_LABEL = "Guardian/Quarantine"
RETRY_STATUSES = (409, 502, 503)


class Unavailable(Exception):
    """The synthetic service is down (a scripted outage) or kept failing."""


def configured(service):
    return bool(os.environ.get(ENV[service]))


def invoke(service, operation, arguments=None, idempotency_key=None, tries=3, opener=None):
    """One call to a synthetic service. Returns the response body as JSON.

    Retries 409/502/503 with the same idempotency key, as the docs ask. `opener` replaces urlopen in tests.
    """
    url = os.environ[ENV[service]]
    body = {"operation": operation, "arguments": arguments or {}}
    if idempotency_key:
        body["idempotency_key"] = idempotency_key
    data = json.dumps(body).encode()
    opener = opener or urllib.request.urlopen
    last = None
    for attempt in range(tries):
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        try:
            with opener(req, timeout=15) as resp:
                raw = resp.read()
            return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            detail = _error_code(e)
            if e.code not in RETRY_STATUSES or detail == "dependency_unavailable":
                if e.code == 503:
                    raise Unavailable("%s is unavailable (%s)" % (service, detail or e.code))
                raise
            last = detail or str(e.code)
            wait = e.headers.get("Retry-After") if e.headers else None
            time.sleep(min(float(wait), 5.0) if wait and wait.replace(".", "", 1).isdigit() else 0.5 * (attempt + 1))
    raise Unavailable("%s kept failing (%s)" % (service, last))


def _error_code(err):
    try:
        out = json.loads(err.read() or b"{}")
    except Exception:
        return None
    e = out.get("error", out)
    return e.get("code") if isinstance(e, dict) else e if isinstance(e, str) else None


# ---------- Gmail ----------

def _header(headers, name):
    return next((h.get("value", "") for h in headers or [] if h.get("name", "").lower() == name), "")


def _body_text(payload):
    """Plain text from a Gmail message payload (base64url parts), or an empty string."""
    if not payload:
        return ""
    parts = [payload] + list(payload.get("parts") or [])
    for p in parts:
        if p.get("mimeType", "text/plain").startswith("text/plain") and (p.get("body") or {}).get("data"):
            raw = p["body"]["data"]
            return base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)).decode("utf-8", "replace")
    for p in parts[1:]:
        text = _body_text(p) if p.get("parts") else ""
        if text:
            return text
    return ""


def _received(msg, headers):
    if msg.get("internalDate"):
        ts = int(msg["internalDate"]) / 1000
        return datetime.fromtimestamp(ts, tz=timezone.utc).replace(tzinfo=None).isoformat(timespec="seconds")
    if msg.get("received"):
        return msg["received"]
    date = _header(headers, "date")
    try:
        from email.utils import parsedate_to_datetime
        return parsedate_to_datetime(date).replace(tzinfo=None).isoformat(timespec="seconds")
    except Exception:
        return datetime.now().isoformat(timespec="seconds")


def message_from_gmail(msg):
    """A Gmail API message (or a flat one) in Guardian's inbox shape."""
    payload = msg.get("payload") or {}
    headers = payload.get("headers") or []
    sender = msg.get("from") or _header(headers, "from")
    sender = re.search(r"<([^>]+)>", sender).group(1) if "<" in sender else sender
    body = msg.get("body") if isinstance(msg.get("body"), str) else _body_text(payload) or msg.get("snippet", "")
    links = msg.get("links")
    if links is None:
        links = re.findall(r"https?://[^\s\"'<>)]+", body)
    return {"id": msg["id"], "from": sender.strip(), "received": _received(msg, headers),
            "subject": msg.get("subject") or _header(headers, "subject"), "body": body, "links": links}


def inbox(max_results=50):
    """The person's inbox from synthetic Gmail, in Guardian's shape."""
    listing = invoke("gmail", OPS["gmail"]["list"], {"userId": "me", "maxResults": max_results})
    out = []
    for item in listing.get("messages") or []:
        full = item if (item.get("payload") or item.get("subject")) else invoke(
            "gmail", OPS["gmail"]["get"], {"userId": "me", "id": item["id"], "format": "full"})
        out.append(message_from_gmail(full))
    return out


_label_ids = {}


def quarantine_label_id():
    url = os.environ[ENV["gmail"]]
    if url in _label_ids:
        return _label_ids[url]
    labels = invoke("gmail", OPS["gmail"]["labels"], {"userId": "me"}).get("labels") or []
    found = next((l["id"] for l in labels if l.get("name") == QUARANTINE_LABEL), None)
    if not found:
        made = invoke("gmail", OPS["gmail"]["create_label"],
                      {"userId": "me", "requestBody": {"name": QUARANTINE_LABEL}},
                      idempotency_key="guardian-label-quarantine")
        found = made.get("id", QUARANTINE_LABEL)
    _label_ids[url] = found
    return found


def quarantine(email_id):
    """Move one email out of the inbox into the quarantine label."""
    invoke("gmail", OPS["gmail"]["modify"],
           {"userId": "me", "id": email_id,
            "requestBody": {"addLabelIds": [quarantine_label_id()], "removeLabelIds": ["INBOX"]}},
           idempotency_key="guardian-quarantine-" + email_id)


# ---------- Stripe ----------

def charge_to_transaction(ch, profile):
    """A Stripe charge in Guardian's transaction shape. Amounts are in cents, `created` is unix time."""
    meta = ch.get("metadata") or {}
    last4 = ((ch.get("payment_method_details") or {}).get("card") or {}).get("last4") or meta.get("last4")
    card = meta.get("card") or next((c["id"] for c in profile["cards"] if c["last4"] == last4), "card-" + str(last4))
    merchant = (meta.get("merchant") or ch.get("calculated_statement_descriptor")
                or ch.get("statement_descriptor") or ch.get("description") or "Unknown merchant")
    date = (datetime.fromtimestamp(ch["created"], tz=timezone.utc).date().isoformat()
            if isinstance(ch.get("created"), (int, float)) else str(ch.get("created", ""))[:10])
    return {"id": ch["id"], "card": card, "merchant": merchant, "amount": round(ch["amount"] / 100.0, 2),
            "date": date}


def transactions(profile, limit=100):
    listing = invoke("stripe", OPS["stripe"]["charges"], {"limit": limit})
    return [charge_to_transaction(ch, profile) for ch in listing.get("data") or []
            if ch.get("status", "succeeded") == "succeeded" and not ch.get("refunded")]


# ---------- Slack ----------

def tell_family(text, key):
    channel = os.environ.get("GUARDIAN_FAMILY_CHANNEL", "family")
    invoke("slack", OPS["slack"]["post"], {"channel": channel, "text": text},
           idempotency_key="guardian-" + re.sub(r"[^A-Za-z0-9_-]", "-", key))
    return channel
