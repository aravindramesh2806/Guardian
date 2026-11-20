"""Firedrill: run Guardian against synthetic Gmail, Stripe and Slack instead of the files in data/.

Firedrill (docs.firedrill.run) gives each drill a local address per synthetic service. The local plan
hands those addresses to Guardian in these variables, each the service's HTTP `invoke` address:

    GUARDIAN_GMAIL_URL   inbox to read, and where phishing is quarantined (a label, INBOX removed)
    GUARDIAN_STRIPE_URL  card charges to check for misuse
    GUARDIAN_SLACK_URL   where family alerts go (GUARDIAN_FAMILY_CHANNEL, default "family")

A variable that is not set keeps the local stand-in (data/*.json, outbox/), like every other integration.
Guardian never holds a Firedrill token; the address is all it gets.

Each call is POST {"operation", "arguments", "idempotency_key"}; the body comes back unchanged. Firedrill's
Gmail, Stripe and Slack copy the real REST APIs (checked 2026-11-20 with `firedrill tools
catalog-operations`: Gmail 1.0.2, Stripe 1.0.2, Slack 1.0.3), so arguments are flat: path values
(userId, id) sit next to the body or query fields.
"""
import base64
import json
import os
import re
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone

ENV = {"gmail": "GUARDIAN_GMAIL_URL", "stripe": "GUARDIAN_STRIPE_URL", "slack": "GUARDIAN_SLACK_URL"}

OPS = {
    "gmail": {"list": "messages.list", "get": "messages.get", "modify": "messages.modify",
              "labels": "labels.list", "create_label": "labels.create"},
    "stripe": {"charges": "charges.list"},
    "slack": {"post": "chat.postMessage", "channels": "conversations.list"},
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
                      {"userId": "me", "name": QUARANTINE_LABEL},
                      idempotency_key="guardian-label-quarantine")
        found = made.get("id", QUARANTINE_LABEL)
    _label_ids[url] = found
    return found


def quarantine(email_id):
    """Move one email out of the inbox into the quarantine label."""
    invoke("gmail", OPS["gmail"]["modify"],
           {"userId": "me", "id": email_id, "addLabelIds": [quarantine_label_id()], "removeLabelIds": ["INBOX"]},
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

def channel_id(name):
    """Slack posts need a channel id; find it by name, or use the value as given if it already is one."""
    name = name.lstrip("#")
    listing = invoke("slack", OPS["slack"]["channels"], {"types": "public_channel,private_channel", "limit": 200})
    return next((c["id"] for c in listing.get("channels") or [] if c.get("name") == name), name)


def tell_family(text, key):
    name = os.environ.get("GUARDIAN_FAMILY_CHANNEL", "family")
    out = invoke("slack", OPS["slack"]["post"], {"channel": channel_id(name), "text": text,
                                                 "client_msg_id": str(uuid.uuid5(uuid.NAMESPACE_URL, "guardian:" + key))},
                 idempotency_key="guardian-" + re.sub(r"[^A-Za-z0-9_-]", "-", key))
    if out.get("ok") is False:
        raise RuntimeError("Slack refused the message (%s)" % out.get("error"))
    return "#" + name
