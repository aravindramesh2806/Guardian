"""Web Push: alerts that reach a phone or computer while Guardian's app is closed.

Needs HTTPS (or localhost) and, on iPhone, Guardian added to the Home Screen (iOS 16.4+). Each push is
encrypted end to end for that one device (aes128gcm); the push service (Apple, Google, Mozilla) only
carries it. A push says what kind of threat it is and who it came from (a number or sender address) so
the person can act at once; it never contains the message itself.

The VAPID key that signs pushes is created once in users/vapid_private.pem (owner-only), or set
VAPID_PRIVATE_KEY_FILE to keep it elsewhere. GUARDIAN_CONTACT is the contact push services may use
(a mailto: or https: address).
"""
import base64
import json
import os

from cryptography.hazmat.primitives import serialization
from py_vapid import Vapid02
from pywebpush import WebPushException, webpush


def _key_path():
    import core
    return os.environ.get("VAPID_PRIVATE_KEY_FILE") or os.path.join(core.USERS, "vapid_private.pem")


def _vapid():
    path = _key_path()
    if not os.path.exists(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        v = Vapid02()
        v.generate_keys()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(v.private_pem())
    return Vapid02.from_file(path)


def public_key():
    """The browser's applicationServerKey: the raw public point, base64url."""
    raw = _vapid().public_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def contact():
    c = os.environ.get("GUARDIAN_CONTACT") or "mailto:" + (os.environ.get("SMTP_USER") or "guardian@example.com")
    return c if c.startswith(("mailto:", "https:")) else "mailto:" + c


def send(subscription, title, body, data=None):
    """Returns "ok", "gone" (the device unsubscribed: forget it) or "error".

    `data` (which threat, which buttons) travels encrypted with the title and body."""
    _vapid()  # make sure the signing key exists
    try:
        webpush(subscription_info=subscription, data=json.dumps(dict(data or {}, title=title, body=body)),
                vapid_private_key=_key_path(),
                vapid_claims={"sub": contact()}, ttl=12 * 3600, timeout=10)
        return "ok"
    except WebPushException as e:
        code = getattr(getattr(e, "response", None), "status_code", None)
        return "gone" if code in (404, 410) else "error"
    except Exception:
        return "error"
