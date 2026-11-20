"""Gmail connector: Google sign-in (read-only), new-mail sync, and revocation.

Setup (PLAN.md and README.md have the clicks): a Google Cloud project with the Gmail API on, an OAuth
consent screen in Testing mode with your address as a test user, and a "Web application" OAuth client whose
redirect URI is <app origin>/oauth/google/callback. Put GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in .env.

What Guardian asks for: only gmail.readonly. It cannot send, delete, move or label mail with this scope, so
in Gmail mode Guardian runs in shadow mode: it says what it would have done and does nothing.

Tokens are stored encrypted (app/vault.py). Messages are cached encrypted and pruned after RETENTION_DAYS.
The Google endpoints are configurable so tests can point them at a fake Google.
"""
import base64
import hashlib
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from agent import firedrill  # noqa: E402  (message_from_gmail turns a Gmail API message into Guardian's shape)

SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
AUTH_URL = os.environ.get("GOOGLE_AUTH_URL", "https://accounts.google.com/o/oauth2/v2/auth")
TOKEN_URL = os.environ.get("GOOGLE_TOKEN_URL", "https://oauth2.googleapis.com/token")
REVOKE_URL = os.environ.get("GOOGLE_REVOKE_URL", "https://oauth2.googleapis.com/revoke")
API_URL = os.environ.get("GMAIL_API_URL", "https://gmail.googleapis.com/gmail/v1")
RETENTION_DAYS = int(os.environ.get("GUARDIAN_RETENTION_DAYS", "30"))
TOKENS, CACHE = "gmail_tokens.enc", "gmail_messages.enc"


class GmailError(Exception):
    pass


def configured():
    return bool(os.environ.get("GOOGLE_CLIENT_ID") and os.environ.get("GOOGLE_CLIENT_SECRET"))


def _b64u(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def auth_url(redirect_uri, login_hint=None):
    """Where to send the person to sign in with Google. Returns (url, state, code_verifier)."""
    if not configured():
        raise GmailError("Gmail isn't set up on this server yet (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET).")
    state, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(48)
    params = {"client_id": os.environ["GOOGLE_CLIENT_ID"], "redirect_uri": redirect_uri, "response_type": "code",
              "scope": SCOPE, "access_type": "offline", "prompt": "consent", "include_granted_scopes": "false",
              "state": state, "code_challenge": _b64u(hashlib.sha256(verifier.encode()).digest()),
              "code_challenge_method": "S256"}
    if login_hint:
        params["login_hint"] = login_hint
    return AUTH_URL + "?" + urllib.parse.urlencode(params), state, verifier


def _post_form(url, form):
    req = urllib.request.Request(url, data=urllib.parse.urlencode(form).encode(),
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        raise GmailError("Google said no (%d)" % e.code)
    except (urllib.error.URLError, OSError):
        raise GmailError("Couldn't reach Google")


def exchange_code(code, redirect_uri, verifier):
    """The code from Google's redirect, swapped for tokens. Refuses anything wider than read-only."""
    out = _post_form(TOKEN_URL, {"code": code, "client_id": os.environ["GOOGLE_CLIENT_ID"],
                                 "client_secret": os.environ["GOOGLE_CLIENT_SECRET"], "redirect_uri": redirect_uri,
                                 "grant_type": "authorization_code", "code_verifier": verifier})
    granted = set((out.get("scope") or SCOPE).split())
    if SCOPE not in granted:
        raise GmailError("Guardian needs permission to read your email. Please try again and allow it.")
    if not out.get("refresh_token"):
        raise GmailError("Google didn't give Guardian lasting access. Please try again.")
    return {"access_token": out["access_token"], "refresh_token": out["refresh_token"],
            "expires_at": time.time() + int(out.get("expires_in", 3600)) - 60, "scope": " ".join(sorted(granted))}


def _access_token(tokens):
    """A valid access token, refreshing it when needed. Returns (token, tokens_changed)."""
    if tokens["expires_at"] > time.time():
        return tokens["access_token"], False
    out = _post_form(TOKEN_URL, {"client_id": os.environ["GOOGLE_CLIENT_ID"],
                                 "client_secret": os.environ["GOOGLE_CLIENT_SECRET"],
                                 "refresh_token": tokens["refresh_token"], "grant_type": "refresh_token"})
    tokens["access_token"] = out["access_token"]
    tokens["expires_at"] = time.time() + int(out.get("expires_in", 3600)) - 60
    return tokens["access_token"], True


def _get(path, token, params=None):
    url = API_URL + path + ("?" + urllib.parse.urlencode(params) if params else "")
    req = urllib.request.Request(url, headers={"Authorization": "Bearer " + token})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        raise GmailError("Gmail said no (%d)" % e.code)
    except (urllib.error.URLError, OSError):
        raise GmailError("Couldn't reach Gmail")


def profile_email(tokens):
    token, _ = _access_token(tokens)
    return _get("/users/me/profile", token).get("emailAddress")


def sync(tokens, cache, max_new=50, now=None):
    """Fetch new messages from the last 2 days into the cache (id -> Guardian message).

    Returns (cache, tokens_changed, new_count). Messages already cached are never fetched again.
    """
    token, changed = _access_token(tokens)
    listing = _get("/users/me/messages", token, {"q": "newer_than:2d", "maxResults": max_new})
    new = 0
    for item in listing.get("messages") or []:
        if item["id"] in cache:
            continue
        full = _get("/users/me/messages/" + urllib.parse.quote(item["id"]), token, {"format": "full"})
        cache[item["id"]] = firedrill.message_from_gmail(full)
        new += 1
    return prune(cache, now), changed, new


def prune(cache, now=None):
    """Keep only messages received in the last RETENTION_DAYS days."""
    cutoff = ((now or datetime.now()) - timedelta(days=RETENTION_DAYS)).isoformat(timespec="seconds")
    return {k: m for k, m in cache.items() if (m.get("received") or "") >= cutoff}


def revoke(tokens):
    """Tell Google to cancel Guardian's access. Best effort: deletion goes ahead even if Google is unreachable."""
    try:
        _post_form(REVOKE_URL, {"token": tokens.get("refresh_token") or tokens.get("access_token")})
        return True
    except GmailError:
        return False
