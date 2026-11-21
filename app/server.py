"""Guardian web app: passkey sign-in, one-time setup, the home screen, and the background checker.

    .venv/bin/pip install -r app/requirements.txt
    .venv/bin/python app/server.py            # then open http://localhost:8800

Passkeys need a secure origin: http://localhost works for development (not 127.0.0.1). For a phone, serve
it over HTTPS on a real domain and set GUARDIAN_ORIGIN and GUARDIAN_RP_ID.

Security: sign-in is passkeys only (no passwords). Risky changes (approving a dispute or lock, turning on
"act for me", deleting everything) need a fresh passkey check in the last 5 minutes. Every POST must come
from our own origin with a JSON body; the session cookie is HttpOnly and SameSite=Strict.
"""
import base64
import hmac
import html
import json
import urllib.parse
import os
import secrets
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

if __name__ == "__main__":
    # Run directly: read .env (Persona secret, origin, mail and push settings) before any module reads the
    # environment, like the agent and the Persona sidecar do. Set variables still win. Tests import this
    # module and keep their own environment.
    from agent.run import load_env  # noqa: E402
    load_env()

import core  # noqa: E402
import demo  # noqa: E402
import gmail  # noqa: E402
from webauthn import (generate_authentication_options, generate_registration_options,  # noqa: E402
                      options_to_json, verify_authentication_response, verify_registration_response)
from webauthn.helpers.structs import (AuthenticatorSelectionCriteria, PublicKeyCredentialDescriptor,  # noqa: E402
                                      ResidentKeyRequirement, UserVerificationRequirement)

PORT = int(os.environ.get("GUARDIAN_PORT", "8800"))
ORIGIN = os.environ.get("GUARDIAN_ORIGIN", "http://localhost:%d" % PORT)
RP_ID = os.environ.get("GUARDIAN_RP_ID", "localhost")
STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
STEP_UP_SECONDS = 300
FLOW_SECONDS = 300
SESSION_SECONDS = 30 * 24 * 3600

PERSONA_URL = os.environ.get("GUARDIAN_PERSONA_URL", "http://127.0.0.1:8787")
WIDGET = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "persona", "node_modules", "@persona", "relay", "dist", "relay.umd.js")
VERIFY_CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; "
              "frame-src https://*.withpersona.com https://challenges.cloudflare.com; connect-src 'self'; "
              "frame-ancestors 'none'")

sessions = {}   # token -> {"uid", "created", "stepped_up_at"}
persona_flows = {}  # flow id -> {"uid", "session", "created"}
oauth_flows = {}    # state -> {"uid", "verifier", "created"}
REDIRECT_URI = ORIGIN + "/oauth/google/callback"
flows = {}      # flow id -> {"challenge", "purpose", "name", "user_id", "created", "uid"}
_state = threading.Lock()


def b64u(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64u(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _new_flow(**kw):
    fid = secrets.token_urlsafe(16)
    with _state:
        now = time.time()
        for k in [k for k, f in flows.items() if now - f["created"] > FLOW_SECONDS]:
            flows.pop(k, None)
        flows[fid] = dict(kw, created=now)
    return fid


def _take_flow(fid, purpose):
    with _state:
        flow = flows.pop(str(fid or ""), None)
    if not flow or flow["purpose"] != purpose or time.time() - flow["created"] > FLOW_SECONDS:
        raise core.AppError("That took too long or was already used. Please try again.")
    return flow


def _new_session(uid, stepped_up=True):
    token = secrets.token_urlsafe(32)
    with _state:
        sessions[token] = {"uid": uid, "created": time.time(), "stepped_up_at": time.time() if stepped_up else 0}
    return token


# ---------- passkey ceremonies ----------

signup_times = {}  # client address -> recent sign-up starts (simple abuse limit)
SIGNUPS_PER_HOUR = int(os.environ.get("GUARDIAN_SIGNUPS_PER_HOUR", "10"))


def _signup_allowed(ip):
    now = time.time()
    with _state:
        recent = [t for t in signup_times.get(ip, []) if now - t < 3600]
        if len(recent) >= SIGNUPS_PER_HOUR:
            signup_times[ip] = recent
            return False
        signup_times[ip] = recent + [now]
        return True


def register_begin(body, ip="?"):
    name = core._clean_name(body.get("name"))
    email = core.clean_email(body.get("email"))
    if core.email_in_use(email):
        raise core.AppError("That email already has a Guardian account. Sign in instead.")
    if not _signup_allowed(ip):
        raise core.AppError("Too many sign-ups from here. Please try again later.")
    user_id = secrets.token_bytes(16)
    opts = generate_registration_options(
        rp_id=RP_ID, rp_name="Guardian", user_name=name, user_id=user_id, user_display_name=name,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED, user_verification=UserVerificationRequirement.REQUIRED))
    fid = _new_flow(challenge=opts.challenge, purpose="register", name=name, email=email)
    return {"flow": fid, "options": json.loads(options_to_json(opts))}


def register_finish(body):
    flow = _take_flow(body.get("flow"), "register")
    try:
        v = verify_registration_response(credential=body.get("credential"), expected_challenge=flow["challenge"],
                                         expected_rp_id=RP_ID, expected_origin=ORIGIN, require_user_verification=True)
    except Exception:
        raise core.AppError("That passkey could not be checked. Please try again.")
    cred = {"id": b64u(v.credential_id), "public_key": b64u(v.credential_public_key), "sign_count": v.sign_count}
    uid = core.create_user(flow["name"], cred, flow["email"])
    core.issue_code(uid)
    return uid


def login_begin(uid=None):
    """Sign in (any of your passkeys) or, with `uid`, a fresh check for a risky change."""
    allow = None
    if uid:
        allow = [PublicKeyCredentialDescriptor(id=unb64u(c["id"])) for c in core.load(uid)["credentials"]]
    opts = generate_authentication_options(rp_id=RP_ID, allow_credentials=allow,
                                           user_verification=UserVerificationRequirement.REQUIRED)
    fid = _new_flow(challenge=opts.challenge, purpose="stepup" if uid else "login", uid=uid)
    return {"flow": fid, "options": json.loads(options_to_json(opts))}


def login_finish(body, purpose, session_uid=None):
    flow = _take_flow(body.get("flow"), purpose)
    credential = body.get("credential") or {}
    cred_id = str(credential.get("id") or "")
    uid = core.user_for_credential(cred_id)
    if not uid or (purpose == "stepup" and uid != session_uid):
        raise core.AppError("That passkey is not one we know for this account.")
    stored = core.credential(uid, cred_id)
    try:
        v = verify_authentication_response(credential=credential, expected_challenge=flow["challenge"],
                                           expected_rp_id=RP_ID, expected_origin=ORIGIN,
                                           credential_public_key=unb64u(stored["public_key"]),
                                           credential_current_sign_count=stored.get("sign_count", 0),
                                           require_user_verification=True)
    except Exception:
        raise core.AppError("That passkey could not be checked. Please try again.")
    core.bump_sign_count(uid, cred_id, v.new_sign_count)
    return uid


# ---------- Persona (through the local sidecar, persona/server.js) ----------

def _sidecar(path, body=None):
    import urllib.request
    secret = os.environ.get("GUARDIAN_SIDECAR_SECRET", "")
    if len(secret) < 16:
        raise core.AppError("Persona isn't set up on this computer yet.")
    req = urllib.request.Request(PERSONA_URL + path, data=json.dumps(body or {}).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "X-Guardian-Secret": secret})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # localhost: never through a proxy
    try:
        with opener.open(req, timeout=30) as r:
            return json.loads(r.read())
    except Exception:
        raise core.AppError("Couldn't reach the Persona check. Is the Persona sidecar running?")


def persona_begin(uid):
    out = _sidecar("/internal/session")
    fid = secrets.token_urlsafe(16)
    with _state:
        persona_flows[fid] = {"uid": uid, "session": out["sessionId"], "created": time.time()}
    return {"flow": fid, "accessToken": out["accessToken"]}


def persona_finish(uid, fid):
    with _state:
        flow = persona_flows.pop(str(fid or ""), None)
    if not flow or flow["uid"] != uid or time.time() - flow["created"] > 30 * 60:
        raise core.AppError("That check expired. Please start again.")
    result = _sidecar("/internal/result", {"sessionId": flow["session"]}).get("result")
    core.set_claim(uid, result)
    return result


# ---------- HTTP ----------

STATIC_TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
                ".css": "text/css; charset=utf-8", ".svg": "image/svg+xml",
                ".webmanifest": "application/manifest+json", ".png": "image/png"}


class Handler(BaseHTTPRequestHandler):
    server_version = "Guardian"

    def log_message(self, fmt, *args):
        if os.environ.get("GUARDIAN_QUIET") != "1":
            sys.stderr.write("%s %s\n" % (self.command, self.path.split("?")[0]))

    # -- helpers --
    def _send(self, code, body, ctype="application/json", cookie=None, csp=None, extra_cookie=None):
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", csp or
                         "default-src 'self'; img-src 'self' data:; style-src 'self'; frame-ancestors 'none'")
        if cookie is not None:
            secure = "; Secure" if ORIGIN.startswith("https://") else ""
            if cookie:
                self.send_header("Set-Cookie", "gsid=%s; HttpOnly; SameSite=Strict; Path=/; Max-Age=%d%s"
                                 % (cookie, SESSION_SECONDS, secure))
            else:
                self.send_header("Set-Cookie", "gsid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0%s" % secure)
        if extra_cookie:
            self.send_header("Set-Cookie", extra_cookie)
        self.end_headers()
        self.wfile.write(raw)

    def _oauth_cookie(self, state):
        """Ties a Google sign-in to the browser that started it. Lax, because a Strict cookie is not sent on
        Google's cross-site redirect back; scoped to the callback path and gone after 10 minutes."""
        secure = "; Secure" if ORIGIN.startswith("https://") else ""
        return "goauth=%s; HttpOnly; SameSite=Lax; Path=/oauth/google/callback; Max-Age=%d%s" % (
            state, 600 if state else 0, secure)

    def _cookie(self, name):
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == name:
                return v
        return ""

    def _redirect(self, url, extra_cookie=None):
        self.send_response(302)
        self.send_header("Location", url)
        if extra_cookie:
            self.send_header("Set-Cookie", extra_cookie)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _bounce(self, url):
        """Move on with a same-site navigation, so the Strict session cookie is sent again."""
        page = ('<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="0;url=%s">'
                '<title>Guardian</title><p>One moment…</p>' % html.escape(url, quote=True))
        self._send(200, page.encode(), STATIC_TYPES[".html"], extra_cookie=self._oauth_cookie(""))

    def _session(self):
        for part in (self.headers.get("Cookie") or "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "gsid":
                with _state:
                    s = sessions.get(v)
                if s and time.time() - s["created"] < SESSION_SECONDS:
                    return v, s
        return None, None

    def _client_ip(self):
        # Behind a tunnel every request comes from 127.0.0.1: trust the tunnel's header only when told to.
        if os.environ.get("GUARDIAN_TRUST_PROXY") == "1":
            fwd = self.headers.get("CF-Connecting-IP") or (self.headers.get("X-Forwarded-For") or "").split(",")[0]
            if fwd.strip():
                return fwd.strip()
        return self.client_address[0]

    def _body(self):
        if self.headers.get("Origin") != ORIGIN:
            raise PermissionError("bad origin")
        if not (self.headers.get("Content-Type") or "").startswith("application/json"):
            raise PermissionError("json only")
        length = int(self.headers.get("Content-Length") or 0)
        if length > 64 * 1024:
            raise PermissionError("too large")
        return json.loads(self.rfile.read(length) or b"{}")

    # -- static --
    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/api/me":
            _, s = self._session()
            demo_on = demo.enabled(ORIGIN)
            if not s:
                return self._send(200, {"signed_in": False, "demo_login": demo_on})
            try:
                meta = core.load(s["uid"])
            except core.AppError:
                return self._send(200, {"signed_in": False, "demo_login": demo_on}, cookie="")
            return self._send(200, {"signed_in": True, "name": meta["name"], "setup_done": meta["setup_done"],
                                    "demo": bool(meta.get("demo_username")), "demo_login": demo_on,
                                    "email": meta.get("email"), "email_verified": bool(meta.get("email_verified")),
                                    "stepped_up": time.time() - s["stepped_up_at"] < STEP_UP_SECONDS,
                                    # The setup screens show whether the Persona check is done and Gmail is offered.
                                    "verified": core.verification(s["uid"]), "gmail_available": gmail.configured()})
        if path == "/api/feed":
            _, s = self._session()
            if not s:
                return self._send(401, {"error": "Please sign in."})
            if not core.load(s["uid"]).get("email_verified"):
                return self._send(403, {"error": "Please confirm your email first.", "verify_email": True})
            return self._send(200, core.feed(s["uid"]))
        if path == "/api/push/key":
            try:
                import push
                return self._send(200, {"key": push.public_key()})
            except ImportError:
                return self._send(400, {"error": "Alerts aren't set up on this server."})
        if path == "/oauth/google/start":
            _, s = self._session()
            if not s:
                return self._redirect("/")
            try:
                url, state, verifier = gmail.auth_url(REDIRECT_URI)
            except gmail.GmailError as e:
                return self._redirect("/?gmail_error=" + urllib.parse.quote(str(e)))
            with _state:
                now = time.time()
                for k in [k for k, f in oauth_flows.items() if now - f["created"] > 600]:
                    oauth_flows.pop(k, None)
                oauth_flows[state] = {"uid": s["uid"], "verifier": verifier, "created": now}
            return self._redirect(url, extra_cookie=self._oauth_cookie(state))
        if path == "/oauth/google/callback":
            # Google sends the person back here. The Strict session cookie is not sent on this cross-site
            # return, so the one-time `state` (made by their own session) says who it is.
            # The state must also match the cookie set in the browser that started this sign-in. Without that,
            # someone could start a sign-in from their own account and get another person to finish it,
            # linking that person's Gmail to their account (OAuth login CSRF).
            q = urllib.parse.parse_qs(self.path.partition("?")[2])
            state = (q.get("state") or [""])[0]
            same_browser = bool(state) and hmac.compare_digest(self._cookie("goauth").encode(), state.encode())
            with _state:
                flow = oauth_flows.pop(state, None) if same_browser else None
            if not flow or time.time() - flow["created"] > 600:
                return self._bounce("/?gmail_error=" + urllib.parse.quote("That sign-in expired. Please try again."))
            if q.get("error") or not q.get("code"):
                return self._bounce("/?gmail_error=" + urllib.parse.quote("Gmail wasn't connected."))
            try:
                tokens = gmail.exchange_code(q["code"][0], REDIRECT_URI, flow["verifier"])
                core.connect_gmail(flow["uid"], tokens)
                core.run_for(flow["uid"])
            except (gmail.GmailError, core.AppError) as e:
                return self._bounce("/?gmail_error=" + urllib.parse.quote(str(e)))
            return self._bounce("/?gmail=connected")
        if path == "/privacy":
            with open(os.path.join(STATIC, "privacy.html"), "rb") as f:
                return self._send(200, f.read(), STATIC_TYPES[".html"])
        if path == "/verify":
            with open(os.path.join(STATIC, "verify.html"), "rb") as f:
                return self._send(200, f.read(), STATIC_TYPES[".html"], csp=VERIFY_CSP)
        if path == "/persona-relay.js":
            if not os.path.isfile(WIDGET):
                return self._send(404, {"error": "Run npm install in persona/ first."})
            with open(WIDGET, "rb") as f:
                return self._send(200, f.read(), STATIC_TYPES[".js"])
        name = "index.html" if path in ("/", "/index.html") else path.lstrip("/")
        full = os.path.normpath(os.path.join(STATIC, name))
        if not full.startswith(STATIC + os.sep) or not os.path.isfile(full):
            return self._send(404, {"error": "not found"})
        with open(full, "rb") as f:
            self._send(200, f.read(), STATIC_TYPES.get(os.path.splitext(full)[1], "application/octet-stream"))

    # -- API --
    def do_POST(self):
        path = self.path.split("?")[0]
        try:
            body = self._body()
        except (PermissionError, ValueError):
            return self._send(403, {"error": "Request refused."})
        token, s = self._session()
        try:
            if path == "/api/register/begin":
                return self._send(200, register_begin(body, self._client_ip()))
            if path == "/api/register/finish":
                uid = register_finish(body)
                return self._send(200, {"ok": True}, cookie=_new_session(uid))
            if path == "/api/login/begin":
                return self._send(200, login_begin())
            if path == "/api/login/finish":
                uid = login_finish(body, "login")
                return self._send(200, {"ok": True}, cookie=_new_session(uid))
            if path == "/api/demo/login":
                # Demo account only, on localhost only, and only with GUARDIAN_DEMO_LOGIN=1 (app/demo.py).
                if not demo.enabled(ORIGIN):
                    return self._send(404, {"error": "not found"})
                uid = demo.login(body.get("username"), body.get("pin"))
                return self._send(200, {"ok": True}, cookie=_new_session(uid))
            if not s:
                return self._send(401, {"error": "Please sign in."})
            uid = s["uid"]
            if path == "/api/logout":
                with _state:
                    sessions.pop(token, None)
                return self._send(200, {"ok": True}, cookie="")
            if path == "/api/stepup/begin":
                return self._send(200, login_begin(uid))
            if path == "/api/stepup/finish":
                login_finish(body, "stepup", uid)
                with _state:
                    s["stepped_up_at"] = time.time()
                return self._send(200, {"ok": True})
            if path == "/api/stepup/pin":
                # The demo account has no passkey: its PIN confirms risky changes instead.
                if not demo.enabled(ORIGIN):
                    return self._send(404, {"error": "not found"})
                demo.confirm(uid, body.get("pin"))
                with _state:
                    s["stepped_up_at"] = time.time()
                return self._send(200, {"ok": True})
            if path == "/api/email/verify":
                core.verify_code(uid, body.get("code"))
                return self._send(200, {"ok": True})
            if path == "/api/email/resend":
                core.issue_code(uid)
                return self._send(200, {"ok": True})
            if not core.load(uid).get("email_verified") and path != "/api/delete":
                return self._send(403, {"error": "Please confirm your email first.", "verify_email": True})
            stepped_up = time.time() - s["stepped_up_at"] < STEP_UP_SECONDS
            needs_step_up = path in ("/api/approve", "/api/already-done", "/api/delete", "/api/gmail/disconnect",
                                    "/api/family/invite") or (
                path in ("/api/mode", "/api/setup") and body.get("mode") == "act" and core.load(uid)["mode"] != "act")
            if needs_step_up and not stepped_up:
                return self._send(403, {"error": "Please confirm it's you first.", "step_up": True})
            if path == "/api/setup":
                core.setup(uid, body.get("who"), body.get("protected_name"), body.get("family_name"),
                           body.get("family_phone"), body.get("mode"), body.get("senior"))
                core.run_for(uid)
                return self._send(200, {"ok": True})
            if path == "/api/persona/begin":
                return self._send(200, persona_begin(uid))
            if path == "/api/persona/finish":
                return self._send(200, {"result": persona_finish(uid, body.get("flow"))})
            if path == "/api/push/subscribe":
                core.add_push(uid, body.get("subscription"))
                sent = core.notify(uid, "Guardian", "Alerts are on for this device.")
                return self._send(200, {"ok": True, "test_sent": sent})
            if path == "/api/accounts":
                core.set_accounts(uid, body.get("accounts") or [])
                return self._send(200, core.feed(uid))
            if path == "/api/gmail/disconnect":
                core.disconnect_gmail(uid)
                return self._send(200, core.feed(uid))
            if path == "/api/family/invite":
                core.send_invite(uid)
                return self._send(200, core.feed(uid))
            if path == "/api/family/yes":
                core.family_said_yes(uid)
                return self._send(200, {"ok": True})
            if path == "/api/test-alert":
                return self._send(200, core.test_alert(uid))
            if path == "/api/check-now":
                core.run_for(uid)
                return self._send(200, core.feed(uid))
            if path == "/api/already-done":
                core.already_done(uid, str(body.get("key") or ""))
                return self._send(200, core.feed(uid))
            if path == "/api/approve":
                core.approve(uid, str(body.get("key") or ""))
                return self._send(200, core.feed(uid))
            if path == "/api/real":
                undone = core.mark_real(uid, str(body.get("threat") or ""))
                return self._send(200, {"undone": undone, "feed": core.feed(uid)})
            if path == "/api/scam":
                # Only records the person's answer. Each fix still needs its own yes (and Face ID) via /api/approve.
                core.confirm_scam(uid, str(body.get("threat") or ""))
                return self._send(200, core.feed(uid))
            if path == "/api/pause":
                core.set_paused(uid, bool(body.get("paused")))
                return self._send(200, core.feed(uid))
            if path == "/api/mode":
                core.set_mode(uid, body.get("mode"))
                return self._send(200, core.feed(uid))
            if path == "/api/delete":
                core.delete_user(uid)
                with _state:
                    for k in [k for k, v in sessions.items() if v["uid"] == uid]:
                        sessions.pop(k, None)
                return self._send(200, {"ok": True}, cookie="")
            return self._send(404, {"error": "not found"})
        except core.AppError as e:
            return self._send(400, {"error": str(e)})
        except Exception as e:  # never show internals to the page
            sys.stderr.write("error on %s: %s: %s\n" % (path, type(e).__name__, e))
            return self._send(500, {"error": "Something went wrong. Please try again."})


def serve(port=PORT, worker=True):
    stop = threading.Event()
    if worker:
        threading.Thread(target=core.worker_loop, args=(stop,), daemon=True).start()
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    return httpd, stop


if __name__ == "__main__":
    httpd, stop = serve()
    print("Guardian on %s (checks every %ds)" % (ORIGIN, core.CHECK_EVERY))
    if demo.enabled(ORIGIN):
        demo.ensure_user()
        print("Demo sign-in is on for username %r (PIN from GUARDIAN_DEMO_PIN, see app/demo.py)" % demo.username())
    elif os.environ.get("GUARDIAN_DEMO_LOGIN") == "1":
        print("Demo sign-in stays off: it only works when the app runs on localhost.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        stop.set()
