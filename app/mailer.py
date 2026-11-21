"""Sending email (sign-up codes). Standard SMTP, so any provider works.

    SMTP_HOST=smtp.gmail.com  SMTP_PORT=587  SMTP_USER=you@gmail.com  SMTP_PASSWORD=<Gmail app password>
    SMTP_FROM="Guardian <you@gmail.com>"

Port 465 uses SSL; anything else uses STARTTLS. A Gmail app password: Google Account > Security > 2-Step
Verification > App passwords.

Without SMTP settings (development only), the email is appended to users/dev_mail.log on this machine and
a note is printed. Nothing is sent anywhere.
"""
import os
import smtplib
import ssl
import sys
import time
from email.message import EmailMessage


def configured():
    return bool(os.environ.get("SMTP_HOST") and os.environ.get("SMTP_FROM"))


def _dev_log_path():
    import core
    return os.path.join(core.USERS, "dev_mail.log")


def send(to, subject, body):
    if not configured():
        path = _dev_log_path()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a") as f:
            f.write("--- %s\nTo: %s\nSubject: %s\n\n%s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), to, subject, body))
        sys.stderr.write("DEV: email to %s written to %s (set SMTP_* in .env to send real email)\n" % (to, path))
        return "dev-log"
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = os.environ["SMTP_FROM"], to, subject
    msg.set_content(body)
    host, port = os.environ["SMTP_HOST"], int(os.environ.get("SMTP_PORT", "587"))
    context = ssl.create_default_context()
    if port == 465:
        server = smtplib.SMTP_SSL(host, port, timeout=20, context=context)
    else:
        server = smtplib.SMTP(host, port, timeout=20)
        server.starttls(context=context)
    with server:
        if os.environ.get("SMTP_USER"):
            server.login(os.environ["SMTP_USER"], os.environ.get("SMTP_PASSWORD", ""))
        server.send_message(msg)
    return "sent"
