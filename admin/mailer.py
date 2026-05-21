import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
ALERT_FROM = os.environ.get("ALERT_FROM", SMTP_USER)
ALERT_TO   = os.environ.get("ALERT_TO", "")


def send_alert(subject: str, body_text: str, body_html: str | None = None) -> bool:
    if not all([SMTP_HOST, SMTP_USER, SMTP_PASS, ALERT_TO]):
        print(f"[mailer] SMTP not configured — skipping: {subject}", flush=True)
        return False
    try:
        if body_html:
            msg = MIMEMultipart("alternative")
            msg.attach(MIMEText(body_text, "plain"))
            msg.attach(MIMEText(body_html, "html"))
        else:
            msg = MIMEText(body_text, "plain")
        msg["Subject"] = subject
        msg["From"]    = ALERT_FROM
        msg["To"]      = ALERT_TO
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as s:
            s.ehlo()
            s.starttls()
            s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
        print(f"[mailer] sent: {subject}", flush=True)
        return True
    except Exception as e:
        print(f"[mailer] failed: {e}", flush=True)
        return False
