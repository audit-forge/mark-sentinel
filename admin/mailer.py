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


def _send(to: str, subject: str, body_text: str, body_html: str | None = None) -> bool:
    if not all([SMTP_HOST, SMTP_USER, SMTP_PASS, to]):
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
        msg["To"]      = to
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as s:
            s.ehlo()
            s.starttls()
            s.login(SMTP_USER, SMTP_PASS)
            s.send_message(msg)
        print(f"[mailer] sent to {to}: {subject}", flush=True)
        return True
    except Exception as e:
        print(f"[mailer] failed: {e}", flush=True)
        return False


def send_alert(subject: str, body_text: str, body_html: str | None = None) -> bool:
    return _send(ALERT_TO, subject, body_text, body_html)


def send_welcome_email(to: str, customer_name: str, login_url: str, temp_password: str) -> bool:
    subject = "[M.A.R.K. Sentinel] Your account is ready"
    body_text = f"""Welcome to M.A.R.K. Sentinel, {customer_name}!

Your account has been provisioned. Use the credentials below to sign in.

Login URL:  {login_url}
Email:      {to}
Password:   {temp_password}

Please change your password immediately after your first login.

If you have any questions, contact your account administrator.

— M.A.R.K. AI Systems
"""
    body_html = f"""
<div style="font-family:'Segoe UI',system-ui,sans-serif;background:#f0f4ff;padding:40px 0;min-height:100vh">
  <div style="max-width:520px;margin:0 auto;background:#ffffff;border-radius:12px;overflow:hidden;border:1px solid #ccd3e8;box-shadow:0 4px 24px rgba(26,47,90,0.12)">
    <div style="background:#0f1e3d;padding:28px 32px">
      <div style="font-size:22px;font-weight:800;color:#ffffff;letter-spacing:4px">
        M.A.R.K. <span style="color:#f5a623">SENTINEL</span>
      </div>
      <div style="font-size:12px;color:#8a9abf;letter-spacing:2px;margin-top:6px;text-transform:uppercase">
        Security Intelligence Platform
      </div>
    </div>
    <div style="padding:32px">
      <div style="font-size:20px;font-weight:700;color:#0a1428;margin-bottom:8px">Your account is ready</div>
      <div style="font-size:15px;color:#1e3060;margin-bottom:24px">Welcome, {customer_name}. Sign in with the credentials below.</div>
      <div style="background:#f7f9ff;border:1px solid #ccd3e8;border-radius:8px;padding:20px;margin-bottom:24px">
        <div style="margin-bottom:12px">
          <div style="font-size:12px;font-weight:700;color:#1e3060;text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px">Login URL</div>
          <a href="{login_url}" style="font-size:14px;color:#f5a623;text-decoration:none;font-weight:600">{login_url}</a>
        </div>
        <div style="margin-bottom:12px">
          <div style="font-size:12px;font-weight:700;color:#1e3060;text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px">Email</div>
          <div style="font-size:14px;color:#0a1428;font-family:monospace">{to}</div>
        </div>
        <div>
          <div style="font-size:12px;font-weight:700;color:#1e3060;text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px">Temporary Password</div>
          <div style="font-size:16px;color:#0a1428;font-family:monospace;font-weight:700;letter-spacing:2px">{temp_password}</div>
        </div>
      </div>
      <div style="background:#fff8e8;border:1px solid #f5a623;border-radius:8px;padding:14px;font-size:13px;color:#7a4800">
        <strong>Action required:</strong> Please change your password immediately after your first login.
      </div>
    </div>
    <div style="padding:20px 32px;border-top:1px solid #ccd3e8;font-size:12px;color:#5a6a8a">
      This message was sent by M.A.R.K. AI Systems. Do not reply to this email.
    </div>
  </div>
</div>
"""
    return _send(to, subject, body_text, body_html)
