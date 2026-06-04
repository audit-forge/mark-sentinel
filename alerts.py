"""
M.A.R.K. Sentinel — Alert delivery module.

Delivers alerts to Slack, email (SMTP), and generic webhooks.
Zero external dependencies — Python stdlib only.

Config file: alerts_config.json (sits next to server.py)
{
  "slack_webhook": "https://hooks.slack.com/services/...",
  "webhook_url":   "https://your-endpoint.com/alerts",
  "email": {
    "smtp_host": "smtp.gmail.com",
    "smtp_port": 587,
    "smtp_user": "you@gmail.com",
    "smtp_pass": "your-app-password",
    "from":      "sentinel@yourdomain.com",
    "to":        "security-team@yourdomain.com"
  },
  "triggers": {
    "new_critical":  true,
    "new_high":      true,
    "new_shadow_ai": true
  }
}

Gmail note: use an App Password (myaccount.google.com/apppasswords),
not your account password. Requires 2FA enabled on the account.
"""
import json
import logging
import smtplib
import time
import urllib.request
from email.mime.text import MIMEText
from pathlib import Path
from typing import Optional

log = logging.getLogger('sentinel.alerts')

_DEFAULT_TRIGGERS = {
    'new_critical':  True,
    'new_high':      True,
    'new_shadow_ai': True,
}
_PASS_MASK = '__set__'


# ── Config ────────────────────────────────────────────────────────────────────

def load_alert_config(path: Path) -> Optional[dict]:
    if not path.exists():
        return None
    try:
        cfg = json.loads(path.read_text(encoding='utf-8'))
        return cfg if isinstance(cfg, dict) else None
    except Exception as e:
        log.error('alert config load error: %s', e)
        return None


def load_alert_config_for_ui(path: Path) -> dict:
    """Load config with password masked for safe return to the browser."""
    cfg = load_alert_config(path) or {}
    result = {
        'slack_webhook':       cfg.get('slack_webhook', ''),
        'google_chat_webhook': cfg.get('google_chat_webhook', ''),
        'webhook_url':         cfg.get('webhook_url', ''),
        'email': {
            'smtp_host': cfg.get('email', {}).get('smtp_host', ''),
            'smtp_port': cfg.get('email', {}).get('smtp_port', 587),
            'smtp_user': cfg.get('email', {}).get('smtp_user', ''),
            'smtp_pass': _PASS_MASK if cfg.get('email', {}).get('smtp_pass') else '',
            'from':      cfg.get('email', {}).get('from', ''),
            'to':        cfg.get('email', {}).get('to', ''),
        },
        'triggers': {**_DEFAULT_TRIGGERS, 'device_offline': True, **cfg.get('triggers', {})},
    }
    return result


def save_alert_config(path: Path, new_data: dict, existing_path: Path) -> None:
    """Save alert config, preserving the SMTP password if masked placeholder sent."""
    existing = load_alert_config(existing_path) or {}
    email_new = new_data.get('email', {})
    email_existing = existing.get('email', {})

    saved_pass = email_existing.get('smtp_pass', '')
    incoming_pass = email_new.get('smtp_pass', '')
    if incoming_pass == _PASS_MASK:
        email_new['smtp_pass'] = saved_pass
    elif incoming_pass == '':
        email_new['smtp_pass'] = ''

    triggers_raw = new_data.get('triggers', {})
    clean = {
        'slack_webhook':       str(new_data.get('slack_webhook', '')).strip(),
        'google_chat_webhook': str(new_data.get('google_chat_webhook', '')).strip(),
        'webhook_url':         str(new_data.get('webhook_url', '')).strip(),
        'email': {
            'smtp_host': str(email_new.get('smtp_host', '')).strip(),
            'smtp_port': int(email_new.get('smtp_port', 587)),
            'smtp_user': str(email_new.get('smtp_user', '')).strip(),
            'smtp_pass': email_new.get('smtp_pass', ''),
            'from':      str(email_new.get('from', '')).strip(),
            'to':        str(email_new.get('to', '')).strip(),
        },
        'triggers': {
            'new_critical':    bool(triggers_raw.get('new_critical', True)),
            'new_high':        bool(triggers_raw.get('new_high', True)),
            'new_shadow_ai':   bool(triggers_raw.get('new_shadow_ai', True)),
            'device_offline':  bool(triggers_raw.get('device_offline', True)),
        },
    }
    path.write_text(json.dumps(clean, indent=2), encoding='utf-8')


# ── Alert firing ──────────────────────────────────────────────────────────────

def fire_alerts(report: dict, device_id: str, hostname: str,
                alert_cfg: dict, store=None) -> None:
    """Called after each new scan report is stored. Fires for new CRITICAL/HIGH findings."""
    triggers = {**_DEFAULT_TRIGGERS, **alert_cfg.get('triggers', {})}
    findings = report.get('findings', [])

    prev_fail_ids: set = set()
    if store is not None:
        try:
            prev = store.get_previous_report(device_id)
            if prev:
                prev_fail_ids = {f['check_id'] for f in prev.get('findings', [])
                                 if f.get('status') == 'FAIL'}
        except Exception as e:
            log.error('prev report lookup: %s', e)

    messages = []
    if triggers.get('new_critical'):
        for f in findings:
            if (f.get('status') == 'FAIL'
                    and f.get('severity', '').upper() == 'CRITICAL'
                    and f.get('check_id', '') not in prev_fail_ids):
                messages.append({
                    'event':    'new_critical_finding',
                    'severity': 'CRITICAL',
                    'device':   hostname,
                    'check_id': f.get('check_id', ''),
                    'title':    f.get('title', ''),
                })
    if triggers.get('new_high'):
        for f in findings:
            if (f.get('status') == 'FAIL'
                    and f.get('severity', '').upper() == 'HIGH'
                    and f.get('check_id', '') not in prev_fail_ids):
                messages.append({
                    'event':    'new_high_finding',
                    'severity': 'HIGH',
                    'device':   hostname,
                    'check_id': f.get('check_id', ''),
                    'title':    f.get('title', ''),
                })

    for msg in messages:
        _dispatch(alert_cfg, msg)
        log.info('alert fired: %s %s on %s', msg['severity'], msg['check_id'], hostname)


def fire_stale_device_alert(hostname: str, device_id: str,
                            hours_offline: float, alert_cfg: dict) -> None:
    """Called by the stale-device monitor when a device exceeds its silence threshold."""
    triggers = {**_DEFAULT_TRIGGERS, 'device_offline': True, **alert_cfg.get('triggers', {})}
    if not triggers.get('device_offline'):
        return
    _dispatch(alert_cfg, {
        'event':         'device_offline',
        'severity':      'HIGH',
        'device':        hostname,
        'device_id':     device_id,
        'hours_offline': round(hours_offline, 1),
    })
    log.info('device offline alert: %s (%s) — %.1fh silent', hostname, device_id, hours_offline)


def fire_shadow_alert(reporter_hostname: str, service: str,
                      host: str, alert_cfg: dict) -> None:
    """Called when a brand-new shadow AI asset is discovered for the first time."""
    triggers = {**_DEFAULT_TRIGGERS, **alert_cfg.get('triggers', {})}
    if not triggers.get('new_shadow_ai'):
        return
    _dispatch(alert_cfg, {
        'event':    'new_shadow_ai',
        'severity': 'HIGH',
        'device':   reporter_hostname,
        'service':  service,
        'host':     host,
    })
    log.info('shadow AI alert: %s at %s via %s', service, host, reporter_hostname)


def send_test_alert(alert_cfg: dict, channel: str) -> tuple[bool, str]:
    """Send a test message to a specific channel. Returns (ok, message)."""
    payload = {
        'event':    'test_alert',
        'severity': 'INFO',
        'device':   'sentinel-test',
        'check_id': 'TEST-001',
        'title':    'Alert configuration test — M.A.R.K. Sentinel alerts are working.',
    }
    if channel == 'slack':
        url = alert_cfg.get('slack_webhook', '').strip()
        if not url:
            return False, 'No Slack webhook URL configured'
        ok = _post_slack(url, _format_text(payload), payload)
        return ok, 'Test sent to Slack' if ok else 'Slack delivery failed — check the webhook URL'
    if channel == 'google_chat':
        url = alert_cfg.get('google_chat_webhook', '').strip()
        if not url:
            return False, 'No Google Chat webhook URL configured'
        ok = _post_google_chat(url, _format_text(payload))
        return ok, 'Test sent to Google Chat' if ok else 'Google Chat delivery failed — check the webhook URL'
    if channel == 'email':
        cfg = alert_cfg.get('email', {})
        if not cfg.get('smtp_host') or not cfg.get('to'):
            return False, 'Email not fully configured (smtp_host and to address required)'
        ok = _send_email(cfg, '[Sentinel] Test alert', _format_text(payload))
        return ok, 'Test email sent' if ok else 'Email delivery failed — check SMTP settings'
    if channel == 'webhook':
        url = alert_cfg.get('webhook_url', '').strip()
        if not url:
            return False, 'No webhook URL configured'
        ok = _post_webhook(url, payload)
        return ok, 'Test sent to webhook' if ok else 'Webhook delivery failed — check the URL'
    return False, f'Unknown channel: {channel}'


# ── Delivery backends ─────────────────────────────────────────────────────────

def _dispatch(alert_cfg: dict, payload: dict) -> None:
    slack_url   = alert_cfg.get('slack_webhook', '').strip()
    gchat_url   = alert_cfg.get('google_chat_webhook', '').strip()
    webhook_url = alert_cfg.get('webhook_url', '').strip()
    email_cfg   = alert_cfg.get('email', {})
    text        = _format_text(payload)
    if slack_url:
        _post_slack(slack_url, text, payload)
    if gchat_url:
        _post_google_chat(gchat_url, text)
    if webhook_url:
        _post_webhook(webhook_url, payload)
    if email_cfg.get('smtp_host') and email_cfg.get('to'):
        _send_email(email_cfg, _alert_subject(payload), text)


def _post_slack(webhook_url: str, text: str, payload: dict) -> bool:
    color = '#d73a49' if payload.get('severity') == 'CRITICAL' else '#e3b341'
    data = json.dumps({
        'attachments': [{
            'color':  color,
            'text':   text,
            'footer': 'M.A.R.K. Sentinel',
            'ts':     int(time.time()),
        }]
    }).encode()
    req = urllib.request.Request(
        webhook_url, data=data,
        headers={'Content-Type': 'application/json'},
        method='POST',
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return 200 <= r.status < 300
    except Exception as e:
        log.error('Slack POST failed: %s', e)
        return False


def _post_google_chat(webhook_url: str, text: str) -> bool:
    """Post a plain-text message to a Google Chat space via incoming webhook."""
    data = json.dumps({'text': text}).encode()
    req = urllib.request.Request(
        webhook_url, data=data,
        headers={'Content-Type': 'application/json'},
        method='POST',
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return 200 <= r.status < 300
    except Exception as e:
        log.error('Google Chat POST failed: %s', e)
        return False


def _post_webhook(url: str, payload: dict) -> bool:
    data = json.dumps({
        **payload,
        'timestamp': _now_iso(),
        'source':    'sentinel',
    }).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={'Content-Type': 'application/json', 'User-Agent': 'sentinel-alerts/1.0'},
        method='POST',
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return 200 <= r.status < 300
    except Exception as e:
        log.error('webhook POST failed: %s', e)
        return False


def _send_email(cfg: dict, subject: str, body: str) -> bool:
    host      = cfg.get('smtp_host', 'smtp.gmail.com')
    port      = int(cfg.get('smtp_port', 587))
    user      = cfg.get('smtp_user', '')
    password  = cfg.get('smtp_pass', '')
    from_addr = cfg.get('from', user)
    to_addr   = cfg.get('to', '')
    if not to_addr:
        return False
    msg            = MIMEText(body, 'plain')
    msg['Subject'] = subject
    msg['From']    = from_addr
    msg['To']      = to_addr
    try:
        with smtplib.SMTP(host, port, timeout=15) as smtp:
            smtp.ehlo()
            smtp.starttls()
            if user and password:
                smtp.login(user, password)
            smtp.sendmail(from_addr, [to_addr], msg.as_string())
        return True
    except Exception as e:
        log.error('email send failed: %s', e)
        return False


# ── Helpers ───────────────────────────────────────────────────────────────────

def _format_text(payload: dict) -> str:
    ev     = payload.get('event', '')
    device = payload.get('device', 'unknown')
    if ev == 'new_shadow_ai':
        return (f"Shadow AI Detected on {device}\n"
                f"Service: {payload.get('service', '')} at {payload.get('host', '')}\n"
                f"Review in the Sentinel Asset Inventory and approve or remove this asset.")
    if ev == 'device_offline':
        return (f"Device Offline: {device}\n"
                f"No check-in for {payload.get('hours_offline', '?')} hours.\n"
                f"Verify the agent is running and the device is reachable.")
    if ev == 'test_alert':
        return payload.get('title', 'Test alert from M.A.R.K. Sentinel')
    sev    = payload.get('severity', 'HIGH')
    prefix = 'CRITICAL Finding' if sev == 'CRITICAL' else 'HIGH Finding'
    return (f"{prefix} on {device}\n"
            f"{payload.get('check_id', '')} — {payload.get('title', '')}\n"
            f"Log in to Sentinel to view full details and remediation steps.")


def _alert_subject(payload: dict) -> str:
    ev     = payload.get('event', '')
    device = payload.get('device', 'unknown')
    if ev == 'new_shadow_ai':
        return f'[Sentinel] Shadow AI detected on {device}'
    if ev == 'device_offline':
        return f'[Sentinel] Device offline: {device} ({payload.get("hours_offline", "?")}h silent)'
    sev = payload.get('severity', 'HIGH')
    return f'[Sentinel] {sev}: {payload.get("check_id", "Finding")} on {device}'


def _now_iso() -> str:
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
