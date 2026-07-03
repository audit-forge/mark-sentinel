"""
M.A.R.K. Sentinel — Alert delivery module.

Delivers alerts to Slack, Google Chat, Microsoft Teams, email (SMTP),
and generic webhooks. Zero external dependencies — Python stdlib only.

Config file: alerts_config.json (sits next to server.py)
{
  "slack_webhook":  "https://hooks.slack.com/services/...",
  "gchat_webhook":  "https://chat.googleapis.com/v1/spaces/.../messages?key=...",
  "teams_webhook":  "https://yourorg.webhook.office.com/webhookb2/...",
  "webhook_url":    "https://your-endpoint.com/alerts",
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

Google Chat: Space → Apps & integrations → Webhooks → Add webhook.
Teams: Channel → Connectors → Incoming Webhook → configure → copy URL.
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
    'new_critical':         True,
    'new_high':             True,
    'new_shadow_ai':        True,
    'alert_unapproved_only': False,
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
    """Load config with password/secret masked for safe return to the browser."""
    cfg = load_alert_config(path) or {}
    psa_raw = cfg.get('psa', {})
    cw  = psa_raw.get('connectwise', {})
    at  = psa_raw.get('autotask', {})
    hp  = psa_raw.get('halopsa', {})
    result = {
        'slack_webhook':  cfg.get('slack_webhook', ''),
        'gchat_webhook':  cfg.get('gchat_webhook', ''),
        'teams_webhook':  cfg.get('teams_webhook', ''),
        'webhook_url':    cfg.get('webhook_url', ''),
        'email': {
            'smtp_host': cfg.get('email', {}).get('smtp_host', ''),
            'smtp_port': cfg.get('email', {}).get('smtp_port', 587),
            'smtp_user': cfg.get('email', {}).get('smtp_user', ''),
            'smtp_pass': _PASS_MASK if cfg.get('email', {}).get('smtp_pass') else '',
            'from':      cfg.get('email', {}).get('from', ''),
            'to':        cfg.get('email', {}).get('to', ''),
        },
        'psa': {
            'provider': psa_raw.get('provider', ''),
            'connectwise': {
                'site':          cw.get('site', ''),
                'company_id':    cw.get('company_id', ''),
                'public_key':    cw.get('public_key', ''),
                'private_key':   _PASS_MASK if cw.get('private_key') else '',
                'client_id':     cw.get('client_id', ''),
                'service_board': cw.get('service_board', ''),
                'company_name':  cw.get('company_name', ''),
            },
            'autotask': {
                'zone':        at.get('zone', 'webservices2'),
                'username':    at.get('username', ''),
                'api_key':     _PASS_MASK if at.get('api_key') else '',
                'account_id':  at.get('account_id', ''),
                'queue_id':    at.get('queue_id', ''),
                'priority_id': at.get('priority_id', 1),
            },
            'halopsa': {
                'tenant':         hp.get('tenant', ''),
                'client_id':      hp.get('client_id', ''),
                'client_secret':  _PASS_MASK if hp.get('client_secret') else '',
                'ticket_type_id': hp.get('ticket_type_id', 1),
                'priority_id':    hp.get('priority_id', 1),
            },
        },
        'triggers': {**_DEFAULT_TRIGGERS, **cfg.get('triggers', {})},
    }
    return result


def save_alert_config(path: Path, new_data: dict, existing_path: Path) -> None:
    """Save alert config, preserving masked secrets (SMTP password, PSA keys)."""
    existing   = load_alert_config(existing_path) or {}
    email_new  = new_data.get('email', {})
    email_old  = existing.get('email', {})
    psa_new    = new_data.get('psa', {})
    psa_old    = existing.get('psa', {})
    cw_new     = psa_new.get('connectwise', {})
    cw_old     = psa_old.get('connectwise', {})
    at_new     = psa_new.get('autotask', {})
    at_old     = psa_old.get('autotask', {})
    hp_new     = psa_new.get('halopsa', {})
    hp_old     = psa_old.get('halopsa', {})

    def _restore(incoming, saved):
        return saved if incoming == _PASS_MASK else (incoming or '')

    triggers_raw = new_data.get('triggers', {})
    clean = {
        'slack_webhook':  str(new_data.get('slack_webhook', '')).strip(),
        'gchat_webhook':  str(new_data.get('gchat_webhook', '')).strip(),
        'teams_webhook':  str(new_data.get('teams_webhook', '')).strip(),
        'webhook_url':    str(new_data.get('webhook_url', '')).strip(),
        'email': {
            'smtp_host': str(email_new.get('smtp_host', '')).strip(),
            'smtp_port': int(email_new.get('smtp_port', 587)),
            'smtp_user': str(email_new.get('smtp_user', '')).strip(),
            'smtp_pass': _restore(email_new.get('smtp_pass', ''), email_old.get('smtp_pass', '')),
            'from':      str(email_new.get('from', '')).strip(),
            'to':        str(email_new.get('to', '')).strip(),
        },
        'psa': {
            'provider': str(psa_new.get('provider', '')).strip(),
            'connectwise': {
                'site':          str(cw_new.get('site', '')).strip(),
                'company_id':    str(cw_new.get('company_id', '')).strip(),
                'public_key':    str(cw_new.get('public_key', '')).strip(),
                'private_key':   _restore(cw_new.get('private_key', ''), cw_old.get('private_key', '')),
                'client_id':     str(cw_new.get('client_id', '')).strip(),
                'service_board': str(cw_new.get('service_board', '')).strip(),
                'company_name':  str(cw_new.get('company_name', '')).strip(),
            },
            'autotask': {
                'zone':        str(at_new.get('zone', 'webservices2')).strip(),
                'username':    str(at_new.get('username', '')).strip(),
                'api_key':     _restore(at_new.get('api_key', ''), at_old.get('api_key', '')),
                'account_id':  at_new.get('account_id', ''),
                'queue_id':    at_new.get('queue_id', ''),
                'priority_id': int(at_new.get('priority_id', 1)),
            },
            'halopsa': {
                'tenant':         str(hp_new.get('tenant', '')).strip(),
                'client_id':      str(hp_new.get('client_id', '')).strip(),
                'client_secret':  _restore(hp_new.get('client_secret', ''), hp_old.get('client_secret', '')),
                'ticket_type_id': int(hp_new.get('ticket_type_id', 1)),
                'priority_id':    int(hp_new.get('priority_id', 1)),
            },
        },
        'triggers': {
            'new_critical':          bool(triggers_raw.get('new_critical', True)),
            'new_high':              bool(triggers_raw.get('new_high', True)),
            'new_shadow_ai':         bool(triggers_raw.get('new_shadow_ai', True)),
            'alert_unapproved_only': bool(triggers_raw.get('alert_unapproved_only', False)),
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
        if store is not None:
            try:
                if store.was_alert_recently_fired(msg['event'], hostname, msg.get('check_id', '')):
                    log.info('alert suppressed (24h cooldown): %s %s on %s',
                             msg['severity'], msg.get('check_id', ''), hostname)
                    continue
            except Exception as e:
                log.error('alert dedup check error: %s', e)
        fired = _dispatch(alert_cfg, msg)
        log.info('alert fired: %s %s on %s', msg['severity'], msg['check_id'], hostname)
        if store is not None:
            try:
                store.log_alert_event(
                    event_type=msg['event'],
                    severity=msg['severity'],
                    device=hostname,
                    check_id=msg.get('check_id', ''),
                    title=msg.get('title', ''),
                    channels=', '.join(fired),
                )
            except Exception as e:
                log.error('alert event log error: %s', e)


def fire_shadow_alert(reporter_hostname: str, service: str,
                      host: str, alert_cfg: dict, source: str = 'network',
                      store=None) -> None:
    """Called when a brand-new unapproved shadow AI asset is discovered."""
    triggers = {**_DEFAULT_TRIGGERS, **alert_cfg.get('triggers', {})}
    if not triggers.get('new_shadow_ai'):
        return
    if store is not None:
        try:
            if store.was_alert_recently_fired('new_shadow_ai', reporter_hostname, service):
                log.info('shadow AI alert suppressed (24h cooldown): %s on %s', service, reporter_hostname)
                return
        except Exception as e:
            log.error('alert dedup check error: %s', e)
    fired = _dispatch(alert_cfg, {
        'event':    'new_shadow_ai',
        'severity': 'HIGH',
        'device':   reporter_hostname,
        'service':  service,
        'host':     host,
        'source':   source,
    })
    log.info('shadow AI alert: %s at %s via %s (source: %s)', service, host, reporter_hostname, source)
    if store is not None:
        try:
            store.log_alert_event(
                event_type='new_shadow_ai',
                severity='HIGH',
                device=reporter_hostname,
                service=service,
                host=host,
                source=source,
                channels=', '.join(fired),
            )
        except Exception as e:
            log.error('alert event log error: %s', e)


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
    if channel == 'gchat':
        url = alert_cfg.get('gchat_webhook', '').strip()
        if not url:
            return False, 'No Google Chat webhook URL configured'
        ok = _post_gchat(url, _format_text(payload))
        return ok, 'Test sent to Google Chat' if ok else 'Google Chat delivery failed — check the webhook URL'
    if channel == 'teams':
        url = alert_cfg.get('teams_webhook', '').strip()
        if not url:
            return False, 'No Teams webhook URL configured'
        ok = _post_teams(url, _format_text(payload))
        return ok, 'Test sent to Microsoft Teams' if ok else 'Teams delivery failed — check the webhook URL'
    return False, f'Unknown channel: {channel}'


# ── Delivery backends ─────────────────────────────────────────────────────────

def send_test_psa(alert_cfg: dict) -> tuple[bool, str]:
    """Test PSA connectivity. Returns (ok, message)."""
    psa_cfg = alert_cfg.get('psa', {})
    if not psa_cfg.get('provider'):
        return False, 'No PSA provider configured'
    try:
        from connectors.psa_connector import test_connection
        return test_connection(psa_cfg)
    except Exception as e:
        return False, f'PSA test failed: {e}'


def _dispatch(alert_cfg: dict, payload: dict) -> list[str]:
    """Deliver alert to all configured channels. Returns list of channel names fired."""
    slack_url   = alert_cfg.get('slack_webhook', '').strip()
    gchat_url   = alert_cfg.get('gchat_webhook', '').strip()
    teams_url   = alert_cfg.get('teams_webhook', '').strip()
    webhook_url = alert_cfg.get('webhook_url', '').strip()
    email_cfg   = alert_cfg.get('email', {})
    psa_cfg     = alert_cfg.get('psa', {})
    text        = _format_text(payload)
    fired: list[str] = []
    if slack_url:
        _post_slack(slack_url, text, payload)
        fired.append('slack')
    if gchat_url:
        _post_gchat(gchat_url, text)
        fired.append('google_chat')
    if teams_url:
        _post_teams(teams_url, text)
        fired.append('teams')
    if webhook_url:
        _post_webhook(webhook_url, payload)
        fired.append('webhook')
    if email_cfg.get('smtp_host') and email_cfg.get('to'):
        _send_email(email_cfg, _alert_subject(payload), text)
        fired.append('email')
    if psa_cfg.get('provider') and payload.get('event', '').startswith('new_'):
        _create_psa_ticket(psa_cfg, payload)
        fired.append(f'psa_{psa_cfg["provider"]}')
    return fired


def _create_psa_ticket(psa_cfg: dict, payload: dict) -> None:
    try:
        from connectors.psa_connector import create_ticket
        finding = {
            'check_id':    payload.get('check_id', ''),
            'title':       payload.get('title', ''),
            'severity':    payload.get('severity', 'HIGH'),
            'description': payload.get('title', ''),
        }
        hostname = payload.get('device', 'Unknown')
        ok, msg = create_ticket(psa_cfg, finding, hostname)
        if ok:
            log.info('PSA ticket created: %s', msg)
        else:
            log.error('PSA ticket creation failed: %s', msg)
    except Exception as e:
        log.error('PSA dispatch error: %s', e)


def _post_slack(webhook_url: str, text: str, payload: dict) -> bool:
    color = '#d73a49' if payload.get('severity') == 'CRITICAL' else '#e3b341'
    lines = text.split('\n', 1)
    title = lines[0]
    body  = lines[1] if len(lines) > 1 else ''
    data = json.dumps({
        'attachments': [{
            'color':     color,
            'title':     title,
            'text':      body,
            'footer':    'RiskRaven: Arckon',
            'ts':        int(time.time()),
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


def _post_gchat(url: str, text: str) -> bool:
    data = json.dumps({'text': text}).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={'Content-Type': 'application/json'},
        method='POST',
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return 200 <= r.status < 300
    except Exception as e:
        log.error('Google Chat POST failed: %s', e)
        return False


def _post_teams(url: str, text: str) -> bool:
    lines = text.split('\n', 1)
    title = lines[0]
    body  = lines[1].replace('\n', '<br>') if len(lines) > 1 else ''
    data = json.dumps({
        '@type':    'MessageCard',
        '@context': 'http://schema.org/extensions',
        'themeColor': 'd73a49',
        'summary': title,
        'sections': [{'activityTitle': title, 'text': body}],
    }).encode()
    req = urllib.request.Request(
        url, data=data,
        headers={'Content-Type': 'application/json'},
        method='POST',
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return 200 <= r.status < 300
    except Exception as e:
        log.error('Teams POST failed: %s', e)
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
        service = payload.get('service', 'Unknown AI service')
        host    = payload.get('host', '')
        source  = payload.get('source', 'network')
        if source == 'saas_ai':
            return (f"RiskRaven: Arckon — Unauthorized SaaS AI Access\n"
                    f"Device: {device}\n"
                    f"Service: {service}\n"
                    f"An employee on {device} was detected accessing {service}. "
                    f"Review in the AI Asset Inventory and approve or block this service.")
        return (f"RiskRaven: Arckon — Shadow AI Detected\n"
                f"Device: {device}\n"
                f"Service: {service}" + (f" ({host})" if host else '') + "\n"
                f"Review in the AI Asset Inventory and approve or remove this asset.")
    if ev == 'test_alert':
        return f"RiskRaven: Arckon — Test alert. Alerts are working correctly."
    sev    = payload.get('severity', 'HIGH')
    prefix = 'CRITICAL Finding' if sev == 'CRITICAL' else 'HIGH Finding'
    check  = payload.get('check_id', '')
    title  = payload.get('title', '')
    return (f"RiskRaven: Arckon — {prefix}\n"
            f"Device: {device}\n"
            + (f"Check: {check}" + (f" — {title}" if title else '') + "\n" if check else (f"{title}\n" if title else ''))
            + "Log in to RiskRaven: Arckon to view full details and remediation steps.")


def _alert_subject(payload: dict) -> str:
    ev     = payload.get('event', '')
    device = payload.get('device', 'unknown')
    if ev == 'new_shadow_ai':
        service = payload.get('service', 'Unknown AI service')
        return f'[RiskRaven: Arckon] Unauthorized AI Access — {service} on {device}'
    sev = payload.get('severity', 'HIGH')
    check = payload.get('check_id', 'Finding')
    return f'[RiskRaven: Arckon] {sev}: {check} on {device}'


def _now_iso() -> str:
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
