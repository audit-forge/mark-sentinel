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
from urllib.parse import parse_qs, urlparse
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
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
    """Load config with secrets masked for safe return to the browser."""
    cfg = load_alert_config(path) or {}
    psa_raw = cfg.get('psa', {})
    cw  = psa_raw.get('connectwise', {})
    at  = psa_raw.get('autotask', {})
    hp  = psa_raw.get('halopsa', {})
    result = {
        # Incoming webhook URLs are bearer secrets; never return them to a browser.
        'slack_webhook':  '',
        'slack_webhook_configured': bool(cfg.get('slack_webhook')),
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
    """Save alert config, preserving masked secrets (SMTP password, PSA keys, Slack)."""
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

    slack_incoming = str(new_data.get('slack_webhook', '')).strip()
    if new_data.get('slack_webhook_clear'):
        slack_webhook = ''
    elif slack_incoming:
        if not is_valid_slack_webhook(slack_incoming):
            raise ValueError('Slack webhook must be an HTTPS hooks.slack.com/services URL')
        slack_webhook = slack_incoming
    else:
        slack_webhook = existing.get('slack_webhook', '')

    def _validate_or_preserve(incoming: str, existing_val: str, validator, label: str) -> str:
        incoming = incoming.strip()
        if not incoming:
            return existing_val
        if not validator(incoming):
            raise ValueError(f'{label} is not a valid URL')
        return incoming

    triggers_raw = new_data.get('triggers', {})
    clean = {
        'slack_webhook':  slack_webhook,
        'gchat_webhook':  _validate_or_preserve(
            str(new_data.get('gchat_webhook', '')), existing.get('gchat_webhook', ''),
            is_valid_gchat_webhook, 'Google Chat webhook'),
        'teams_webhook':  _validate_or_preserve(
            str(new_data.get('teams_webhook', '')), existing.get('teams_webhook', ''),
            is_valid_teams_webhook, 'Microsoft Teams webhook'),
        'webhook_url':    _validate_or_preserve(
            str(new_data.get('webhook_url', '')), existing.get('webhook_url', ''),
            lambda u: is_valid_url(u, ('http', 'https')), 'Webhook URL'),
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

def _finding_payload(event: str, severity: str, hostname: str, finding: dict) -> dict:
    """Builds the alert payload for one finding — carries remediation/
    details/category/frameworks through from the raw finding dict (same
    field names ArckonFinding.from_result() reads in siem_connector.py)
    so every downstream channel (chat, PSA tickets, Notion) can render a
    real canned response instead of a bare title. Previously these fields
    were dropped here, which is why every auto-fired notification just
    said "log in to see details" even though the finding data was right
    there the whole time."""
    return {
        'event':       event,
        'severity':    severity,
        'device':      hostname,
        'check_id':    finding.get('check_id', ''),
        'title':       finding.get('title', ''),
        'category':    finding.get('category', ''),
        'details':     finding.get('details', ''),
        'remediation': finding.get('remediation', ''),
        'frameworks':  finding.get('frameworks') or {},
    }


def _build_canned_response(payload: dict) -> dict:
    """Turns an alert payload into structured, actionable content shared
    by every notification channel (chat, PSA tickets, Notion) — so a
    customer receiving a Slack ping or a Jira ticket sees real "what /
    why / how to fix" content instead of a bare title and a "log in to
    see details" punt.

    Returns {summary, body_text, body_markdown}: callers pick whichever
    shape their target API wants — Slack/Teams/email want plain text
    with light structure, Notion wants markdown-ish block content, PSA
    tickets want a plain description field. All three are built from the
    same underlying facts so the content never diverges between channels.
    """
    severity    = payload.get('severity', 'HIGH')
    device      = payload.get('device', 'unknown')
    check_id    = payload.get('check_id', '')
    title       = payload.get('title', '')
    category    = payload.get('category', '')
    details     = payload.get('details', '')
    remediation = payload.get('remediation', '')
    frameworks  = payload.get('frameworks') or {}

    summary = f'{severity} Finding' + (f' — {check_id}' if check_id else '') + (f': {title}' if title else '')

    framework_line = ''
    if frameworks:
        mapped = ', '.join(
            f'{k}: {v}' if isinstance(v, str) and v else str(k)
            for k, v in frameworks.items()
        )
        framework_line = f'Mapped controls: {mapped}'

    fix_line = f'Recommended fix: {remediation}' if remediation \
        else 'Log in to RiskRaven: Arckon to view full details and remediation steps.'

    # detail_lines omits the summary/device line — for callers (like
    # _format_text) that already render their own branded header and
    # just need the enriched tail appended to it. body_text/body_markdown
    # below are the full self-contained versions, for callers with no
    # header of their own (PSA ticket descriptions, the Notion page body).
    detail_lines = []
    if category:
        detail_lines.append(f'Category: {category}')
    if details:
        detail_lines.append(f'What we found: {details}')
    if framework_line:
        detail_lines.append(framework_line)
    detail_lines.append(fix_line)

    text_lines = [f'{summary} on {device}.'] + detail_lines

    md_lines = [f'**{summary}** on `{device}`']
    if category:
        md_lines.append(f'**Category:** {category}')
    if details:
        md_lines.append(f'**What we found:** {details}')
    if frameworks:
        md_lines.append(f'**Mapped controls:** {mapped}')
    md_lines.append(f'**Recommended fix:** {remediation}' if remediation else fix_line)

    return {
        'summary':       summary,
        'detail_text':   '\n'.join(detail_lines),
        'body_text':     '\n'.join(text_lines),
        'body_markdown': '\n\n'.join(md_lines),
    }


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
                messages.append(_finding_payload('new_critical_finding', 'CRITICAL', hostname, f))
    if triggers.get('new_high'):
        for f in findings:
            if (f.get('status') == 'FAIL'
                    and f.get('severity', '').upper() == 'HIGH'
                    and f.get('check_id', '') not in prev_fail_ids):
                messages.append(_finding_payload('new_high_finding', 'HIGH', hostname, f))

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
        if not is_valid_slack_webhook(url):
            return False, 'Slack webhook must be an HTTPS hooks.slack.com/services URL'
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
        if not is_valid_gchat_webhook(url):
            return False, 'Google Chat webhook must be a https://chat.googleapis.com/v1/spaces/.../messages?key=...&token=... URL'
        ok = _post_gchat(url, _format_text(payload))
        return ok, 'Test sent to Google Chat' if ok else 'Google Chat delivery failed — check the webhook URL'
    if channel == 'teams':
        url = alert_cfg.get('teams_webhook', '').strip()
        if not url:
            return False, 'No Teams webhook URL configured'
        if not is_valid_teams_webhook(url):
            return False, 'Teams webhook must be a https://*.webhook.office.com/webhookb2/.../IncomingWebhook/... URL'
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


def send_test_notion(alert_cfg: dict) -> tuple[bool, str]:
    """Test Notion connectivity. Returns (ok, message)."""
    notion_cfg = alert_cfg.get('notion', {})
    if not notion_cfg.get('token'):
        return False, 'No Notion token configured'
    try:
        from connectors.notion_connector import test_connection
        return test_connection(notion_cfg)
    except Exception as e:
        return False, f'Notion test failed: {e}'


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
        if is_valid_slack_webhook(slack_url) and _post_slack(slack_url, text, payload):
            fired.append('slack')
        elif not is_valid_slack_webhook(slack_url):
            log.error('Skipping invalid Slack webhook URL')
    if gchat_url:
        if is_valid_gchat_webhook(gchat_url) and _post_gchat(gchat_url, text):
            fired.append('google_chat')
        elif not is_valid_gchat_webhook(gchat_url):
            log.error('Skipping invalid Google Chat webhook URL')
    if teams_url:
        if is_valid_teams_webhook(teams_url) and _post_teams(teams_url, text):
            fired.append('teams')
        elif not is_valid_teams_webhook(teams_url):
            log.error('Skipping invalid Microsoft Teams webhook URL')
    if webhook_url:
        if is_valid_url(webhook_url, ('http', 'https')) and _post_webhook(webhook_url, payload):
            fired.append('webhook')
        elif not is_valid_url(webhook_url, ('http', 'https')):
            log.error('Skipping invalid generic webhook URL')
    if email_cfg.get('smtp_host') and email_cfg.get('to'):
        _send_email(email_cfg, _alert_subject(payload), text)
        fired.append('email')
    if psa_cfg.get('provider') and payload.get('event', '').startswith('new_'):
        _create_psa_ticket(psa_cfg, payload)
        fired.append(f'psa_{psa_cfg["provider"]}')
    notion_cfg = alert_cfg.get('notion', {})
    if notion_cfg.get('enabled') and notion_cfg.get('token') and payload.get('event', '').startswith('new_'):
        _create_notion_page(notion_cfg, payload)
        fired.append('notion')
    return fired


def _create_notion_page(notion_cfg: dict, payload: dict) -> None:
    try:
        from connectors.notion_connector import create_page
        finding = {
            'check_id':    payload.get('check_id', ''),
            'title':       payload.get('title', ''),
            'severity':    payload.get('severity', 'HIGH'),
            'description': _build_canned_response(payload)['detail_text'],
            'remediation': payload.get('remediation', ''),
        }
        hostname = payload.get('device', 'Unknown')
        ok, msg = create_page(notion_cfg, finding, hostname)
        if ok:
            log.info('Notion page created: %s', msg)
        else:
            log.error('Notion page creation failed: %s', msg)
    except Exception as e:
        log.error('Notion dispatch error: %s', e)


def _create_psa_ticket(psa_cfg: dict, payload: dict) -> None:
    try:
        from connectors.psa_connector import create_ticket
        # description now carries the full canned response (what was
        # found, mapped controls, recommended fix) instead of just
        # repeating the title — every PSA provider's ticket body function
        # already has fallback logic reading this field (e.g. Jira's
        # `finding.get('description', finding.get('remediation', ''))`,
        # psa_connector.py:307), it just never received anything richer
        # than the title before now.
        finding = {
            'check_id':    payload.get('check_id', ''),
            'title':       payload.get('title', ''),
            'severity':    payload.get('severity', 'HIGH'),
            'description': _build_canned_response(payload)['detail_text'],
            'remediation': payload.get('remediation', ''),
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
    if not is_valid_slack_webhook(webhook_url):
        log.error('Refusing to post to an invalid Slack webhook URL')
        return False
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


def is_valid_slack_webhook(webhook_url: str) -> bool:
    """Accept only Slack's official HTTPS incoming-webhook endpoint."""
    try:
        parsed = urlparse(webhook_url)
        return (parsed.scheme == 'https'
                and parsed.hostname == 'hooks.slack.com'
                and parsed.path.startswith('/services/')
                and len(parsed.path.split('/')) >= 5)
    except (TypeError, ValueError):
        return False


def is_valid_url(url: str, allowed_schemes: tuple[str, ...] = ('https',)) -> bool:
    """Basic URL validation: allowed scheme and a non-empty host."""
    try:
        parsed = urlparse(url)
        return (parsed.scheme in allowed_schemes
                and parsed.hostname is not None
                and parsed.hostname != '')
    except (TypeError, ValueError):
        return False


def is_valid_gchat_webhook(url: str) -> bool:
    """Accept only Google Chat Space incoming webhook URLs.

    Expected shape:
      https://chat.googleapis.com/v1/spaces/{spaceId}/messages?key={key}&token={token}
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme != 'https' or parsed.hostname != 'chat.googleapis.com':
            return False
        if not parsed.path.startswith('/v1/spaces/'):
            return False
        if not parsed.path.rstrip('/').endswith('/messages'):
            return False
        qs = parse_qs(parsed.query)
        return bool(qs.get('key')) and bool(qs.get('token'))
    except (TypeError, ValueError):
        return False


def is_valid_teams_webhook(url: str) -> bool:
    """Accept only Microsoft Teams incoming webhook URLs."""
    try:
        parsed = urlparse(url)
        return (parsed.scheme == 'https'
                and parsed.hostname is not None
                and parsed.hostname.endswith('.webhook.office.com')
                and parsed.path.startswith('/webhookb2/')
                and '/IncomingWebhook/' in parsed.path)
    except (TypeError, ValueError):
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


def send_email_with_attachment(cfg: dict, to_addr: str, subject: str, body_text: str,
                                attachment_bytes: bytes, attachment_filename: str) -> bool:
    """Same SMTP config shape as _send_email's 'email' block, but delivers
    to an explicit recipient (to_addr) with a binary attachment — used for
    scheduled per-client PDF report delivery, where the recipient is the
    client org's own report_email, not the customer-wide alert 'to'."""
    host      = cfg.get('smtp_host', 'smtp.gmail.com')
    port      = int(cfg.get('smtp_port', 587))
    user      = cfg.get('smtp_user', '')
    password  = cfg.get('smtp_pass', '')
    from_addr = cfg.get('from', user)
    if not to_addr or not host or not user:
        log.warning('send_email_with_attachment: SMTP not configured or no recipient — skipping "%s"', subject)
        return False
    msg = MIMEMultipart()
    msg['Subject'] = subject
    msg['From']    = from_addr
    msg['To']      = to_addr
    msg.attach(MIMEText(body_text, 'plain'))
    part = MIMEApplication(attachment_bytes, Name=attachment_filename)
    part['Content-Disposition'] = f'attachment; filename="{attachment_filename}"'
    msg.attach(part)
    try:
        with smtplib.SMTP(host, port, timeout=30) as smtp:
            smtp.ehlo()
            smtp.starttls()
            if user and password:
                smtp.login(user, password)
            smtp.sendmail(from_addr, [to_addr], msg.as_string())
        return True
    except Exception as e:
        log.error('email with attachment send failed: %s', e)
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
                "Review in the AI Asset Inventory and approve or remove this asset.")
    if ev == 'test_alert':
        return "RiskRaven: Arckon — Test alert. Alerts are working correctly."
    sev    = payload.get('severity', 'HIGH')
    prefix = 'CRITICAL Finding' if sev == 'CRITICAL' else 'HIGH Finding'
    check  = payload.get('check_id', '')
    title  = payload.get('title', '')
    return (f"RiskRaven: Arckon — {prefix}\n"
            f"Device: {device}\n"
            + (f"Check: {check}" + (f" — {title}" if title else '') + "\n" if check else (f"{title}\n" if title else ''))
            + _build_canned_response(payload)['detail_text'])


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
