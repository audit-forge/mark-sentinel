#!/usr/bin/env python3
import json
import logging
import os
import smtplib
import urllib.request
from dataclasses import dataclass
from email.message import EmailMessage
from pathlib import Path

log = logging.getLogger(__name__)

_SEVERITY_ORDER = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}


@dataclass
class AlertConfig:
    webhook_url: str = ''
    slack_webhook: str = ''
    email_to: str = ''
    email_from: str = ''
    smtp_host: str = ''
    smtp_port: int = 587
    min_severity: str = 'CRITICAL'


def load_alert_config(path: Path) -> AlertConfig | None:
    try:
        data = json.loads(Path(path).read_text())
        return AlertConfig(**{k: v for k, v in data.items() if k in AlertConfig.__dataclass_fields__})
    except FileNotFoundError:
        return None
    except (json.JSONDecodeError, OSError) as e:
        log.warning('Could not parse alerts config %s: %s', path, e)
        return None


def should_alert(report: dict, config: AlertConfig) -> list[dict]:
    threshold = _SEVERITY_ORDER.get(config.min_severity, 4)
    findings = report.get('findings', [])
    return [
        f for f in findings
        if _SEVERITY_ORDER.get(f.get('severity', ''), 0) >= threshold
    ]


def send_webhook(findings: list[dict], device_id: str, hostname: str, config: AlertConfig) -> bool:
    payload = json.dumps({
        'event': 'sentinel.finding',
        'device_id': device_id,
        'hostname': hostname,
        'findings': [
            {
                'check_id': f.get('check_id', ''),
                'title': f.get('title', ''),
                'severity': f.get('severity', ''),
                'status': f.get('status', ''),
            }
            for f in findings
        ],
    }).encode()
    req = urllib.request.Request(
        config.webhook_url,
        data=payload,
        headers={'Content-Type': 'application/json'},
        method='POST',
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status < 400
    except Exception as exc:
        log.error('webhook failed: %s', exc)
        return False


def send_slack(findings: list[dict], device_id: str, hostname: str, config: AlertConfig) -> bool:
    blocks = [
        {'type': 'header', 'text': {'type': 'plain_text', 'text': '🔴 M.A.R.K. Sentinel Alert'}},
        {
            'type': 'section',
            'text': {
                'type': 'mrkdwn',
                'text': f'*Device:* {hostname} (`{device_id}`)\n*Findings:* {len(findings)}',
            },
        },
    ]
    for f in findings:
        blocks.append({
            'type': 'section',
            'text': {
                'type': 'mrkdwn',
                'text': f'`{f.get("check_id", "")}` — *{f.get("title", "")}* [{f.get("severity", "")}]',
            },
        })
    payload = json.dumps({'blocks': blocks}).encode()
    req = urllib.request.Request(
        config.slack_webhook,
        data=payload,
        headers={'Content-Type': 'application/json'},
        method='POST',
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status < 400
    except Exception as exc:
        log.error('slack alert failed: %s', exc)
        return False


def send_email(findings: list[dict], device_id: str, hostname: str, config: AlertConfig) -> bool:
    password = os.environ.get('SENTINEL_SMTP_PASSWORD', '')
    safe_hostname = hostname.replace('\r', '').replace('\n', '').replace('\0', '')[:253]
    subject = f'Sentinel Alert: {len(findings)} critical finding(s) on {safe_hostname}'
    lines = [
        f'M.A.R.K. Sentinel detected {len(findings)} finding(s) requiring attention.',
        f'Device: {hostname} ({device_id})',
        '',
    ]
    for f in findings:
        lines.append(f'[{f.get("severity", "")}] {f.get("check_id", "")} — {f.get("title", "")} (status: {f.get("status", "")})')
    body = '\n'.join(lines)

    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = config.email_from
    msg['To'] = config.email_to
    msg.set_content(body)

    try:
        with smtplib.SMTP(config.smtp_host, config.smtp_port, timeout=15) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            if password:
                server.login(config.email_from, password)
            server.send_message(msg)
        return True
    except Exception as exc:
        log.error('email alert failed: %s', exc)
        return False


def fire_alerts(report: dict, device_id: str, hostname: str, config: AlertConfig) -> None:
    findings = should_alert(report, config)
    if not findings:
        return
    if config.webhook_url:
        ok = send_webhook(findings, device_id, hostname, config)
        log.info('webhook alert: %s', 'sent' if ok else 'FAILED')
    if config.slack_webhook:
        ok = send_slack(findings, device_id, hostname, config)
        log.info('slack alert: %s', 'sent' if ok else 'FAILED')
    if config.email_to:
        ok = send_email(findings, device_id, hostname, config)
        log.info('email alert: %s', 'sent' if ok else 'FAILED')
