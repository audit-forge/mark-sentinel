#!/usr/bin/env python3
"""Google Workspace Drive audit forwarder for Arckon Protected Cloud Assets.

Polls the Google Workspace Admin SDK Reports API for Drive audit activities
and forwards each one to Arckon's authenticated cloud-asset ingest endpoint.

Prerequisites:
  1. A Google Cloud service account with domain-wide delegation enabled.
  2. In Google Workspace Admin Console, grant the service account the OAuth
     scope: https://www.googleapis.com/auth/admin.reports.audit.readonly
  3. The service account JSON key file downloaded locally.
  4. An Arckon ingest token (from the Protected Cloud Assets dashboard page).

Usage:
  pip install google-api-python-client google-auth google-auth-httplib2
  python3 gworkspace_drive_forwarder.py \
    --service-account-key /path/to/service-account.json \
    --admin-email admin@yourdomain.com \
    --arckon-url https://arckon.riskraven.ai \
    --arckon-token-file /path/to/arckon-ingest-token \
    --domain yourdomain.com \
    --state-file /var/lib/arckon-drive-forwarder/state

Run as a scheduler job every 30 seconds. State is persisted in the configured
state file so only new activities are sent. Google publishes Drive audit events
asynchronously, so the provider can add a variable delay before a new access is
available for this forwarder to retrieve.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.request
from pathlib import Path

STATE_FILE = Path(__file__).parent / '.gworkspace_forwarder_state.json'


def _load_state(state_file: Path = STATE_FILE) -> str:
    """Return the last-processed event timestamp, or empty string."""
    if state_file.is_file():
        try:
            return state_file.read_text().strip()
        except OSError:
            pass
    return ''


def _save_state(ts: str, state_file: Path = STATE_FILE) -> None:
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(ts)


def _fetch_drive_activities(service_account_key: str, admin_email: str,
                             start_time: str) -> list[dict]:
    """Fetch Drive audit activities since start_time from the Reports API."""
    from google.oauth2 import service_account
    from googleapiclient.discovery import build

    creds = service_account.Credentials.from_service_account_file(
        service_account_key,
        scopes=['https://www.googleapis.com/auth/admin.reports.audit.readonly'])
    creds = creds.with_subject(admin_email)
    service = build('admin', 'reports_v1', credentials=creds)

    activities = []
    page_token = None
    while True:
        kwargs = {'userKey': 'all', 'applicationName': 'drive', 'maxResults': 1000}
        if start_time:
            kwargs['startTime'] = start_time
        if page_token:
            kwargs['pageToken'] = page_token
        resp = service.activities().list(**kwargs).execute()
        activities.extend(resp.get('items', []))
        page_token = resp.get('nextPageToken')
        if not page_token:
            break
    return activities


def _event_payloads(activity: dict, domain: str) -> list[dict]:
    """Split a Drive activity so each audit event has a stable unique id."""
    activity_id = activity.get('id', {})
    if not isinstance(activity_id, dict):
        activity_id = {}
    base_id = ':'.join(filter(None, (
        str(activity_id.get('time', '')),
        str(activity_id.get('uniqQualifier', '')),
    )))
    payloads = []
    for index, event in enumerate(activity.get('events', [])):
        if not isinstance(event, dict):
            continue
        payloads.append({
            'arckonDomain': domain,
            'arckonEventId': f'{base_id}:{index}' if base_id else '',
            'actor': activity.get('actor', {}),
            'id': activity_id,
            'events': [event],
        })
    return payloads


def _forward_to_arckon(activity: dict, arckon_url: str, token: str,
                       domain: str) -> tuple[int, int]:
    """Forward each Drive audit event separately. Return successes and failures."""
    url = f'{arckon_url.rstrip("/")}/api/cloud-assets/events'
    forwarded = 0
    failed = 0
    for payload in _event_payloads(activity, domain):
        req = urllib.request.Request(url, data=json.dumps(payload).encode(), method='POST')
        req.add_header('Content-Type', 'application/json')
        req.add_header('Authorization', f'Bearer {token}')
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                forwarded += resp.status == 200
        except Exception as e:
            print(f'Forward error: {e}', file=sys.stderr)
            failed += 1
    return forwarded, failed


def main() -> int:
    parser = argparse.ArgumentParser(description='Forward Google Workspace Drive audit events to Arckon')
    parser.add_argument('--service-account-key', required=True, help='Path to service account JSON key file')
    parser.add_argument('--admin-email', required=True, help='Admin email for domain-wide delegation')
    parser.add_argument('--arckon-url', required=True, help='Arckon server URL')
    token_group = parser.add_mutually_exclusive_group(required=True)
    token_group.add_argument('--arckon-token', help='Arckon ingest token (avoid in scheduled commands)')
    token_group.add_argument('--arckon-token-file',
                             help='Path to a file containing the Arckon ingest token')
    parser.add_argument('--domain', required=True, help='Google Workspace domain')
    parser.add_argument('--state-file', default=str(STATE_FILE),
                        help='Persistent file for the last forwarded timestamp')
    args = parser.parse_args()

    token = args.arckon_token
    if args.arckon_token_file:
        try:
            token = Path(args.arckon_token_file).read_text().strip()
        except OSError as e:
            print(f'Could not read Arckon ingest token file: {e}', file=sys.stderr)
            return 2
    if not token:
        print('Arckon ingest token is empty', file=sys.stderr)
        return 2

    state_file = Path(args.state_file)
    start_time = _load_state(state_file)
    try:
        activities = _fetch_drive_activities(
            args.service_account_key, args.admin_email, start_time)
    except Exception as e:
        print(f'Fetch error: {e}', file=sys.stderr)
        return 1

    if not activities:
        print('No new activities.')
        return 0

    forwarded = 0
    failures = 0
    latest_ts = start_time
    for activity in activities:
        ts = activity.get('id', {}).get('time', '')
        if not ts:
            continue
        sent, failed = _forward_to_arckon(activity, args.arckon_url, token, args.domain)
        forwarded += sent
        failures += failed
        if ts > latest_ts:
            latest_ts = ts

    if failures:
        print(f'Forwarded {forwarded} audit events; {failures} failed. Checkpoint not advanced.',
              file=sys.stderr)
        return 1
    _save_state(latest_ts, state_file)
    print(f'Forwarded {forwarded} audit events from {len(activities)} activities.')
    return 0


if __name__ == '__main__':
    sys.exit(main())
