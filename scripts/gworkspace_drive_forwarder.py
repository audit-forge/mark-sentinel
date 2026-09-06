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
    --arckon-token YOUR_ARCKON_INGEST_TOKEN \
    --domain yourdomain.com

Run as a cron job every 2-5 minutes. State is persisted in
.gworkspace_forwarder_state.json so only new activities are sent.
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


def _load_state() -> str:
    """Return the last-processed event timestamp, or empty string."""
    if STATE_FILE.is_file():
        try:
            return STATE_FILE.read_text().strip()
        except OSError:
            pass
    return ''


def _save_state(ts: str) -> None:
    STATE_FILE.write_text(ts)


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


def _forward_to_arckon(activity: dict, arckon_url: str, token: str,
                       domain: str) -> bool:
    """Forward one Drive audit activity to Arckon's ingest endpoint."""
    url = f'{arckon_url.rstrip("/")}/api/cloud-assets/events'
    body = json.dumps({
        'arckonDomain': domain,
        'actor': activity.get('actor', {}),
        'id': activity.get('id', {}),
        'events': activity.get('events', []),
    }).encode()
    req = urllib.request.Request(url, data=body, method='POST')
    req.add_header('Content-Type', 'application/json')
    req.add_header('Authorization', f'Bearer {token}')
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status == 200
    except Exception as e:
        print(f'Forward error: {e}', file=sys.stderr)
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description='Forward Google Workspace Drive audit events to Arckon')
    parser.add_argument('--service-account-key', required=True, help='Path to service account JSON key file')
    parser.add_argument('--admin-email', required=True, help='Admin email for domain-wide delegation')
    parser.add_argument('--arckon-url', required=True, help='Arckon server URL')
    parser.add_argument('--arckon-token', required=True, help='Arckon ingest token')
    parser.add_argument('--domain', required=True, help='Google Workspace domain')
    args = parser.parse_args()

    start_time = _load_state()
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
    latest_ts = start_time
    for activity in activities:
        ts = activity.get('id', {}).get('time', '')
        if not ts:
            continue
        if _forward_to_arckon(activity, args.arckon_url, args.arckon_token, args.domain):
            forwarded += 1
            if ts > latest_ts:
                latest_ts = ts

    _save_state(latest_ts)
    print(f'Forwarded {forwarded}/{len(activities)} activities.')
    return 0


if __name__ == '__main__':
    sys.exit(main())