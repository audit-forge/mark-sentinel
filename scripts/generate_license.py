#!/usr/bin/env python3
"""
M.A.R.K. Sentinel — License Generator

Usage:
  python3 scripts/generate_license.py \
    --customer-id acme-corp \
    --licensed-to "Acme Corporation" \
    --max-agents 5000 \
    --expires 2027-05-11 \
    --webhook https://hooks.slack.com/services/xxx \
    --telemetry-url https://telemetry.mark-sentinel.com/ingest \
    --out /path/to/customer/license.json
"""
import argparse
import hashlib
import hmac
import json
import os
import sys
from datetime import date, timedelta
from pathlib import Path


def main():
    ap = argparse.ArgumentParser(description='Generate a Sentinel license.json')
    ap.add_argument('--customer-id',       required=True,
                    help='URL-safe slug, e.g. acme-corp')
    ap.add_argument('--licensed-to',       required=True,
                    help='Display name, e.g. "Acme Corporation"')
    ap.add_argument('--max-agents',        required=True, type=int,
                    help='Contracted seat count (0 = unlimited)')
    ap.add_argument('--grace-pct',         type=float, default=10.0,
                    help='Overage grace %% before hard-alert fires (default: 10)')
    ap.add_argument('--expires',           default='',
                    help='Expiry date YYYY-MM-DD (default: 1 year from today)')
    ap.add_argument('--webhook',           default='',
                    help='Webhook URL for overage + stale-device alerts (Slack, Teams, etc.)')
    ap.add_argument('--telemetry-url',     default='',
                    help='M.A.R.K. telemetry endpoint — receives rolling usage heartbeats')
    ap.add_argument('--telemetry-interval', type=float, default=24.0,
                    help='Hours between usage heartbeats (default: 24)')
    ap.add_argument('--stale-hours',       type=float, default=26.0,
                    help='Hours of silence before a device is flagged unreachable (default: 26)')
    ap.add_argument('--plan',              default='plus', choices=['demo', 'standard', 'plus'],
                    help='License plan: demo, standard, or plus (default: plus)')
    ap.add_argument('--out',               default='license.json',
                    help='Output file path (default: ./license.json)')
    args = ap.parse_args()

    if args.max_agents < 0:
        print('ERROR: --max-agents must be >= 0 (0 = unlimited)', file=sys.stderr)
        sys.exit(1)

    expires = args.expires or (date.today() + timedelta(days=365)).isoformat()
    try:
        date.fromisoformat(expires)
    except ValueError:
        print(f'ERROR: --expires must be YYYY-MM-DD, got: {expires}', file=sys.stderr)
        sys.exit(1)

    license_data = {
        'customer_id':          args.customer_id,
        'licensed_to':          args.licensed_to,
        'max_agents':           args.max_agents,
        'grace_pct':            args.grace_pct,
        'expires_at':           expires,
        'issued_at':            date.today().isoformat(),
        'issued_by':            'M.A.R.K. AI Systems',
        'plan':                 args.plan,
        'webhook_url':          args.webhook,
        'telemetry_url':        args.telemetry_url,
        'telemetry_interval_h': args.telemetry_interval,
        'stale_alert_hours':    args.stale_hours,
    }

    signing_key = os.environ.get('LICENSE_SIGNING_KEY', '').encode()
    if signing_key:
        canon = json.dumps({k: v for k, v in sorted(license_data.items())},
                           sort_keys=True, separators=(',', ':'))
        license_data['sig'] = hmac.new(signing_key, canon.encode(), hashlib.sha256).hexdigest()
    else:
        print('WARNING: LICENSE_SIGNING_KEY not set — license will not be signed.', file=sys.stderr)

    out_path = Path(args.out)
    out_path.write_text(json.dumps(license_data, indent=2) + '\n', encoding='utf-8')

    grace_limit = int(args.max_agents * (1 + args.grace_pct / 100)) if args.max_agents else 0

    print(f'\nLicense generated: {out_path}')
    print(f'  Customer      : {args.licensed_to} ({args.customer_id})')
    print(f'  Seats         : {args.max_agents:,}' if args.max_agents else '  Seats         : unlimited')
    if args.max_agents:
        print(f'  Grace limit   : {grace_limit:,}  ({args.grace_pct}% → alert fires)')
    print(f'  Expires       : {expires}')
    print(f'  Webhook       : {args.webhook or "(none)"}')
    print(f'  Telemetry     : {args.telemetry_url or "(none)"}  every {args.telemetry_interval:.0f}h')
    print(f'  Stale alert   : {args.stale_hours:.0f}h silence → device flagged unreachable')
    print()
    print('Place license.json next to server.py on the customer Sentinel server.')
    print('Audit log  : GET /api/admin/license')
    print('Telemetry  : auto-posted to telemetry_url on schedule (1 min after server start)')


if __name__ == '__main__':
    main()
