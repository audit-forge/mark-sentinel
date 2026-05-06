#!/usr/bin/env python3
import sys
if sys.version_info < (3, 11):
    sys.exit(
        "M.A.R.K. Sentinel requires Python 3.11 or later.\n"
        f"Running: Python {sys.version.split()[0]}\n"
        "Install: https://python.org/downloads/"
    )

import argparse
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_DB = Path(__file__).parent / 'output' / 'agents.db'
BAR_WIDTH = 8


def _conn(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(f'file:{db_path}?mode=ro', uri=True, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def _bar(value: int, max_val: int, width: int = BAR_WIDTH) -> str:
    if max_val == 0:
        return '░' * width
    filled = round((value / max_val) * width)
    return '█' * filled + '░' * (width - filled)


def _ts(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).strftime('%Y-%m-%d %H:%M UTC')


def cmd_list_devices(args: argparse.Namespace) -> None:
    db = Path(args.db)
    if not db.exists():
        print(f'Database not found: {db}')
        return
    with _conn(db) as conn:
        rows = conn.execute("""
            SELECT
                d.device_id, d.hostname, d.platform, d.last_seen,
                r.fail_count, r.warn_count, r.pass_count
            FROM devices d
            LEFT JOIN reports r
                ON r.device_id = d.device_id
                AND r.received_at = (
                    SELECT MAX(received_at) FROM reports WHERE device_id = d.device_id
                )
            ORDER BY d.last_seen DESC
        """).fetchall()
    if not rows:
        print('No devices found.')
        return
    print(f'{"DEVICE ID":<36}  {"HOSTNAME":<20}  {"PLATFORM":<12}  {"LAST SEEN":<22}  FAIL  WARN  PASS')
    print('-' * 110)
    for r in rows:
        print(
            f'{r["device_id"]:<36}  {(r["hostname"] or ""):<20}  {(r["platform"] or ""):<12}  '
            f'{_ts(r["last_seen"]):<22}  {(r["fail_count"] or 0):>4}  {(r["warn_count"] or 0):>4}  {(r["pass_count"] or 0):>4}'
        )


def cmd_device(args: argparse.Namespace) -> None:
    db = Path(args.db)
    if not db.exists():
        print(f'Database not found: {db}')
        return
    with _conn(db) as conn:
        rows = conn.execute("""
            SELECT received_at, scan_date, fail_count, warn_count, pass_count, profile
            FROM reports
            WHERE device_id = ?
            ORDER BY received_at DESC
            LIMIT ?
        """, (args.device_id, args.limit)).fetchall()
    if not rows:
        print(f'No reports found for device: {args.device_id}')
        return
    print(f'{"DATE":<22}  FAIL  WARN  PASS  PROFILE')
    print('-' * 60)
    for r in rows:
        print(
            f'{_ts(r["received_at"]):<22}  '
            f'{r["fail_count"]:>4}  {r["warn_count"]:>4}  {r["pass_count"]:>4}  '
            f'{r["profile"] or ""}'
        )


def cmd_trends(args: argparse.Namespace) -> None:
    db = Path(args.db)
    if not db.exists():
        print(f'Database not found: {db}')
        return
    with _conn(db) as conn:
        rows = conn.execute("""
            SELECT received_at, fail_count, warn_count, pass_count
            FROM reports
            WHERE device_id = ?
            ORDER BY received_at DESC
            LIMIT 20
        """, (args.device_id,)).fetchall()
    if not rows:
        print(f'No reports found for device: {args.device_id}')
        return
    rows = list(reversed(rows))
    max_fail = max(r['fail_count'] for r in rows) or 1
    max_warn = max(r['warn_count'] for r in rows) or 1
    max_pass = max(r['pass_count'] for r in rows) or 1
    for r in rows:
        date = datetime.fromtimestamp(r['received_at'], tz=timezone.utc).strftime('%Y-%m-%d')
        fb = _bar(r['fail_count'], max_fail)
        wb = _bar(r['warn_count'], max_warn)
        pb = _bar(r['pass_count'], max_pass)
        print(
            f'{date}  FAIL {fb}  {r["fail_count"]:>3}   '
            f'WARN {wb}  {r["warn_count"]:>3}   '
            f'PASS {pb}  {r["pass_count"]:>3}'
        )


def cmd_summary(args: argparse.Namespace) -> None:
    db = Path(args.db)
    if not db.exists():
        print(f'Database not found: {db}')
        return
    with _conn(db) as conn:
        total_devices = conn.execute('SELECT COUNT(*) FROM devices').fetchone()[0]
        total_scans = conn.execute('SELECT COUNT(*) FROM reports').fetchone()[0]

        worst = conn.execute("""
            SELECT d.hostname, d.device_id, SUM(r.fail_count) AS total_fails
            FROM reports r
            JOIN devices d ON d.device_id = r.device_id
            GROUP BY r.device_id
            ORDER BY total_fails DESC
            LIMIT 1
        """).fetchone()

        avg_row = conn.execute("""
            SELECT AVG(CAST(pass_count AS REAL) / NULLIF(fail_count + warn_count + pass_count, 0)) AS avg_score
            FROM reports
        """).fetchone()

    print(f'Total devices:         {total_devices}')
    print(f'Total scans stored:    {total_scans}')
    if worst:
        print(f'Most failures:         {worst["hostname"]} ({worst["device_id"]}) — {worst["total_fails"]} total fails')
    avg = avg_row['avg_score']
    if avg is not None:
        print(f'Avg compliance score:  {avg * 100:.1f}%')
    else:
        print('Avg compliance score:  N/A')


def main() -> None:
    parser = argparse.ArgumentParser(
        prog='audit_history',
        description='M.A.R.K. Sentinel — query historical scan data',
    )
    parser.add_argument('--db', default=str(DEFAULT_DB), metavar='PATH',
                        help='Path to agents.db (default: output/agents.db)')

    sub = parser.add_subparsers(dest='cmd', required=True)

    sub.add_parser('list-devices', help='List all devices with latest scan summary')

    p_device = sub.add_parser('device', help='Show scan history for a device')
    p_device.add_argument('device_id', metavar='device-id')
    p_device.add_argument('--limit', type=int, default=10, metavar='N',
                          help='Number of reports to show (default: 10)')

    p_trends = sub.add_parser('trends', help='ASCII trend chart for a device')
    p_trends.add_argument('device_id', metavar='device-id')

    sub.add_parser('summary', help='Aggregate stats across all devices')

    args = parser.parse_args()

    dispatch = {
        'list-devices': cmd_list_devices,
        'device': cmd_device,
        'trends': cmd_trends,
        'summary': cmd_summary,
    }
    dispatch[args.cmd](args)


if __name__ == '__main__':
    main()
