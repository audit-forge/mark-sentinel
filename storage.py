#!/usr/bin/env python3
"""
M.A.R.K. Sentinel — Agent storage layer (SQLite dev / PostgreSQL prod)

FedRAMP note: SQLite has no FIPS 140-2 validation. For FedRAMP Moderate
production deployments replace this backend with PostgreSQL 14+ (which
supports pg_trgm + pgcrypto for FIPS-validated at-rest encryption)
or SQLite compiled with SQLCipher. The AgentStore interface is the same
in both cases — swap _conn() and _init_db() only.
"""
import json
import sqlite3
import threading
import time
import os
from pathlib import Path


class AgentStore:
    """Thread-safe SQLite store for distributed agent scan reports."""

    def __init__(self, db_path: Path):
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        # timeout=30: on Windows, a previous process may hold the WAL lock briefly
        # after a service restart; wait up to 30s rather than raising immediately.
        conn = sqlite3.connect(str(self._path), check_same_thread=False, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self) -> None:
        with self._lock, self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS devices (
                    device_id    TEXT PRIMARY KEY,
                    hostname     TEXT NOT NULL,
                    platform     TEXT NOT NULL DEFAULT '',
                    agent_version TEXT NOT NULL DEFAULT '',
                    ip_address   TEXT NOT NULL DEFAULT '',
                    first_seen   INTEGER NOT NULL,
                    last_seen    INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS reports (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id    TEXT NOT NULL,
                    received_at  INTEGER NOT NULL,
                    scan_date    TEXT NOT NULL DEFAULT '',
                    profile      TEXT NOT NULL DEFAULT '',
                    mode         TEXT NOT NULL DEFAULT '',
                    target       TEXT NOT NULL DEFAULT '',
                    fail_count   INTEGER NOT NULL DEFAULT 0,
                    warn_count   INTEGER NOT NULL DEFAULT 0,
                    pass_count   INTEGER NOT NULL DEFAULT 0,
                    report_json  TEXT NOT NULL,
                    FOREIGN KEY (device_id) REFERENCES devices(device_id)
                );

                CREATE INDEX IF NOT EXISTS idx_reports_device_time
                    ON reports(device_id, received_at DESC);

                CREATE TABLE IF NOT EXISTS commands (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id   TEXT NOT NULL,
                    command     TEXT NOT NULL DEFAULT 'scan_now',
                    created_at  INTEGER NOT NULL,
                    claimed_at  INTEGER,
                    FOREIGN KEY (device_id) REFERENCES devices(device_id)
                );

                CREATE INDEX IF NOT EXISTS idx_commands_device
                    ON commands(device_id, claimed_at);

                CREATE TABLE IF NOT EXISTS license_events (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type   TEXT NOT NULL,
                    device_id    TEXT NOT NULL DEFAULT '',
                    hostname     TEXT NOT NULL DEFAULT '',
                    agent_count  INTEGER NOT NULL,
                    max_agents   INTEGER NOT NULL,
                    recorded_at  INTEGER NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_license_events_time
                    ON license_events(recorded_at DESC);

                CREATE TABLE IF NOT EXISTS shadow_devices (
                    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                    reporter_device_id  TEXT NOT NULL,
                    reporter_hostname   TEXT NOT NULL DEFAULT '',
                    host                TEXT NOT NULL,
                    port                INTEGER NOT NULL DEFAULT 0,
                    service             TEXT NOT NULL DEFAULT '',
                    models_json         TEXT NOT NULL DEFAULT '[]',
                    source              TEXT NOT NULL DEFAULT 'network',
                    detail              TEXT NOT NULL DEFAULT '',
                    first_seen          INTEGER NOT NULL,
                    last_seen           INTEGER NOT NULL,
                    dismissed           INTEGER NOT NULL DEFAULT 0,
                    UNIQUE(source, reporter_device_id, host, port)
                );

                CREATE INDEX IF NOT EXISTS idx_shadow_last_seen
                    ON shadow_devices(last_seen DESC);

                CREATE TABLE IF NOT EXISTS approval_events (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    shadow_id       INTEGER NOT NULL,
                    from_status     TEXT NOT NULL DEFAULT '',
                    to_status       TEXT NOT NULL,
                    changed_by      TEXT NOT NULL DEFAULT '',
                    ip_address      TEXT NOT NULL DEFAULT '',
                    changed_at      INTEGER NOT NULL,
                    FOREIGN KEY (shadow_id) REFERENCES shadow_devices(id)
                );

                CREATE INDEX IF NOT EXISTS idx_approval_events_shadow
                    ON approval_events(shadow_id, changed_at DESC);

                CREATE INDEX IF NOT EXISTS idx_approval_events_time
                    ON approval_events(changed_at DESC);

                CREATE TABLE IF NOT EXISTS mcp_servers (
                    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                    reporter_device_id  TEXT NOT NULL,
                    reporter_hostname   TEXT NOT NULL DEFAULT '',
                    host                TEXT NOT NULL,
                    port                INTEGER NOT NULL DEFAULT 0,
                    server_name         TEXT NOT NULL DEFAULT '',
                    tools_json          TEXT NOT NULL DEFAULT '[]',
                    auth_status         TEXT NOT NULL DEFAULT 'unknown',
                    source              TEXT NOT NULL DEFAULT 'network',
                    process_info        TEXT NOT NULL DEFAULT '',
                    first_seen          INTEGER NOT NULL,
                    last_seen           INTEGER NOT NULL,
                    dismissed           INTEGER NOT NULL DEFAULT 0,
                    UNIQUE(reporter_device_id, host, port, source)
                );

                CREATE INDEX IF NOT EXISTS idx_mcp_last_seen
                    ON mcp_servers(last_seen DESC);

                CREATE TABLE IF NOT EXISTS scan_schedules (
                    id         INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id  TEXT NOT NULL DEFAULT 'all',
                    cadence    TEXT NOT NULL DEFAULT 'daily',
                    hour       INTEGER NOT NULL DEFAULT 2,
                    weekday    INTEGER,
                    monthday   INTEGER,
                    profile    TEXT NOT NULL DEFAULT 'default',
                    label      TEXT NOT NULL DEFAULT '',
                    enabled    INTEGER NOT NULL DEFAULT 1,
                    created_at INTEGER NOT NULL,
                    last_fired INTEGER
                );

                CREATE TABLE IF NOT EXISTS risk_overrides (
                    check_id    TEXT PRIMARY KEY,
                    action      TEXT NOT NULL,
                    assignee    TEXT NOT NULL DEFAULT '',
                    note        TEXT NOT NULL DEFAULT '',
                    expires_at  INTEGER,
                    created_by  TEXT NOT NULL DEFAULT '',
                    created_at  INTEGER NOT NULL,
                    updated_at  INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS approved_services (
                    service     TEXT PRIMARY KEY,
                    approved_by TEXT NOT NULL DEFAULT '',
                    approved_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS alert_events (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts          INTEGER NOT NULL,
                    event_type  TEXT NOT NULL,
                    severity    TEXT NOT NULL DEFAULT 'HIGH',
                    device      TEXT NOT NULL DEFAULT '',
                    service     TEXT NOT NULL DEFAULT '',
                    host        TEXT NOT NULL DEFAULT '',
                    check_id    TEXT NOT NULL DEFAULT '',
                    title       TEXT NOT NULL DEFAULT '',
                    source      TEXT NOT NULL DEFAULT '',
                    channels    TEXT NOT NULL DEFAULT '',
                    reviewed    INTEGER NOT NULL DEFAULT 0
                );

            """)
            # Migrations
            cols = {r[1] for r in conn.execute("PRAGMA table_info(devices)")}
            if 'ip_address' not in cols:
                conn.execute("ALTER TABLE devices ADD COLUMN ip_address TEXT NOT NULL DEFAULT ''")
            sh_cols = {r[1] for r in conn.execute("PRAGMA table_info(shadow_devices)")}
            if 'approval_status' not in sh_cols:
                conn.execute(
                    "ALTER TABLE shadow_devices ADD COLUMN approval_status TEXT NOT NULL DEFAULT 'unapproved'"
                )
            if 'approved_by' not in sh_cols:
                conn.execute(
                    "ALTER TABLE shadow_devices ADD COLUMN approved_by TEXT NOT NULL DEFAULT ''"
                )
            if 'approved_at' not in sh_cols:
                conn.execute(
                    "ALTER TABLE shadow_devices ADD COLUMN approved_at INTEGER"
                )
            if 'false_positive' not in sh_cols:
                conn.execute(
                    "ALTER TABLE shadow_devices ADD COLUMN false_positive INTEGER NOT NULL DEFAULT 0"
                )
            if 'notes' not in sh_cols:
                conn.execute(
                    "ALTER TABLE shadow_devices ADD COLUMN notes TEXT NOT NULL DEFAULT ''"
                )
            sc_cols = {r[1] for r in conn.execute("PRAGMA table_info(scan_schedules)")}
            if 'interval_hours' not in sc_cols:
                conn.execute(
                    "ALTER TABLE scan_schedules ADD COLUMN interval_hours INTEGER NOT NULL DEFAULT 0"
                )

        # Prune old reports per retention policy (env var or default 90 days)
        self.prune_old_reports(int(os.environ.get('SENTINEL_RETAIN_DAYS', '90')))

    def upsert_report(self, device_id: str, hostname: str, report: dict,
                      platform: str = '', agent_version: str = '',
                      ip_address: str = '') -> None:
        """Store a new report for a device, upserting device metadata."""
        now = int(time.time())
        summary = report.get('summary', {})
        with self._lock, self._conn() as conn:
            conn.execute("""
                INSERT INTO devices
                    (device_id, hostname, platform, agent_version, ip_address, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(device_id) DO UPDATE SET
                    hostname      = excluded.hostname,
                    platform      = excluded.platform,
                    agent_version = excluded.agent_version,
                    ip_address    = CASE WHEN excluded.ip_address != '' THEN excluded.ip_address ELSE ip_address END,
                    last_seen     = excluded.last_seen
            """, (device_id, hostname, platform, agent_version, ip_address, now, now))

            conn.execute("""
                INSERT INTO reports
                    (device_id, received_at, scan_date, profile, mode, target,
                     fail_count, warn_count, pass_count, report_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                device_id, now,
                report.get('scan_date', ''),
                report.get('profile', ''),
                report.get('mode', ''),
                report.get('target', ''),
                summary.get('fail', 0),
                summary.get('warn', 0),
                summary.get('pass', 0),
                json.dumps(report),
            ))

    def list_devices(self) -> list[dict]:
        """Return all devices with their latest scan summary."""
        with self._lock, self._conn() as conn:
            rows = conn.execute("""
                SELECT
                    d.device_id, d.hostname, d.platform, d.agent_version,
                    d.first_seen, d.last_seen,
                    r.scan_date, r.profile, r.mode, r.target,
                    r.fail_count, r.warn_count, r.pass_count,
                    r.received_at AS report_time
                FROM devices d
                LEFT JOIN reports r
                    ON r.device_id = d.device_id
                    AND r.received_at = (
                        SELECT MAX(received_at) FROM reports
                        WHERE device_id = d.device_id
                    )
                ORDER BY d.last_seen DESC
            """).fetchall()
        return [dict(r) for r in rows]

    def list_agent_ips(self) -> set[str]:
        """Return the set of IP addresses for all registered agents."""
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                "SELECT ip_address FROM devices WHERE ip_address != ''"
            ).fetchall()
        return {r[0] for r in rows}

    def list_devices_by_profile(self, profiles: list[str]) -> list[dict]:
        """Return devices with their latest scan matching any of the given profile slugs.

        Each device row includes '_report' (full parsed report JSON) keyed to
        the most recent scan that matched the requested profiles — not the
        overall latest scan, which may be a different profile.
        """
        _SLUG_TO_DISPLAY = {
            'default':   'default (full suite)',
            'fedramp':   'fedramp moderate',
            'cmmc':      'cmmc level 2',
            'financial': 'financial services',
        }
        terms = set()
        for p in profiles:
            p = p.lower()
            terms.add(p)
            if p in _SLUG_TO_DISPLAY:
                terms.add(_SLUG_TO_DISPLAY[p])
        term_list = list(terms)
        ph = ','.join('?' * len(term_list))
        with self._lock, self._conn() as conn:
            rows = conn.execute(f"""
                SELECT
                    d.device_id, d.hostname, d.platform, d.agent_version,
                    d.first_seen, d.last_seen,
                    r.scan_date, r.profile, r.mode, r.target,
                    r.fail_count, r.warn_count, r.pass_count,
                    r.received_at AS report_time,
                    r.report_json
                FROM devices d
                JOIN reports r
                    ON r.device_id = d.device_id
                    AND r.received_at = (
                        SELECT MAX(r2.received_at) FROM reports r2
                        WHERE r2.device_id = d.device_id
                        AND LOWER(r2.profile) IN ({ph})
                    )
                WHERE LOWER(r.profile) IN ({ph})
                ORDER BY d.last_seen DESC
            """, term_list + term_list).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            d['_report'] = json.loads(d.pop('report_json'))
            result.append(d)
        return result

    def prune_old_reports(self, retention_days: int = 90) -> int:
        """Delete reports older than retention_days. Returns count deleted."""
        cutoff = int(time.time()) - (retention_days * 86400)
        with self._lock, self._conn() as conn:
            cur = conn.execute("DELETE FROM reports WHERE received_at < ?", (cutoff,))
            pruned = cur.rowcount
        return pruned

    def get_latest_report(self, device_id: str) -> dict | None:
        """Return the most recent full report JSON for a device."""
        with self._lock, self._conn() as conn:
            row = conn.execute("""
                SELECT report_json FROM reports
                WHERE device_id = ?
                ORDER BY received_at DESC LIMIT 1
            """, (device_id,)).fetchone()
        return json.loads(row['report_json']) if row else None

    def get_risk_register(self) -> list[dict]:
        """Return deduplicated open FAIL/WARN findings across all devices with trend info."""
        now = int(time.time())
        with self._lock, self._conn() as conn:
            latest_rows = conn.execute("""
                SELECT r.device_id, d.hostname, r.received_at, r.report_json
                FROM reports r
                JOIN devices d ON d.device_id = r.device_id
                WHERE r.received_at = (
                    SELECT MAX(r2.received_at) FROM reports r2 WHERE r2.device_id = r.device_id
                )
                ORDER BY r.received_at DESC
            """).fetchall()
            prev_rows = conn.execute("""
                SELECT r.device_id, r.report_json
                FROM reports r
                WHERE r.received_at = (
                    SELECT r2.received_at FROM reports r2
                    WHERE r2.device_id = r.device_id
                    ORDER BY r2.received_at DESC LIMIT 1 OFFSET 1
                )
            """).fetchall()

        prev_failing: dict[str, set] = {}
        for row in prev_rows:
            prev_data = json.loads(row['report_json'])
            prev_failing[row['device_id']] = {
                f['check_id'] for f in prev_data.get('findings', prev_data.get('results', []))
                if f.get('status') in ('FAIL', 'WARN')
            }

        findings_map: dict[str, dict] = {}
        for row in latest_rows:
            device_id = row['device_id']
            hostname = row['hostname']
            received_at = row['received_at']
            data = json.loads(row['report_json'])
            prev_ids = prev_failing.get(device_id, set())
            for f in data.get('findings', data.get('results', [])):
                if f.get('status') not in ('FAIL', 'WARN'):
                    continue
                check_id = f.get('check_id', '')
                if not check_id:
                    continue
                if check_id not in findings_map:
                    findings_map[check_id] = {
                        'check_id': check_id,
                        'title': f.get('title', ''),
                        'severity': f.get('severity', ''),
                        'category': f.get('category', ''),
                        'status': f.get('status', ''),
                        'affected_devices': [],
                        'recurring_count': 0,
                        'first_seen_ts': received_at,
                    }
                entry = findings_map[check_id]
                entry['affected_devices'].append(hostname)
                if check_id in prev_ids:
                    entry['recurring_count'] += 1
                entry['first_seen_ts'] = min(entry['first_seen_ts'], received_at)

        overrides = {}
        with self._lock, self._conn() as conn:
            for row in conn.execute("SELECT * FROM risk_overrides").fetchall():
                overrides[row['check_id']] = dict(row)

        result = []
        for entry in findings_map.values():
            affected_count = len(entry['affected_devices'])
            trend = 'Recurring' if entry['recurring_count'] > 0 else 'New'
            days_open = max(1, (now - entry['first_seen_ts']) // 86400)
            ov = overrides.get(entry['check_id'], {})
            result.append({
                'check_id': entry['check_id'],
                'title': entry['title'],
                'severity': entry['severity'],
                'category': entry['category'],
                'status': entry['status'],
                'affected_count': affected_count,
                'affected_devices': entry['affected_devices'][:10],
                'trend': trend,
                'days_open': days_open,
                'override_action':   ov.get('action', ''),
                'override_assignee': ov.get('assignee', ''),
                'override_note':     ov.get('note', ''),
                'override_expires':  ov.get('expires_at'),
                'override_by':       ov.get('created_by', ''),
            })

        sev_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        result.sort(key=lambda x: (sev_order.get(x['severity'], 99), -x['affected_count']))
        return result

    def upsert_risk_override(self, check_id: str, action: str, assignee: str,
                             note: str, expires_at: int | None,
                             created_by: str) -> None:
        now = int(time.time())
        with self._lock, self._conn() as conn:
            conn.execute("""
                INSERT INTO risk_overrides
                    (check_id, action, assignee, note, expires_at, created_by, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(check_id) DO UPDATE SET
                    action     = excluded.action,
                    assignee   = excluded.assignee,
                    note       = excluded.note,
                    expires_at = excluded.expires_at,
                    created_by = excluded.created_by,
                    updated_at = excluded.updated_at
            """, (check_id, action, assignee, note, expires_at, created_by, now, now))

    def delete_risk_override(self, check_id: str) -> bool:
        with self._lock, self._conn() as conn:
            cur = conn.execute("DELETE FROM risk_overrides WHERE check_id = ?", (check_id,))
            return cur.rowcount > 0

    def get_risk_overrides(self) -> list[dict]:
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM risk_overrides ORDER BY updated_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def get_device(self, device_id: str) -> dict | None:
        """Return device metadata row or None."""
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM devices WHERE device_id = ?", (device_id,)
            ).fetchone()
        return dict(row) if row else None

    def get_previous_report(self, device_id: str) -> dict | None:
        """Return the second-most-recent report for a device (used for new-finding detection)."""
        with self._lock, self._conn() as conn:
            row = conn.execute("""
                SELECT report_json FROM reports
                WHERE device_id = ?
                ORDER BY received_at DESC
                LIMIT 1 OFFSET 1
            """, (device_id,)).fetchone()
        return json.loads(row['report_json']) if row else None

    def get_all_latest_reports(self) -> list[dict]:
        """Return the latest report for every known device."""
        with self._lock, self._conn() as conn:
            rows = conn.execute("""
                SELECT r.device_id, d.hostname, r.report_json
                FROM reports r
                JOIN devices d ON d.device_id = r.device_id
                WHERE r.received_at = (
                    SELECT MAX(received_at) FROM reports r2
                    WHERE r2.device_id = r.device_id
                )
                ORDER BY r.received_at DESC
            """).fetchall()
        result = []
        for row in rows:
            rep = json.loads(row['report_json'])
            rep['_device_id'] = row['device_id']
            rep['_hostname']   = row['hostname']
            result.append(rep)
        return result

    def get_active_critical_high_findings(self) -> list[dict]:
        """Return CRITICAL/HIGH FAILs from the latest report per device, excluding overridden findings."""
        with self._lock, self._conn() as conn:
            overrides = {
                row['check_id']: row['action']
                for row in conn.execute("SELECT check_id, action FROM risk_overrides").fetchall()
            }
            rows = conn.execute("""
                SELECT r.device_id, d.hostname, r.received_at, r.report_json
                FROM reports r
                JOIN devices d ON d.device_id = r.device_id
                WHERE r.received_at = (
                    SELECT MAX(received_at) FROM reports r2
                    WHERE r2.device_id = r.device_id
                )
                ORDER BY r.received_at DESC
            """).fetchall()
        issues = []
        for row in rows:
            rep = json.loads(row['report_json'])
            for f in rep.get('findings', []):
                if (f.get('status') == 'FAIL'
                        and f.get('severity', '').upper() in ('CRITICAL', 'HIGH')):
                    check_id = f.get('check_id', '')
                    if overrides.get(check_id) in ('false_positive', 'accepted'):
                        continue
                    issues.append({
                        'device_id':  row['device_id'],
                        'hostname':   row['hostname'],
                        'last_seen':  row['received_at'],
                        'check_id':   check_id,
                        'title':      f.get('title', ''),
                        'severity':   f.get('severity', '').upper(),
                        'description': f.get('description', ''),
                    })
        issues.sort(key=lambda x: (0 if x['severity'] == 'CRITICAL' else 1, x['hostname']))
        return issues

    def device_count(self) -> int:
        with self._lock, self._conn() as conn:
            return conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]

    def touch_device(self, device_id: str) -> None:
        """Update last_seen for a device without changing any other fields (heartbeat)."""
        now = int(time.time())
        with self._lock, self._conn() as conn:
            conn.execute(
                "UPDATE devices SET last_seen = ? WHERE device_id = ?",
                (now, device_id),
            )

    def get_stale_devices(self, stale_after_seconds: int) -> list[dict]:
        """Return devices that have not reported since stale_after_seconds ago."""
        cutoff = int(time.time()) - stale_after_seconds
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                """SELECT device_id, hostname, platform, agent_version, last_seen
                   FROM devices WHERE last_seen < ?
                   ORDER BY last_seen ASC""",
                (cutoff,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_all_devices_summary(self) -> list[dict]:
        """Return lightweight device list for telemetry reporting."""
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                """SELECT device_id, hostname, platform, agent_version, last_seen
                   FROM devices ORDER BY last_seen DESC"""
            ).fetchall()
        return [dict(r) for r in rows]

    def is_known_device(self, device_id: str) -> bool:
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT 1 FROM devices WHERE device_id = ? LIMIT 1", (device_id,)
            ).fetchone()
        return row is not None

    def find_devices_by_hostname(self, hostname: str) -> list[dict]:
        """Return all device_ids that share a hostname (used for duplicate detection)."""
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                "SELECT device_id, hostname, platform, last_seen FROM devices WHERE hostname = ?",
                (hostname,),
            ).fetchall()
        return [dict(r) for r in rows]

    def log_license_event(self, event_type: str, device_id: str, hostname: str,
                          agent_count: int, max_agents: int) -> None:
        now = int(time.time())
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO license_events
                   (event_type, device_id, hostname, agent_count, max_agents, recorded_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (event_type, device_id, hostname, agent_count, max_agents, now),
            )

    def get_license_events(self, limit: int = 50) -> list[dict]:
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                """SELECT event_type, device_id, hostname, agent_count, max_agents, recorded_at
                   FROM license_events ORDER BY recorded_at DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def enqueue_command(self, device_id: str, command: str = 'scan_now') -> int:
        """Queue a command for a device. Returns the new command id."""
        now = int(time.time())
        with self._lock, self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO commands (device_id, command, created_at) VALUES (?, ?, ?)",
                (device_id, command, now),
            )
            return cur.lastrowid

    def claim_command(self, device_id: str) -> str | None:
        """Return and mark-claimed the oldest pending command for a device, or None."""
        now = int(time.time())
        with self._lock, self._conn() as conn:
            row = conn.execute(
                """SELECT id, command FROM commands
                   WHERE device_id = ? AND claimed_at IS NULL
                   ORDER BY created_at ASC LIMIT 1""",
                (device_id,),
            ).fetchone()
            if not row:
                return None
            conn.execute(
                "UPDATE commands SET claimed_at = ? WHERE id = ?",
                (now, row['id']),
            )
            return row['command']

    def pending_command_count(self, device_id: str) -> int:
        """Return how many unclaimed commands are queued for a device."""
        with self._lock, self._conn() as conn:
            return conn.execute(
                "SELECT COUNT(*) FROM commands WHERE device_id = ? AND claimed_at IS NULL",
                (device_id,),
            ).fetchone()[0]

    def delete_device(self, device_id: str) -> bool:
        """Remove a device and all its reports/commands. Returns True if found."""
        with self._lock, self._conn() as conn:
            cur = conn.execute("DELETE FROM reports WHERE device_id = ?", (device_id,))
            conn.execute("DELETE FROM commands WHERE device_id = ?", (device_id,))
            conn.execute("DELETE FROM devices WHERE device_id = ?", (device_id,))
            return cur.rowcount > 0

    def upsert_shadow_device(self, reporter_device_id: str, reporter_hostname: str,
                             host: str, port: int, service: str, models: list,
                             source: str = 'network', detail: str = '') -> bool:
        """Upsert a shadow device. Returns True if this is a brand-new discovery."""
        now = int(time.time())
        with self._lock, self._conn() as conn:
            # New entries auto-approve if the service is on the global approved list
            globally_approved = conn.execute(
                "SELECT 1 FROM approved_services WHERE service=?", (service,)
            ).fetchone() is not None
            auto_status = 'approved' if globally_approved else 'unapproved'

            existing = conn.execute(
                "SELECT id FROM shadow_devices WHERE source=? AND reporter_device_id=? AND host=? AND port=?",
                (source, reporter_device_id, host, port)
            ).fetchone()
            is_new = existing is None
            conn.execute("""
                INSERT INTO shadow_devices
                    (reporter_device_id, reporter_hostname, host, port, service,
                     models_json, source, detail, first_seen, last_seen, dismissed,
                     approval_status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)
                ON CONFLICT(source, reporter_device_id, host, port) DO UPDATE SET
                    reporter_hostname  = excluded.reporter_hostname,
                    service            = excluded.service,
                    models_json        = excluded.models_json,
                    detail             = excluded.detail,
                    last_seen          = excluded.last_seen,
                    dismissed          = 0
            """, (reporter_device_id, reporter_hostname, host, port, service,
                  json.dumps(models), source, detail, now, now, auto_status))
        return is_new

    def list_shadow_devices(self, max_age_days: int = 7) -> list[dict]:
        cutoff = int(time.time()) - (max_age_days * 86400)
        with self._lock, self._conn() as conn:
            rows = conn.execute("""
                SELECT id, reporter_device_id, reporter_hostname, host, port,
                       service, models_json, source, detail, first_seen, last_seen
                FROM shadow_devices
                WHERE dismissed = 0 AND last_seen >= ?
                ORDER BY source ASC, last_seen DESC
            """, (cutoff,)).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            d['models'] = json.loads(d.pop('models_json', '[]'))
            result.append(d)
        return result

    def dismiss_shadow_device(self, shadow_id: int) -> bool:
        with self._lock, self._conn() as conn:
            cur = conn.execute(
                "UPDATE shadow_devices SET dismissed = 1 WHERE id = ?", (shadow_id,)
            )
            return cur.rowcount > 0

    def dismiss_all_shadow_devices(self) -> int:
        with self._lock, self._conn() as conn:
            cur = conn.execute("UPDATE shadow_devices SET dismissed = 1 WHERE dismissed = 0")
            return cur.rowcount

    def shadow_device_count(self) -> int:
        with self._lock, self._conn() as conn:
            return conn.execute(
                "SELECT COUNT(*) FROM shadow_devices WHERE dismissed = 0"
            ).fetchone()[0]

    def add_schedule(self, device_id: str, cadence: str, hour: int,
                     profile: str, label: str = '',
                     weekday: int | None = None, monthday: int | None = None,
                     interval_hours: int = 0) -> int:
        now = int(time.time())
        with self._lock, self._conn() as conn:
            cur = conn.execute("""
                INSERT INTO scan_schedules
                    (device_id, cadence, hour, weekday, monthday, profile, label, enabled, created_at, interval_hours)
                VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
            """, (device_id, cadence, hour, weekday, monthday, profile, label, now, interval_hours))
            return cur.lastrowid

    def list_schedules(self) -> list[dict]:
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM scan_schedules ORDER BY created_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def delete_schedule(self, schedule_id: int) -> bool:
        with self._lock, self._conn() as conn:
            cur = conn.execute("DELETE FROM scan_schedules WHERE id = ?", (schedule_id,))
            return cur.rowcount > 0

    def toggle_schedule(self, schedule_id: int) -> bool:
        with self._lock, self._conn() as conn:
            cur = conn.execute(
                "UPDATE scan_schedules SET enabled = 1 - enabled WHERE id = ?", (schedule_id,)
            )
            return cur.rowcount > 0

    def get_due_schedules(self) -> list[dict]:
        """Return enabled schedules that are due to fire right now."""
        import datetime as _dt
        now_ts = int(time.time())
        now_utc = _dt.datetime.utcnow()
        h, wd, md = now_utc.hour, now_utc.weekday(), now_utc.day
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM scan_schedules WHERE enabled = 1"
            ).fetchall()
        due = []
        for row in rows:
            r = dict(row)
            last = r.get('last_fired') or 0
            cadence = r['cadence']
            elapsed = now_ts - last
            if cadence == 'hourly':
                if elapsed >= 3540:  # 59 min — fire every hour
                    due.append(r)
            elif cadence == 'interval':
                ih = max(1, int(r.get('interval_hours') or 1))
                if elapsed >= (ih * 3600 - 300):  # 5-min tolerance
                    due.append(r)
            elif cadence == 'daily':
                if r['hour'] == h and elapsed >= 82800:
                    due.append(r)
            elif cadence == 'weekly':
                if r['hour'] == h and r.get('weekday') == wd and elapsed >= 604800 - 3600:
                    due.append(r)
            elif cadence == 'monthly':
                if r['hour'] == h and r.get('monthday') == md and elapsed >= 2419200 - 3600:
                    due.append(r)
        return due

    def mark_schedule_fired(self, schedule_id: int) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                "UPDATE scan_schedules SET last_fired = ? WHERE id = ?",
                (int(time.time()), schedule_id),
            )

    def list_inventory(self) -> list[dict]:
        """Return all shadow devices (inc. dismissed) as the formal AI asset inventory."""
        with self._lock, self._conn() as conn:
            rows = conn.execute("""
                SELECT id, reporter_hostname, host, port, service, models_json,
                       source, detail, first_seen, last_seen, dismissed,
                       approval_status, approved_by, approved_at,
                       false_positive, notes
                FROM shadow_devices
                ORDER BY false_positive ASC, approval_status ASC, last_seen DESC
            """).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            d['models'] = json.loads(d.pop('models_json', '[]'))
            result.append(d)
        return result

    def set_shadow_approval(self, shadow_id: int, status: str,
                            changed_by: str = '', ip_address: str = '') -> bool:
        """Set approval_status for a shadow device and record the attribution event."""
        if status not in ('approved', 'under_review', 'unapproved'):
            return False
        now = int(time.time())
        actor = changed_by.strip() or 'Dashboard user'
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT approval_status FROM shadow_devices WHERE id = ?", (shadow_id,)
            ).fetchone()
            if row is None:
                return False
            from_status = row['approval_status'] or 'unapproved'
            cur = conn.execute(
                """UPDATE shadow_devices
                   SET approval_status = ?, approved_by = ?, approved_at = ?
                   WHERE id = ?""",
                (status, actor, now, shadow_id),
            )
            if cur.rowcount == 0:
                return False
            conn.execute(
                """INSERT INTO approval_events
                       (shadow_id, from_status, to_status, changed_by, ip_address, changed_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (shadow_id, from_status, status, actor, ip_address, now),
            )
            return True

    def set_false_positive(self, shadow_id: int, is_fp: bool,
                           notes: str = '', changed_by: str = '',
                           ip_address: str = '') -> bool:
        """Mark/unmark a shadow device as a false positive with an optional note."""
        now = int(time.time())
        actor = changed_by.strip() or 'Dashboard user'
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT approval_status FROM shadow_devices WHERE id = ?", (shadow_id,)
            ).fetchone()
            if row is None:
                return False
            from_status = row['approval_status'] or 'unapproved'
            to_status = 'false_positive' if is_fp else from_status
            conn.execute(
                """UPDATE shadow_devices
                   SET false_positive = ?, notes = ?, approved_by = ?, approved_at = ?
                   WHERE id = ?""",
                (1 if is_fp else 0, notes.strip(), actor, now, shadow_id),
            )
            conn.execute(
                """INSERT INTO approval_events
                       (shadow_id, from_status, to_status, changed_by, ip_address, changed_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (shadow_id, from_status,
                 'false_positive' if is_fp else 'fp_cleared',
                 actor, ip_address, now),
            )
            return True

    def get_approval_history(self, shadow_id: int) -> list[dict]:
        """Return full approval event history for one asset, newest first."""
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                """SELECT from_status, to_status, changed_by, ip_address, changed_at
                   FROM approval_events WHERE shadow_id = ?
                   ORDER BY changed_at DESC""",
                (shadow_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_all_approval_events(self) -> list[dict]:
        """Return all approval events across all assets for evidence export."""
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                """SELECT ae.id, ae.shadow_id, sd.host, sd.port, sd.service,
                          ae.from_status, ae.to_status, ae.changed_by,
                          ae.ip_address, ae.changed_at
                   FROM approval_events ae
                   JOIN shadow_devices sd ON sd.id = ae.shadow_id
                   ORDER BY ae.changed_at DESC""",
            ).fetchall()
        return [dict(r) for r in rows]

    def is_service_approved(self, service: str) -> bool:
        with self._lock, self._conn() as conn:
            return conn.execute(
                "SELECT 1 FROM approved_services WHERE service=?", (service,)
            ).fetchone() is not None

    def approve_service_globally(self, service: str, approved_by: str = '') -> None:
        now = int(time.time())
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO approved_services (service, approved_by, approved_at) VALUES (?,?,?)
                   ON CONFLICT(service) DO UPDATE SET approved_by=excluded.approved_by, approved_at=excluded.approved_at""",
                (service, approved_by, now),
            )
            # Bulk-approve all existing unapproved entries for this service name
            conn.execute(
                "UPDATE shadow_devices SET approval_status='approved', approved_by=?, approved_at=? WHERE service=? AND approval_status='unapproved'",
                (approved_by, now, service),
            )

    def unapprove_service_globally(self, service: str) -> None:
        with self._lock, self._conn() as conn:
            conn.execute("DELETE FROM approved_services WHERE service=?", (service,))

    def list_approved_services(self) -> list[str]:
        with self._lock, self._conn() as conn:
            return [r[0] for r in conn.execute(
                "SELECT service FROM approved_services ORDER BY service"
            ).fetchall()]

    # ── Alert event log ───────────────────────────────────────────────────────

    def log_alert_event(self, event_type: str, severity: str, device: str,
                        service: str = '', host: str = '', check_id: str = '',
                        title: str = '', source: str = '', channels: str = '') -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO alert_events
                       (ts, event_type, severity, device, service, host,
                        check_id, title, source, channels)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (int(time.time()), event_type, severity, device,
                 service, host, check_id, title, source, channels),
            )

    def was_alert_recently_fired(self, event_type: str, device: str,
                                  dedup_key: str, within_seconds: int = 86400) -> bool:
        """Return True if the same alert already fired within the cooldown window."""
        cutoff = int(time.time()) - within_seconds
        with self._lock, self._conn() as conn:
            row = conn.execute(
                """SELECT 1 FROM alert_events
                   WHERE event_type=? AND device=? AND (service=? OR check_id=?) AND ts>?
                   LIMIT 1""",
                (event_type, device, dedup_key, dedup_key, cutoff),
            ).fetchone()
        return row is not None

    def get_alert_events(self, limit: int = 300, unreviewed_only: bool = False) -> list[dict]:
        sql = ("SELECT id, ts, event_type, severity, device, service, host, "
               "check_id, title, source, channels, reviewed FROM alert_events")
        if unreviewed_only:
            sql += " WHERE reviewed=0"
        sql += " ORDER BY ts DESC LIMIT ?"
        with self._lock, self._conn() as conn:
            rows = conn.execute(sql, (limit,)).fetchall()
        return [
            {'id': r[0], 'ts': r[1], 'event_type': r[2], 'severity': r[3],
             'device': r[4], 'service': r[5], 'host': r[6], 'check_id': r[7],
             'title': r[8], 'source': r[9], 'channels': r[10], 'reviewed': bool(r[11])}
            for r in rows
        ]

    def count_unreviewed_alerts(self) -> int:
        with self._lock, self._conn() as conn:
            return conn.execute(
                "SELECT COUNT(*) FROM alert_events WHERE reviewed=0"
            ).fetchone()[0]

    def mark_alert_reviewed(self, event_id: int) -> None:
        with self._lock, self._conn() as conn:
            conn.execute("UPDATE alert_events SET reviewed=1 WHERE id=?", (event_id,))

    def mark_all_alerts_reviewed(self) -> None:
        with self._lock, self._conn() as conn:
            conn.execute("UPDATE alert_events SET reviewed=1 WHERE reviewed=0")

    def upsert_mcp_server(self, reporter_device_id: str, reporter_hostname: str,
                          host: str, port: int, server_name: str, tools: list,
                          auth_status: str = 'unknown', source: str = 'network',
                          process_info: str = '') -> None:
        now = int(time.time())
        with self._lock, self._conn() as conn:
            conn.execute("""
                INSERT INTO mcp_servers
                    (reporter_device_id, reporter_hostname, host, port, server_name,
                     tools_json, auth_status, source, process_info, first_seen, last_seen, dismissed)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                ON CONFLICT(reporter_device_id, host, port, source) DO UPDATE SET
                    reporter_hostname = excluded.reporter_hostname,
                    server_name  = CASE WHEN excluded.server_name != '' THEN excluded.server_name ELSE server_name END,
                    tools_json   = excluded.tools_json,
                    auth_status  = excluded.auth_status,
                    process_info = excluded.process_info,
                    last_seen    = excluded.last_seen,
                    dismissed    = 0
            """, (reporter_device_id, reporter_hostname, host, port, server_name,
                  json.dumps(tools), auth_status, source, process_info, now, now))

    def list_mcp_servers(self) -> list[dict]:
        with self._lock, self._conn() as conn:
            rows = conn.execute("""
                SELECT id, reporter_device_id, reporter_hostname, host, port,
                       server_name, tools_json, auth_status, source, process_info,
                       first_seen, last_seen
                FROM mcp_servers
                WHERE dismissed = 0
                ORDER BY auth_status ASC, last_seen DESC
            """).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            d['tools'] = json.loads(d.pop('tools_json', '[]'))
            result.append(d)
        return result

    def dismiss_mcp_server(self, mcp_id: int) -> bool:
        with self._lock, self._conn() as conn:
            cur = conn.execute(
                "UPDATE mcp_servers SET dismissed = 1 WHERE id = ?", (mcp_id,)
            )
            return cur.rowcount > 0

    def dismiss_all_mcp_servers(self) -> int:
        with self._lock, self._conn() as conn:
            cur = conn.execute("UPDATE mcp_servers SET dismissed = 1 WHERE dismissed = 0")
            return cur.rowcount

    def mcp_server_count(self) -> int:
        with self._lock, self._conn() as conn:
            return conn.execute(
                "SELECT COUNT(*) FROM mcp_servers WHERE dismissed = 0"
            ).fetchone()[0]

    def get_device_timeseries(self, device_id: str) -> list[dict]:
        """Return ordered list of {t, fail, warn, pass} scan history points for a device."""
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                "SELECT received_at, fail_count, warn_count, pass_count FROM reports "
                "WHERE device_id = ? ORDER BY received_at ASC",
                (device_id,),
            ).fetchall()
        return [
            {'t': int(r['received_at']), 'fail': int(r['fail_count']),
             'warn': int(r['warn_count']), 'pass': int(r['pass_count'])}
            for r in rows
        ]


# ── Customer registry + dashboard auth (central DB, one record per customer) ──

_REGISTRY_SESSION_TTL = 8 * 3600


class CustomerRegistry:
    """
    Central registry: one record per customer, all dashboard users and sessions.
    Lives at data/customers.db — separate from per-customer agents.db files.
    """

    def __init__(self, db_path: Path):
        self._path = Path(db_path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._path), check_same_thread=False, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self) -> None:
        with self._lock, self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS customers (
                    id                   TEXT PRIMARY KEY,
                    name                 TEXT NOT NULL,
                    agent_token          TEXT UNIQUE NOT NULL,
                    agent_token_prev     TEXT DEFAULT NULL,
                    token_prev_expires   INTEGER DEFAULT 0,
                    created_at           INTEGER NOT NULL,
                    active               INTEGER NOT NULL DEFAULT 1
                );

                CREATE TABLE IF NOT EXISTS dashboard_users (
                    id            TEXT PRIMARY KEY,
                    customer_id   TEXT NOT NULL REFERENCES customers(id),
                    email         TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role          TEXT NOT NULL DEFAULT 'admin',
                    created_at    INTEGER NOT NULL,
                    active        INTEGER NOT NULL DEFAULT 1
                );

                CREATE INDEX IF NOT EXISTS idx_du_customer
                    ON dashboard_users(customer_id, active);

                CREATE TABLE IF NOT EXISTS dashboard_sessions (
                    token       TEXT PRIMARY KEY,
                    user_id     TEXT NOT NULL REFERENCES dashboard_users(id),
                    customer_id TEXT NOT NULL REFERENCES customers(id),
                    email       TEXT NOT NULL,
                    created_at  INTEGER NOT NULL,
                    expires_at  INTEGER NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ds_expires
                    ON dashboard_sessions(expires_at);
            """)

    # ── password helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _hash_pw(password: str) -> str:
        import hashlib
        import secrets
        salt = secrets.token_hex(16)
        dk = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode(), 260_000)
        return f'pbkdf2:sha256:260000:{salt}:{dk.hex()}'

    @staticmethod
    def _verify_pw(password: str, stored: str) -> bool:
        import hashlib
        import hmac as _hmac
        try:
            _, algo, iters, salt, dk_hex = stored.split(':')
            dk = hashlib.pbkdf2_hmac(algo, password.encode('utf-8'), salt.encode(), int(iters))
            return _hmac.compare_digest(dk.hex(), dk_hex)
        except Exception:
            return False

    # ── customer management ───────────────────────────────────────────────────

    def has_customers(self) -> bool:
        with self._lock, self._conn() as conn:
            return conn.execute(
                'SELECT 1 FROM customers WHERE active=1 LIMIT 1'
            ).fetchone() is not None

    def create_customer(self, name: str) -> dict:
        import uuid
        import secrets
        cid = str(uuid.uuid4())
        token = secrets.token_urlsafe(32)
        now = int(time.time())
        with self._lock, self._conn() as conn:
            conn.execute(
                'INSERT INTO customers (id, name, agent_token, created_at, active) VALUES (?,?,?,?,1)',
                (cid, name.strip(), token, now),
            )
        return {'id': cid, 'name': name.strip(), 'agent_token': token}

    def list_customers(self) -> list[dict]:
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                'SELECT id, name, agent_token, created_at, active FROM customers ORDER BY created_at DESC'
            ).fetchall()
        return [dict(r) for r in rows]

    def get_by_agent_token(self, token: str) -> dict | None:
        if not token:
            return None
        with self._lock, self._conn() as conn:
            # Try current token first
            row = conn.execute(
                'SELECT id, name, agent_token FROM customers WHERE agent_token=? AND active=1',
                (token,),
            ).fetchone()
            if row:
                return {'id': row['id'], 'name': row['name'], 'using_old_token': False}
            # Try previous token within rollover window
            now = int(time.time())
            row = conn.execute(
                '''SELECT id, name, agent_token FROM customers
                   WHERE agent_token_prev=? AND active=1 AND token_prev_expires>?''',
                (token, now),
            ).fetchone()
            if row:
                return {
                    'id': row['id'],
                    'name': row['name'],
                    'new_token': row['agent_token'],
                    'using_old_token': True,
                }
        return None

    def get_by_id(self, customer_id: str) -> dict | None:
        with self._lock, self._conn() as conn:
            row = conn.execute(
                'SELECT id, name, agent_token FROM customers WHERE id=? AND active=1', (customer_id,)
            ).fetchone()
        return dict(row) if row else None

    def rotate_agent_token(self, customer_id: str, rollover_hours: int = 48) -> str:
        """Replace the agent token, keeping the old one valid for rollover_hours.
        Returns the new token. Agents still using the old token receive the new
        one in their next check-in response and self-update."""
        import secrets
        new_token = secrets.token_urlsafe(32)
        expires = int(time.time()) + rollover_hours * 3600
        with self._lock, self._conn() as conn:
            # Migrate schema if columns don't exist yet (live upgrade path)
            cols = {r[1] for r in conn.execute('PRAGMA table_info(customers)').fetchall()}
            if 'agent_token_prev' not in cols:
                conn.execute('ALTER TABLE customers ADD COLUMN agent_token_prev TEXT DEFAULT NULL')
            if 'token_prev_expires' not in cols:
                conn.execute('ALTER TABLE customers ADD COLUMN token_prev_expires INTEGER DEFAULT 0')
            # Move current token → previous, set new token
            conn.execute(
                '''UPDATE customers
                   SET agent_token_prev=agent_token, token_prev_expires=?, agent_token=?
                   WHERE id=?''',
                (expires, new_token, customer_id),
            )
        return new_token

    def token_rollout_status(self, customer_id: str) -> dict | None:
        """Return rollover state: new token expiry and whether a rollover is active."""
        with self._lock, self._conn() as conn:
            row = conn.execute(
                'SELECT agent_token_prev, token_prev_expires FROM customers WHERE id=? AND active=1',
                (customer_id,),
            ).fetchone()
        if not row:
            return None
        now = int(time.time())
        active = bool(row['agent_token_prev'] and row['token_prev_expires'] > now)
        return {
            'rollover_active': active,
            'expires_at': row['token_prev_expires'] if active else None,
            'seconds_remaining': max(0, row['token_prev_expires'] - now) if active else 0,
        }

    # ── dashboard user management ─────────────────────────────────────────────

    def create_user(self, customer_id: str, email: str, password: str, role: str = 'admin') -> dict:
        import uuid
        uid = str(uuid.uuid4())
        now = int(time.time())
        with self._lock, self._conn() as conn:
            conn.execute(
                'INSERT INTO dashboard_users '
                '(id, customer_id, email, password_hash, role, created_at, active) '
                'VALUES (?,?,?,?,?,?,1)',
                (uid, customer_id, email.lower().strip(), self._hash_pw(password), role, now),
            )
        return {'id': uid, 'customer_id': customer_id,
                'email': email.lower().strip(), 'role': role}

    def authenticate_user(self, email: str, password: str) -> dict | None:
        with self._lock, self._conn() as conn:
            row = conn.execute(
                'SELECT id, customer_id, email, password_hash, role FROM dashboard_users '
                'WHERE email=? AND active=1',
                (email.lower().strip(),),
            ).fetchone()
        if row is None or not self._verify_pw(password, row['password_hash']):
            return None
        return {'id': row['id'], 'customer_id': row['customer_id'],
                'email': row['email'], 'role': row['role']}

    def list_users(self, customer_id: str) -> list[dict]:
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                'SELECT id, email, role, created_at, active FROM dashboard_users '
                'WHERE customer_id=? ORDER BY created_at ASC',
                (customer_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def deactivate_user(self, user_id: str, customer_id: str) -> bool:
        with self._lock, self._conn() as conn:
            cur = conn.execute(
                'UPDATE dashboard_users SET active=0 WHERE id=? AND customer_id=?',
                (user_id, customer_id),
            )
            if cur.rowcount:
                conn.execute('DELETE FROM dashboard_sessions WHERE user_id=?', (user_id,))
            return cur.rowcount > 0

    def change_user_password(self, user_id: str, customer_id: str, new_password: str) -> bool:
        with self._lock, self._conn() as conn:
            cur = conn.execute(
                'UPDATE dashboard_users SET password_hash=? WHERE id=? AND customer_id=? AND active=1',
                (self._hash_pw(new_password), user_id, customer_id),
            )
            return cur.rowcount > 0

    # ── session management ────────────────────────────────────────────────────

    def create_session(self, user_id: str, customer_id: str, email: str) -> str:
        import secrets
        token = secrets.token_urlsafe(32)
        now = int(time.time())
        with self._lock, self._conn() as conn:
            conn.execute(
                'INSERT INTO dashboard_sessions '
                '(token, user_id, customer_id, email, created_at, expires_at) '
                'VALUES (?,?,?,?,?,?)',
                (token, user_id, customer_id, email, now, now + _REGISTRY_SESSION_TTL),
            )
        return token

    def get_session(self, token: str) -> dict | None:
        if not token:
            return None
        now = int(time.time())
        with self._lock, self._conn() as conn:
            row = conn.execute(
                'SELECT s.user_id, s.customer_id, s.email, u.role '
                'FROM dashboard_sessions s '
                'JOIN dashboard_users u ON u.id = s.user_id '
                'WHERE s.token=? AND s.expires_at>? AND u.active=1',
                (token, now),
            ).fetchone()
        return dict(row) if row else None

    def delete_session(self, token: str) -> None:
        with self._lock, self._conn() as conn:
            conn.execute('DELETE FROM dashboard_sessions WHERE token=?', (token,))

    def prune_expired_sessions(self) -> None:
        now = int(time.time())
        with self._lock, self._conn() as conn:
            conn.execute('DELETE FROM dashboard_sessions WHERE expires_at<?', (now,))
