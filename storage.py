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
            """)
            # Migration: add ip_address column to existing databases
            cols = {r[1] for r in conn.execute("PRAGMA table_info(devices)")}
            if 'ip_address' not in cols:
                conn.execute("ALTER TABLE devices ADD COLUMN ip_address TEXT NOT NULL DEFAULT ''")

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
            'smb':       'smb basic',
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
            conn.execute("DELETE FROM devices WHERE device_id NOT IN (SELECT DISTINCT device_id FROM reports)")
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

    def get_device(self, device_id: str) -> dict | None:
        """Return device metadata row or None."""
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM devices WHERE device_id = ?", (device_id,)
            ).fetchone()
        return dict(row) if row else None

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

    def device_count(self) -> int:
        with self._lock, self._conn() as conn:
            return conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]

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
                             source: str = 'network', detail: str = '') -> None:
        now = int(time.time())
        with self._lock, self._conn() as conn:
            conn.execute("""
                INSERT INTO shadow_devices
                    (reporter_device_id, reporter_hostname, host, port, service,
                     models_json, source, detail, first_seen, last_seen, dismissed)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
                ON CONFLICT(source, reporter_device_id, host, port) DO UPDATE SET
                    reporter_hostname  = excluded.reporter_hostname,
                    service            = excluded.service,
                    models_json        = excluded.models_json,
                    detail             = excluded.detail,
                    last_seen          = excluded.last_seen,
                    dismissed          = 0
            """, (reporter_device_id, reporter_hostname, host, port, service,
                  json.dumps(models), source, detail, now, now))

    def list_shadow_devices(self) -> list[dict]:
        with self._lock, self._conn() as conn:
            rows = conn.execute("""
                SELECT id, reporter_device_id, reporter_hostname, host, port,
                       service, models_json, source, detail, first_seen, last_seen
                FROM shadow_devices
                WHERE dismissed = 0
                ORDER BY source ASC, last_seen DESC
            """).fetchall()
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

    def shadow_device_count(self) -> int:
        with self._lock, self._conn() as conn:
            return conn.execute(
                "SELECT COUNT(*) FROM shadow_devices WHERE dismissed = 0"
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
