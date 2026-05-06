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
        conn = sqlite3.connect(str(self._path), check_same_thread=False)
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
            """)

        # Prune old reports per retention policy (env var or default 90 days)
        self.prune_old_reports(int(os.environ.get('SENTINEL_RETAIN_DAYS', '90')))

    def upsert_report(self, device_id: str, hostname: str, report: dict,
                      platform: str = '', agent_version: str = '') -> None:
        """Store a new report for a device, upserting device metadata."""
        now = int(time.time())
        summary = report.get('summary', {})
        with self._lock, self._conn() as conn:
            conn.execute("""
                INSERT INTO devices
                    (device_id, hostname, platform, agent_version, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(device_id) DO UPDATE SET
                    hostname      = excluded.hostname,
                    platform      = excluded.platform,
                    agent_version = excluded.agent_version,
                    last_seen     = excluded.last_seen
            """, (device_id, hostname, platform, agent_version, now, now))

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
        with self._conn() as conn:
            row = conn.execute("""
                SELECT report_json FROM reports
                WHERE device_id = ?
                ORDER BY received_at DESC LIMIT 1
            """, (device_id,)).fetchone()
        return json.loads(row['report_json']) if row else None

    def get_device(self, device_id: str) -> dict | None:
        """Return device metadata row or None."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM devices WHERE device_id = ?", (device_id,)
            ).fetchone()
        return dict(row) if row else None

    def get_all_latest_reports(self) -> list[dict]:
        """Return the latest report for every known device."""
        with self._conn() as conn:
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
        with self._conn() as conn:
            return conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]

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
        with self._conn() as conn:
            return conn.execute(
                "SELECT COUNT(*) FROM commands WHERE device_id = ? AND claimed_at IS NULL",
                (device_id,),
            ).fetchone()[0]
