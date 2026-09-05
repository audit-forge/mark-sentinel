#!/usr/bin/env python3
"""
RiskRaven Arckon — Agent storage layer (SQLite dev / PostgreSQL prod)

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

                CREATE TABLE IF NOT EXISTS network_assets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    reporter_device_id TEXT NOT NULL,
                    ip_address TEXT NOT NULL,
                    mac_address TEXT NOT NULL DEFAULT '',
                    interface TEXT NOT NULL DEFAULT '',
                    source TEXT NOT NULL,
                    hostname TEXT NOT NULL DEFAULT '',
                    port INTEGER NOT NULL DEFAULT 0,
                    service TEXT NOT NULL DEFAULT '',
                    first_seen INTEGER NOT NULL,
                    last_seen INTEGER NOT NULL,
                    UNIQUE(reporter_device_id, ip_address, mac_address, interface, source)
                );
                CREATE INDEX IF NOT EXISTS idx_network_assets_reporter_seen
                    ON network_assets(reporter_device_id, last_seen DESC);

                CREATE TABLE IF NOT EXISTS network_asset_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    reporter_device_id TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    scope TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL,
                    detail TEXT NOT NULL DEFAULT '',
                    completed_at INTEGER NOT NULL
                );

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

                CREATE TABLE IF NOT EXISTS ai_spend (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    provider      TEXT NOT NULL,
                    model         TEXT NOT NULL DEFAULT '',
                    period_date   TEXT NOT NULL,
                    client_org_id TEXT NOT NULL DEFAULT '',
                    key_id        TEXT NOT NULL DEFAULT '',
                    key_label     TEXT NOT NULL DEFAULT '',
                    key_last4     TEXT NOT NULL DEFAULT '',
                    input_tokens  INTEGER NOT NULL DEFAULT 0,
                    output_tokens INTEGER NOT NULL DEFAULT 0,
                    total_tokens  INTEGER NOT NULL DEFAULT 0,
                    cost_usd      REAL NOT NULL DEFAULT 0.0,
                    currency      TEXT NOT NULL DEFAULT 'USD',
                    request_count INTEGER,
                    raw_snapshot  TEXT NOT NULL DEFAULT '',
                    fetched_at    INTEGER NOT NULL,
                    UNIQUE(provider, model, period_date, client_org_id, key_id)
                );

                CREATE INDEX IF NOT EXISTS idx_ai_spend_period
                    ON ai_spend(period_date DESC);
                CREATE INDEX IF NOT EXISTS idx_ai_spend_provider_period
                    ON ai_spend(provider, period_date DESC);
                CREATE INDEX IF NOT EXISTS idx_ai_spend_model
                    ON ai_spend(model);
                CREATE INDEX IF NOT EXISTS idx_ai_spend_client_org
                    ON ai_spend(client_org_id, period_date DESC);
                CREATE INDEX IF NOT EXISTS idx_ai_spend_key
                    ON ai_spend(key_id, period_date DESC);

                -- Protected Files monitoring (FedRAMP-aligned AI access detection)
                -- SC-13: protected_paths.path is encrypted at rest (AES-256-GCM via crypto.py)
                CREATE TABLE IF NOT EXISTS protected_paths (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id   TEXT NOT NULL,
                    path        TEXT NOT NULL,
                    path_hash   TEXT NOT NULL,
                    recursive   INTEGER NOT NULL DEFAULT 1,
                    actions     TEXT NOT NULL DEFAULT 'read,write,open',
                    created_by  TEXT NOT NULL DEFAULT '',
                    created_at  INTEGER NOT NULL,
                    updated_at  INTEGER NOT NULL,
                    UNIQUE(device_id, path_hash)
                );
                CREATE INDEX IF NOT EXISTS idx_protected_paths_device
                    ON protected_paths(device_id);

                -- AU-2: access_events form a tamper-evident SHA-256 hash chain
                CREATE TABLE IF NOT EXISTS access_events (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts          INTEGER NOT NULL,
                    device_id   TEXT NOT NULL,
                    hostname    TEXT NOT NULL DEFAULT '',
                    platform    TEXT NOT NULL DEFAULT '',
                    process     TEXT NOT NULL,
                    pid         INTEGER NOT NULL DEFAULT 0,
                    path        TEXT NOT NULL,
                    action      TEXT NOT NULL,
                    source      TEXT NOT NULL DEFAULT '',
                    prev_hash   TEXT NOT NULL DEFAULT '',
                    event_hash  TEXT NOT NULL,
                    reviewed    INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_access_events_ts
                    ON access_events(ts DESC);
                CREATE INDEX IF NOT EXISTS idx_access_events_device
                    ON access_events(device_id, ts DESC);
                CREATE INDEX IF NOT EXISTS idx_access_events_unreviewed
                    ON access_events(reviewed, ts DESC);

                -- CM-2/CM-6: audit log of all protected-path policy changes
                CREATE TABLE IF NOT EXISTS protected_paths_audit (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts          INTEGER NOT NULL,
                    action      TEXT NOT NULL,
                    device_id   TEXT NOT NULL,
                    path        TEXT NOT NULL,
                    changed_by  TEXT NOT NULL,
                    details     TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_protected_paths_audit_ts
                    ON protected_paths_audit(ts DESC);

                -- Protected Cloud Assets: policies are scope-constrained and
                -- event metadata is tamper-evident. No object contents or raw
                -- provider payloads are retained.
                CREATE TABLE IF NOT EXISTS protected_cloud_assets (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    provider        TEXT NOT NULL,
                    resource_type   TEXT NOT NULL,
                    account_id      TEXT NOT NULL DEFAULT '',
                    resource_scope  TEXT NOT NULL,
                    tag_key         TEXT NOT NULL DEFAULT '',
                    tag_value       TEXT NOT NULL DEFAULT '',
                    created_by      TEXT NOT NULL DEFAULT '',
                    created_at      INTEGER NOT NULL,
                    updated_at      INTEGER NOT NULL,
                    UNIQUE(provider, resource_type, account_id, resource_scope, tag_key, tag_value)
                );
                CREATE TABLE IF NOT EXISTS protected_cloud_asset_events (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts              INTEGER NOT NULL,
                    provider        TEXT NOT NULL,
                    resource_type   TEXT NOT NULL,
                    account_id      TEXT NOT NULL DEFAULT '',
                    region          TEXT NOT NULL DEFAULT '',
                    resource        TEXT NOT NULL,
                    actor           TEXT NOT NULL,
                    action          TEXT NOT NULL,
                    event_name      TEXT NOT NULL,
                    external_id     TEXT NOT NULL DEFAULT '',
                    policy_id       INTEGER NOT NULL,
                    prev_hash       TEXT NOT NULL DEFAULT '',
                    event_hash      TEXT NOT NULL,
                    reviewed        INTEGER NOT NULL DEFAULT 0,
                    UNIQUE(provider, external_id)
                );
                CREATE INDEX IF NOT EXISTS idx_cloud_asset_events_ts
                    ON protected_cloud_asset_events(ts DESC);
                CREATE TABLE IF NOT EXISTS protected_cloud_assets_audit (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts              INTEGER NOT NULL,
                    action          TEXT NOT NULL,
                    policy_id       INTEGER NOT NULL DEFAULT 0,
                    changed_by      TEXT NOT NULL,
                    details         TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_cloud_assets_audit_ts
                    ON protected_cloud_assets_audit(ts DESC);

            """)
            # Migrations
            cols = {r[1] for r in conn.execute("PRAGMA table_info(devices)")}
            if 'ip_address' not in cols:
                conn.execute("ALTER TABLE devices ADD COLUMN ip_address TEXT NOT NULL DEFAULT ''")
            if 'client_org_id' not in cols:
                # Nullable — NULL means "unassigned" (pre-existing devices, or an MSP
                # that hasn't set up client orgs yet). Never enforced NOT NULL so this
                # migration can't fail against existing data.
                conn.execute("ALTER TABLE devices ADD COLUMN client_org_id TEXT DEFAULT NULL")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_devices_client_org ON devices(client_org_id)")
            # ai_spend: add client_org_id to pre-existing tables (nullable→default '')
            spend_cols = {r[1] for r in conn.execute("PRAGMA table_info(ai_spend)")}
            if 'client_org_id' not in spend_cols:
                conn.execute("ALTER TABLE ai_spend ADD COLUMN client_org_id TEXT NOT NULL DEFAULT ''")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_ai_spend_client_org ON ai_spend(client_org_id, period_date DESC)")
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
            network_cols = {r[1] for r in conn.execute("PRAGMA table_info(network_assets)")}
            if 'port' not in network_cols:
                conn.execute("ALTER TABLE network_assets ADD COLUMN port INTEGER NOT NULL DEFAULT 0")
            if 'service' not in network_cols:
                conn.execute("ALTER TABLE network_assets ADD COLUMN service TEXT NOT NULL DEFAULT ''")

        # Prune old reports per retention policy (env var or default 90 days)
        self.prune_old_reports(int(os.environ.get('SENTINEL_RETAIN_DAYS', '90')))

    def upsert_report(self, device_id: str, hostname: str, report: dict,
                      platform: str = '', agent_version: str = '',
                      ip_address: str = '', client_org_id: str = '') -> None:
        """Store a new report for a device, upserting device metadata.

        client_org_id: pass '' (default) when the agent didn't send a
        client-org token — an existing assignment is preserved rather than
        cleared. Pass an actual org id to (re)assign the device."""
        now = int(time.time())
        summary = report.get('summary', {})
        with self._lock, self._conn() as conn:
            conn.execute("""
                INSERT INTO devices
                    (device_id, hostname, platform, agent_version, ip_address, client_org_id, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(device_id) DO UPDATE SET
                    hostname      = excluded.hostname,
                    platform      = excluded.platform,
                    agent_version = excluded.agent_version,
                    ip_address    = CASE WHEN excluded.ip_address != '' THEN excluded.ip_address ELSE ip_address END,
                    client_org_id = CASE WHEN excluded.client_org_id != '' THEN excluded.client_org_id ELSE client_org_id END,
                    last_seen     = excluded.last_seen
            """, (device_id, hostname, platform, agent_version, ip_address, client_org_id or None, now, now))

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

    def list_devices(self, client_org_id: str | None = None) -> list[dict]:
        """Return all devices with their latest scan summary.

        client_org_id: pass a specific org id to filter to just that org's
        devices (used by the client-viewer role and the fleet view's org
        filter); pass '' (empty string, not None) to filter to unassigned
        devices only; leave as None (default) for no filtering (MSP admin
        view — all devices across all orgs)."""
        with self._lock, self._conn() as conn:
            query = """
                SELECT
                    d.device_id, d.hostname, d.platform, d.agent_version,
                    d.first_seen, d.last_seen, d.client_org_id,
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
            """
            params: tuple = ()
            if client_org_id == '':
                query += " WHERE d.client_org_id IS NULL"
            elif client_org_id is not None:
                query += " WHERE d.client_org_id = ?"
                params = (client_org_id,)
            query += " ORDER BY d.last_seen DESC"
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def set_device_client_org(self, device_id: str, client_org_id: str | None) -> bool:
        """Manually (re)assign a device to a client org — used by the onboarding
        UI to move devices between orgs, independent of the agent's own token."""
        with self._lock, self._conn() as conn:
            cur = conn.execute(
                "UPDATE devices SET client_org_id=? WHERE device_id=?",
                (client_org_id, device_id),
            )
            return cur.rowcount > 0

    def rollup_by_client_org(self) -> dict[str | None, dict]:
        """Aggregate list_devices() by client_org_id for the Level-1 rollup
        dashboard. Returns {client_org_id_or_None: {device_count, critical,
        warning, ok, no_data, last_scan_at, worst_severity}}. Severity per
        device: fail_count>0 -> critical, warn_count>0 -> warning,
        report_time set with no fail/warn -> ok, no report yet -> no_data.
        None key groups unassigned devices — surfaced by the caller as an
        explicit "Unassigned" row so nothing silently disappears from the
        rollup."""
        devices = self.list_devices()
        by_org: dict[str | None, dict] = {}
        for d in devices:
            org = d.get('client_org_id')
            bucket = by_org.setdefault(org, {
                'device_count': 0, 'critical': 0, 'warning': 0, 'ok': 0, 'no_data': 0,
                'last_scan_at': 0,
            })
            bucket['device_count'] += 1
            if d.get('report_time'):
                bucket['last_scan_at'] = max(bucket['last_scan_at'], d['report_time'])
            if not d.get('report_time'):
                bucket['no_data'] += 1
            elif (d.get('fail_count') or 0) > 0:
                bucket['critical'] += 1
            elif (d.get('warn_count') or 0) > 0:
                bucket['warning'] += 1
            else:
                bucket['ok'] += 1
        for bucket in by_org.values():
            if bucket['critical']:
                bucket['worst_severity'] = 'critical'
            elif bucket['warning']:
                bucket['worst_severity'] = 'warning'
            elif bucket['no_data'] == bucket['device_count']:
                bucket['worst_severity'] = 'no_data'
            else:
                bucket['worst_severity'] = 'ok'
        return by_org

    def list_agent_ips(self) -> set[str]:
        """Return the set of IP addresses for all registered agents."""
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                "SELECT ip_address FROM devices WHERE ip_address != ''"
            ).fetchall()
        return {r[0] for r in rows}

    def list_devices_by_profile(self, profiles: list[str],
                                client_org_id: str | None = None) -> list[dict]:
        """Return devices with their latest scan matching any of the given profile slugs.

        Each device row includes '_report' (full parsed report JSON) keyed to
        the most recent scan that matched the requested profiles — not the
        overall latest scan, which may be a different profile.

        client_org_id: same semantics as list_devices(client_org_id=...) —
        pass a specific org id to filter to just that org's devices, pass ''
        (empty string, not None) to filter to unassigned devices only, leave
        as None (default) for no filtering (MSP admin view). Callers serving
        a client_viewer must pass a resolved org id here; None means "every
        org", which is exactly the cross-tenant read this scoping prevents."""
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

        # Org filter is bound, never interpolated — the profile placeholders
        # above are the only thing built into the SQL text.
        org_clause = ''
        org_params: list = []
        if client_org_id == '':
            org_clause = ' AND d.client_org_id IS NULL'
        elif client_org_id is not None:
            org_clause = ' AND d.client_org_id = ?'
            org_params = [client_org_id]

        with self._lock, self._conn() as conn:
            rows = conn.execute(f"""
                SELECT
                    d.device_id, d.hostname, d.platform, d.agent_version,
                    d.first_seen, d.last_seen, d.client_org_id,
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
                WHERE LOWER(r.profile) IN ({ph}){org_clause}
                ORDER BY d.last_seen DESC
            """, term_list + term_list + org_params).fetchall()
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
            conn.execute("DELETE FROM network_assets WHERE reporter_device_id = ?", (device_id,))
            conn.execute("DELETE FROM devices WHERE device_id = ?", (device_id,))
            return cur.rowcount > 0

    def upsert_network_asset(self, reporter_device_id: str, ip_address: str,
                              mac_address: str = '', interface: str = '', source: str = '',
                              hostname: str = '', port: int = 0, service: str = '') -> None:
        """Upsert one passive neighbor-cache observation; no AI inventory overlap."""
        now = int(time.time())
        with self._lock, self._conn() as conn:
            conn.execute("""INSERT INTO network_assets
                (reporter_device_id, ip_address, mac_address, interface, source, hostname, port, service, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(reporter_device_id, ip_address, mac_address, interface, source) DO UPDATE SET
                    hostname=excluded.hostname, service=excluded.service, last_seen=excluded.last_seen""",
                (reporter_device_id, ip_address, mac_address, interface, source, hostname, port, service, now, now))

    def list_network_assets(self, client_org_id: str | None = None) -> list[dict]:
        """List assets only through their reporting device's client-org assignment."""
        query = """SELECT n.id, n.ip_address, n.mac_address, n.interface, n.source, n.hostname, n.port, n.service,
                   n.first_seen, n.last_seen, n.reporter_device_id, d.hostname AS reporter_hostname,
                   d.client_org_id FROM network_assets n JOIN devices d ON d.device_id=n.reporter_device_id"""
        params: tuple = ()
        if client_org_id == '':
            query += ' WHERE d.client_org_id IS NULL'
        elif client_org_id is not None:
            query += ' WHERE d.client_org_id = ?'
            params = (client_org_id,)
        query += ' ORDER BY n.last_seen DESC'
        with self._lock, self._conn() as conn:
            return [dict(r) for r in conn.execute(query, params).fetchall()]

    def record_network_asset_scan(self, reporter_device_id: str, scan_type: str, scope: str,
                                  status: str, detail: str) -> None:
        with self._lock, self._conn() as conn:
            conn.execute("INSERT INTO network_asset_scans "
                         "(reporter_device_id, scan_type, scope, status, detail, completed_at) VALUES (?,?,?,?,?,?)",
                         (reporter_device_id, scan_type, scope, status, detail, int(time.time())))

    def list_network_asset_scans(self, client_org_id: str | None = None) -> list[dict]:
        query = """SELECT s.*, d.hostname AS reporter_hostname, d.client_org_id
                   FROM network_asset_scans s JOIN devices d ON d.device_id=s.reporter_device_id"""
        params: tuple = ()
        if client_org_id == '':
            query += ' WHERE d.client_org_id IS NULL'
        elif client_org_id is not None:
            query += ' WHERE d.client_org_id = ?'
            params = (client_org_id,)
        query += ' ORDER BY s.completed_at DESC LIMIT 50'
        with self._lock, self._conn() as conn:
            return [dict(r) for r in conn.execute(query, params).fetchall()]

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

    def list_shadow_devices(self, max_age_days: int = 90) -> list[dict]:
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

    # ── Protected Files monitoring ──────────────────────────────────────────────
    #
    # FedRAMP controls: SC-13 (encryption at rest), AU-2 (audit events with
    # tamper-evident hash chain), CM-2/CM-6 (policy config management + audit).

    def add_protected_path(self, device_id: str, path: str, recursive: bool = True,
                           actions: str = 'read,write,open', created_by: str = '') -> int:
        """Add a protected path for a device. Path is encrypted at rest (SC-13).
        A policy-change audit record is written (CM-6). Returns the new row id."""
        import crypto
        canon = os.path.realpath(path)
        path_hash = crypto.hash_path(canon)
        enc_path = crypto.encrypt_field(canon)
        now = int(time.time())
        with self._lock, self._conn() as conn:
            cur = conn.execute(
                """INSERT INTO protected_paths
                       (device_id, path, path_hash, recursive, actions, created_by, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(device_id, path_hash) DO UPDATE SET
                       recursive = excluded.recursive,
                       actions   = excluded.actions,
                       updated_at = excluded.updated_at""",
                (device_id, enc_path, path_hash, 1 if recursive else 0,
                 actions, created_by, now, now))
            row_id = cur.lastrowid
            conn.execute(
                """INSERT INTO protected_paths_audit
                       (ts, action, device_id, path, changed_by, details)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (now, 'upsert', device_id, enc_path, created_by,
                 f'recursive={recursive}, actions={actions}'))
        return row_id

    def remove_protected_path(self, path_id: int, changed_by: str = '') -> bool:
        """Remove a protected path by id. Writes an audit record. Returns True
        if a row was deleted."""
        now = int(time.time())
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT device_id, path FROM protected_paths WHERE id=?",
                (path_id,)).fetchone()
            if not row:
                return False
            conn.execute("DELETE FROM protected_paths WHERE id=?", (path_id,))
            conn.execute(
                """INSERT INTO protected_paths_audit
                       (ts, action, device_id, path, changed_by, details)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (now, 'remove', row['device_id'], row['path'], changed_by, ''))
            return True

    def get_protected_paths(self, device_id: str | None = None) -> list[dict]:
        """Return protected paths (decrypted). If device_id is None, returns all.
        Includes both device-specific paths and wildcard ('*') paths."""
        import crypto
        with self._lock, self._conn() as conn:
            if device_id is None:
                rows = conn.execute(
                    "SELECT * FROM protected_paths ORDER BY device_id, path").fetchall()
            else:
                rows = conn.execute(
                    """SELECT * FROM protected_paths
                       WHERE device_id=? OR device_id='*'
                       ORDER BY path""",
                    (device_id,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d['path'] = crypto.decrypt_field(d['path'])
            except Exception:
                pass  # legacy plaintext
            d['recursive'] = bool(d['recursive'])
            out.append(d)
        return out

    def get_protected_paths_for_agent(self, device_id: str) -> list[dict]:
        """Return protected paths (decrypted) for a specific agent, including
        wildcard ('*') paths. Used when pushing policy to agents via command
        poll. Returns only the fields the agent needs."""
        rows = self.get_protected_paths(device_id)
        return [{'path': r['path'], 'recursive': r['recursive'],
                 'actions': r['actions']} for r in rows]

    def get_protected_paths_audit_log(self, limit: int = 100) -> list[dict]:
        """Return the policy-change audit log (CM-6). Paths are decrypted for
        dashboard display."""
        import crypto
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM protected_paths_audit
                   ORDER BY ts DESC LIMIT ?""",
                (limit,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d['path'] = crypto.decrypt_field(d['path'])
            except Exception:
                pass
            out.append(d)
        return out

    def ingest_access_events(self, events: list[dict]) -> int:
        """Ingest a batch of access events from an agent. Each event is
        appended to the tamper-evident hash chain (AU-2). Returns the count
        stored.

        Events are validated: required fields must be present, and the hash
        chain is continued from the last stored event_hash.
        """
        import crypto
        if not events:
            return 0
        required = {'ts', 'device_id', 'process', 'path', 'action'}
        stored = 0
        with self._lock, self._conn() as conn:
            # Get the last event_hash to continue the chain
            last = conn.execute(
                "SELECT event_hash FROM access_events ORDER BY id DESC LIMIT 1"
            ).fetchone()
            prev_hash = last['event_hash'] if last else ''
            for evt in events:
                if not required.issubset(evt):
                    continue
                data = {
                    'ts': int(evt['ts']),
                    'device_id': str(evt['device_id']),
                    'hostname': str(evt.get('hostname', '')),
                    'platform': str(evt.get('platform', '')),
                    'process': str(evt['process']),
                    'pid': int(evt.get('pid', 0)),
                    'path': str(evt['path']),
                    'action': str(evt['action']),
                    'source': str(evt.get('source', '')),
                }
                event_hash = crypto.compute_event_hash(prev_hash, data)
                conn.execute(
                    """INSERT INTO access_events
                           (ts, device_id, hostname, platform, process, pid,
                            path, action, source, prev_hash, event_hash)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (data['ts'], data['device_id'], data['hostname'],
                     data['platform'], data['process'], data['pid'],
                     data['path'], data['action'], data['source'],
                     prev_hash, event_hash))
                prev_hash = event_hash
                stored += 1
        return stored

    def get_access_events(self, limit: int = 300,
                          device_id: str | None = None,
                          unreviewed_only: bool = False) -> list[dict]:
        """Return access events (newest first). Optionally filter by device."""
        with self._lock, self._conn() as conn:
            conditions = []
            params: list = []
            if device_id:
                conditions.append("device_id=?")
                params.append(device_id)
            if unreviewed_only:
                conditions.append("reviewed=0")
            where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
            params.append(limit)
            rows = conn.execute(
                f"""SELECT * FROM access_events {where}
                    ORDER BY ts DESC LIMIT ?""",
                tuple(params)).fetchall()
        return [dict(r) for r in rows]

    def count_unreviewed_access_events(self) -> int:
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS c FROM access_events WHERE reviewed=0"
            ).fetchone()
            return row['c']

    def mark_access_event_reviewed(self, event_id: int) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                "UPDATE access_events SET reviewed=1 WHERE id=?", (event_id,))

    def mark_all_access_events_reviewed(self) -> None:
        with self._lock, self._conn() as conn:
            conn.execute("UPDATE access_events SET reviewed=1 WHERE reviewed=0")

    def verify_access_event_chain(self) -> bool:
        """Verify the full access_events hash chain integrity (AU-2 tamper
        detection). Returns True if the chain is intact."""
        import crypto
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM access_events ORDER BY id ASC").fetchall()
        prev = ''
        for r in rows:
            d = dict(r)
            data = {
                'ts': d['ts'],
                'device_id': d['device_id'],
                'hostname': d.get('hostname', ''),
                'platform': d.get('platform', ''),
                'process': d['process'],
                'pid': d['pid'],
                'path': d['path'],
                'action': d['action'],
                'source': d.get('source', ''),
            }
            expected = crypto.compute_event_hash(prev, data)
            if d.get('event_hash') != expected:
                return False
            prev = d['event_hash']
        return True

    # ── Protected Cloud Assets ────────────────────────────────────────────────

    def add_protected_cloud_asset(self, provider: str, resource_type: str,
                                  account_id: str, resource_scope: str,
                                  tag_key: str = '', tag_value: str = '',
                                  created_by: str = '') -> int:
        """Add an explicit cloud-resource scope, optionally requiring a tag.

        Wildcards are rejected by the API before reaching this method. The
        audit record deliberately contains only policy metadata, never a cloud
        access token or a provider event payload.
        """
        now = int(time.time())
        with self._lock, self._conn() as conn:
            cur = conn.execute(
                """INSERT INTO protected_cloud_assets
                   (provider, resource_type, account_id, resource_scope, tag_key,
                    tag_value, created_by, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(provider, resource_type, account_id, resource_scope, tag_key, tag_value)
                   DO UPDATE SET updated_at=excluded.updated_at, created_by=excluded.created_by""",
                (provider, resource_type, account_id, resource_scope, tag_key,
                 tag_value, created_by, now, now))
            policy_id = cur.lastrowid
            if not policy_id:
                row = conn.execute(
                    """SELECT id FROM protected_cloud_assets WHERE provider=? AND resource_type=?
                       AND account_id=? AND resource_scope=? AND tag_key=? AND tag_value=?""",
                    (provider, resource_type, account_id, resource_scope, tag_key, tag_value)).fetchone()
                policy_id = row['id']
            conn.execute(
                """INSERT INTO protected_cloud_assets_audit
                   (ts, action, policy_id, changed_by, details) VALUES (?, ?, ?, ?, ?)""",
                (now, 'upsert', policy_id, created_by,
                 f'{provider}:{resource_type} {resource_scope}'))
        return int(policy_id)

    def remove_protected_cloud_asset(self, policy_id: int, changed_by: str = '') -> bool:
        now = int(time.time())
        with self._lock, self._conn() as conn:
            row = conn.execute("SELECT id FROM protected_cloud_assets WHERE id=?", (policy_id,)).fetchone()
            if not row:
                return False
            conn.execute("DELETE FROM protected_cloud_assets WHERE id=?", (policy_id,))
            conn.execute(
                "INSERT INTO protected_cloud_assets_audit (ts, action, policy_id, changed_by) VALUES (?, ?, ?, ?)",
                (now, 'remove', policy_id, changed_by))
        return True

    def get_protected_cloud_assets(self) -> list[dict]:
        with self._lock, self._conn() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT * FROM protected_cloud_assets ORDER BY provider, account_id, resource_scope").fetchall()]

    def get_protected_cloud_assets_audit_log(self, limit: int = 100) -> list[dict]:
        with self._lock, self._conn() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT * FROM protected_cloud_assets_audit ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()]

    def ingest_protected_cloud_event(self, event: dict, policy_id: int) -> bool:
        """Append a normalized cloud event to its tamper-evident chain.

        Duplicate external provider event IDs are rejected by SQLite's unique
        constraint, providing idempotency for at-least-once delivery.
        """
        import crypto
        now = int(time.time())
        data = {k: str(event.get(k, '')) for k in ('provider', 'resource_type', 'account_id',
                'region', 'resource', 'actor', 'action', 'event_name', 'event_id')}
        data['ts'] = int(event.get('ts', now))
        data['policy_id'] = int(policy_id)
        with self._lock, self._conn() as conn:
            last = conn.execute("SELECT event_hash FROM protected_cloud_asset_events ORDER BY id DESC LIMIT 1").fetchone()
            prev_hash = last['event_hash'] if last else ''
            event_hash = crypto.compute_event_hash(prev_hash, data)
            try:
                conn.execute(
                    """INSERT INTO protected_cloud_asset_events
                       (ts, provider, resource_type, account_id, region, resource, actor, action,
                        event_name, external_id, policy_id, prev_hash, event_hash)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (data['ts'], data['provider'], data['resource_type'], data['account_id'],
                     data['region'], data['resource'], data['actor'], data['action'],
                     data['event_name'], data['event_id'], policy_id, prev_hash, event_hash))
            except sqlite3.IntegrityError:
                return False
        return True

    def get_protected_cloud_events(self, limit: int = 300) -> list[dict]:
        with self._lock, self._conn() as conn:
            return [dict(r) for r in conn.execute(
                "SELECT * FROM protected_cloud_asset_events ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()]

    # ── AI spend tracking ─────────────────────────────────────────────────────

    def upsert_ai_spend(self, records: list) -> int:
        """Insert or replace AI spend records.  Each record may carry a
        `client_org_id` (MSP client org the key belongs to); empty string means
        unscoped/single-tenant."""
        if not records:
            return 0
        now = int(time.time())
        with self._lock, self._conn() as conn:
            for rec in records:
                conn.execute(
                    """INSERT INTO ai_spend
                           (provider, model, period_date, client_org_id, key_id, key_label, key_last4, input_tokens,
                            output_tokens, total_tokens, cost_usd, currency,
                            request_count, raw_snapshot, fetched_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(provider, model, period_date, client_org_id, key_id) DO UPDATE SET
                           input_tokens  = excluded.input_tokens,
                           output_tokens = excluded.output_tokens,
                           total_tokens  = excluded.total_tokens,
                           cost_usd      = excluded.cost_usd,
                           currency      = excluded.currency,
                           request_count = excluded.request_count,
                           raw_snapshot  = excluded.raw_snapshot,
                           fetched_at    = excluded.fetched_at""",
                    (
                        rec.get('provider', ''),
                        rec.get('model', ''),
                        rec.get('period_date', ''),
                        rec.get('client_org_id', '') or '',
                        rec.get('key_id', '') or '',
                        rec.get('key_label', '') or '',
                        rec.get('key_last4', '') or '',
                        int(rec.get('input_tokens', 0) or 0),
                        int(rec.get('output_tokens', 0) or 0),
                        int(rec.get('total_tokens', 0) or 0),
                        float(rec.get('cost_usd', 0.0) or 0.0),
                        rec.get('currency', 'USD'),
                        rec.get('request_count'),
                        rec.get('raw_snapshot', ''),
                        now,
                    ),
                )
        return len(records)

    def get_ai_spend_summary(self, days: int = 30, client_org_id: str | None = None) -> dict:
        """Return rolled-up AI spend for the last N days.

        client_org_id: pass a specific org id to filter to that client's spend
        only (used by client_viewer scoping and the MSP drill-down); pass None
        for no filtering (MSP admin aggregate view across all client orgs)."""
        cutoff = self._days_ago_iso(days)
        where = "WHERE period_date >= ?"
        params: list = [cutoff]
        if client_org_id is not None:
            where += " AND client_org_id = ?"
            params.append(client_org_id)
        with self._lock, self._conn() as conn:
            total = conn.execute(
                f"""SELECT COALESCE(SUM(cost_usd), 0), COALESCE(SUM(input_tokens), 0),
                          COALESCE(SUM(output_tokens), 0), COALESCE(SUM(total_tokens), 0)
                   FROM ai_spend {where}""",
                params,
            ).fetchone()
            by_provider = conn.execute(
                f"""SELECT provider,
                          COALESCE(SUM(cost_usd), 0) AS cost_usd,
                          COALESCE(SUM(total_tokens), 0) AS total_tokens,
                          COUNT(DISTINCT model) AS model_count
                   FROM ai_spend
                   {where}
                   GROUP BY provider
                   ORDER BY cost_usd DESC""",
                params,
            ).fetchall()
            by_model = conn.execute(
                f"""SELECT provider, model,
                          COALESCE(SUM(cost_usd), 0) AS cost_usd,
                          COALESCE(SUM(total_tokens), 0) AS total_tokens,
                          COALESCE(SUM(input_tokens), 0) AS input_tokens,
                          COALESCE(SUM(output_tokens), 0) AS output_tokens
                   FROM ai_spend
                   {where}
                   GROUP BY provider, model
                   ORDER BY cost_usd DESC""",
                params,
            ).fetchall()
            daily = conn.execute(
                f"""SELECT period_date,
                          COALESCE(SUM(cost_usd), 0) AS cost_usd,
                          COALESCE(SUM(total_tokens), 0) AS total_tokens
                   FROM ai_spend
                   {where}
                   GROUP BY period_date
                   ORDER BY period_date ASC""",
                params,
            ).fetchall()
        return {
            'period_days': days,
            'client_org_id': client_org_id,
            'total_cost_usd': total[0] if total else 0.0,
            'input_tokens': total[1] if total else 0,
            'output_tokens': total[2] if total else 0,
            'total_tokens': total[3] if total else 0,
            'by_provider': [dict(r) for r in by_provider],
            'by_model': [dict(r) for r in by_model],
            'daily': [dict(r) for r in daily],
        }

    def get_ai_spend_by_client_org(self, days: int = 30) -> list[dict]:
        """Return spend broken down by client_org_id for the last N days.

        MSP admin view: aggregates every client org under this customer. A
        client_viewer should never reach this method — the caller gates it."""
        cutoff = self._days_ago_iso(days)
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                """SELECT COALESCE(client_org_id, '') AS client_org_id,
                          COALESCE(SUM(cost_usd), 0) AS cost_usd,
                          COALESCE(SUM(total_tokens), 0) AS total_tokens,
                          COALESCE(SUM(input_tokens), 0) AS input_tokens,
                          COALESCE(SUM(output_tokens), 0) AS output_tokens,
                          COUNT(DISTINCT provider) AS provider_count,
                          COUNT(DISTINCT model) AS model_count
                   FROM ai_spend
                   WHERE period_date >= ?
                   GROUP BY client_org_id
                   ORDER BY cost_usd DESC""",
                (cutoff,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_ai_spend_by_key(self, days: int = 30) -> list[dict]:
        """Return spend grouped by the redacted key identity, never the key."""
        cutoff = self._days_ago_iso(days)
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                """SELECT provider, client_org_id, key_id, key_label, key_last4,
                          COALESCE(SUM(cost_usd), 0) AS spend_usd,
                          COALESCE(SUM(total_tokens), 0) AS total_tokens
                   FROM ai_spend WHERE period_date >= ?
                   GROUP BY provider, client_org_id, key_id, key_label, key_last4
                   ORDER BY spend_usd DESC""",
                (cutoff,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_ai_spend_by_date(self, start_date: str, end_date: str | None = None,
                             client_org_id: str | None = None) -> list[dict]:
        """Return raw ai_spend rows between two ISO dates (inclusive)."""
        end = end_date or start_date
        if end < start_date:
            start_date, end = end, start_date
        where = "WHERE period_date >= ? AND period_date <= ?"
        params: list = [start_date, end]
        if client_org_id is not None:
            where += " AND client_org_id = ?"
            params.append(client_org_id)
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                f"""SELECT id, provider, model, period_date, client_org_id,
                          input_tokens, output_tokens, total_tokens, cost_usd,
                          currency, request_count, fetched_at
                   FROM ai_spend
                   {where}
                   ORDER BY period_date DESC, cost_usd DESC""",
                params,
            ).fetchall()
        return [dict(r) for r in rows]

    @staticmethod
    def _days_ago_iso(days: int) -> str:
        import datetime as _dt
        return (_dt.date.today() - _dt.timedelta(days=days)).isoformat()

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

                CREATE TABLE IF NOT EXISTS client_orgs (
                    id           TEXT PRIMARY KEY,
                    customer_id  TEXT NOT NULL REFERENCES customers(id),
                    name         TEXT NOT NULL,
                    enroll_token TEXT UNIQUE NOT NULL,
                    created_at   INTEGER NOT NULL,
                    active       INTEGER NOT NULL DEFAULT 1
                );

                CREATE INDEX IF NOT EXISTS idx_client_orgs_customer
                    ON client_orgs(customer_id, active);
            """)
            # Migrations
            du_cols = {r[1] for r in conn.execute("PRAGMA table_info(dashboard_users)")}
            if 'client_org_id' not in du_cols:
                # NULL = full MSP-admin access (sees every client org for this
                # customer); non-NULL = client-viewer scoped to that one org.
                # Sessions don't need their own copy of this — get_session()
                # joins to dashboard_users and reads it from there, so it's
                # always current even if an admin changes a user's scope
                # after they've already logged in.
                conn.execute("ALTER TABLE dashboard_users ADD COLUMN client_org_id TEXT DEFAULT NULL")
            co_cols = {r[1] for r in conn.execute("PRAGMA table_info(client_orgs)")}
            if 'psa_config_json' not in co_cols:
                # NULL = this client uses the customer's default/global PSA
                # config (data/alerts_config.json) — set only when an MSP
                # wants a specific client's tickets routed to a different
                # PSA company record/board than the default.
                conn.execute("ALTER TABLE client_orgs ADD COLUMN psa_config_json TEXT DEFAULT NULL")
            if 'report_email' not in co_cols:
                conn.execute("ALTER TABLE client_orgs ADD COLUMN report_email TEXT NOT NULL DEFAULT ''")
            if 'report_cadence' not in co_cols:
                # 'off' or 'monthly' — validated in server.py before writing.
                conn.execute("ALTER TABLE client_orgs ADD COLUMN report_cadence TEXT NOT NULL DEFAULT 'off'")
            if 'last_report_sent_at' not in co_cols:
                conn.execute("ALTER TABLE client_orgs ADD COLUMN last_report_sent_at INTEGER DEFAULT NULL")

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

    # ── client org management (MSP's own downstream clients) ─────────────────

    def create_client_org(self, customer_id: str, name: str) -> dict:
        """Create a new client org under an MSP customer and issue its
        enrollment token — the token an agent installer embeds so check-ins
        get tagged with this org automatically."""
        import uuid
        import secrets
        oid = str(uuid.uuid4())
        token = secrets.token_urlsafe(24)
        now = int(time.time())
        with self._lock, self._conn() as conn:
            conn.execute(
                'INSERT INTO client_orgs (id, customer_id, name, enroll_token, created_at, active) '
                'VALUES (?,?,?,?,?,1)',
                (oid, customer_id, name.strip(), token, now),
            )
        return {'id': oid, 'customer_id': customer_id, 'name': name.strip(),
                'enroll_token': token, 'created_at': now}

    def list_client_orgs(self, customer_id: str) -> list[dict]:
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                'SELECT id, customer_id, name, enroll_token, created_at, active, '
                'report_email, report_cadence, last_report_sent_at '
                'FROM client_orgs WHERE customer_id=? ORDER BY created_at ASC',
                (customer_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_client_org(self, org_id: str) -> dict | None:
        with self._lock, self._conn() as conn:
            row = conn.execute(
                'SELECT id, customer_id, name, enroll_token, created_at, active, '
                'report_email, report_cadence, last_report_sent_at '
                'FROM client_orgs WHERE id=?',
                (org_id,),
            ).fetchone()
        return dict(row) if row else None

    def get_client_org_by_token(self, token: str) -> dict | None:
        """Resolve an agent's client-org enrollment token at check-in time."""
        if not token:
            return None
        with self._lock, self._conn() as conn:
            row = conn.execute(
                'SELECT id, customer_id, name FROM client_orgs WHERE enroll_token=? AND active=1',
                (token,),
            ).fetchone()
        return dict(row) if row else None

    def rename_client_org(self, org_id: str, customer_id: str, name: str) -> bool:
        with self._lock, self._conn() as conn:
            cur = conn.execute(
                'UPDATE client_orgs SET name=? WHERE id=? AND customer_id=?',
                (name.strip(), org_id, customer_id),
            )
            return cur.rowcount > 0

    def deactivate_client_org(self, org_id: str, customer_id: str) -> bool:
        """Soft-delete — devices keep their client_org_id (historical data
        stays intact) but the org drops out of the active rollup/onboarding
        lists and its client-viewer logins stop working."""
        with self._lock, self._conn() as conn:
            cur = conn.execute(
                'UPDATE client_orgs SET active=0 WHERE id=? AND customer_id=?',
                (org_id, customer_id),
            )
            return cur.rowcount > 0

    def get_client_org_psa_override(self, org_id: str) -> dict | None:
        """Return this org's PSA config override, or None if it uses the
        customer's default (data/alerts_config.json)."""
        with self._lock, self._conn() as conn:
            row = conn.execute(
                'SELECT psa_config_json FROM client_orgs WHERE id=?', (org_id,),
            ).fetchone()
        if not row or not row['psa_config_json']:
            return None
        import json
        try:
            return json.loads(row['psa_config_json'])
        except (ValueError, TypeError):
            return None

    def set_client_org_psa_override(self, org_id: str, customer_id: str, psa_cfg: dict) -> bool:
        """Store a per-client PSA override. psa_cfg shape matches the 'psa'
        key of alerts_config.json ({'provider': ..., 'connectwise': {...},
        ...}) so the same _create_psa_ticket()/create_ticket() code in
        alerts.py/psa_connector.py works unchanged for both the global
        config and a per-org override."""
        import json
        with self._lock, self._conn() as conn:
            cur = conn.execute(
                'UPDATE client_orgs SET psa_config_json=? WHERE id=? AND customer_id=?',
                (json.dumps(psa_cfg), org_id, customer_id),
            )
            return cur.rowcount > 0

    def clear_client_org_psa_override(self, org_id: str, customer_id: str) -> bool:
        """Revert an org to the customer's default PSA config."""
        with self._lock, self._conn() as conn:
            cur = conn.execute(
                'UPDATE client_orgs SET psa_config_json=NULL WHERE id=? AND customer_id=?',
                (org_id, customer_id),
            )
            return cur.rowcount > 0

    def set_client_org_report_config(self, org_id: str, customer_id: str,
                                      report_email: str, report_cadence: str) -> bool:
        if report_cadence not in ('off', 'monthly'):
            report_cadence = 'off'
        with self._lock, self._conn() as conn:
            cur = conn.execute(
                'UPDATE client_orgs SET report_email=?, report_cadence=? WHERE id=? AND customer_id=?',
                (report_email.strip(), report_cadence, org_id, customer_id),
            )
            return cur.rowcount > 0

    def get_client_orgs_due_for_report(self, min_interval_days: int = 28) -> list[dict]:
        """Every active client org (across ALL customers — this registry is
        the single central db) with report_cadence='monthly', a report
        email set, and either never sent or sent >= min_interval_days ago.
        Used by the scheduler tick in server.py's main(); intentionally not
        scoped to one customer since the ticker walks every customer."""
        cutoff = int(time.time()) - min_interval_days * 86400
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                "SELECT id, customer_id, name, report_email, last_report_sent_at "
                "FROM client_orgs "
                "WHERE active=1 AND report_cadence='monthly' AND report_email != '' "
                "AND (last_report_sent_at IS NULL OR last_report_sent_at < ?)",
                (cutoff,),
            ).fetchall()
        return [dict(r) for r in rows]

    def mark_client_org_report_sent(self, org_id: str) -> None:
        with self._lock, self._conn() as conn:
            conn.execute(
                'UPDATE client_orgs SET last_report_sent_at=? WHERE id=?',
                (int(time.time()), org_id),
            )

    # ── dashboard user management ─────────────────────────────────────────────

    def create_user(self, customer_id: str, email: str, password: str, role: str = 'admin',
                     client_org_id: str | None = None) -> dict:
        import uuid
        uid = str(uuid.uuid4())
        now = int(time.time())
        with self._lock, self._conn() as conn:
            conn.execute(
                'INSERT INTO dashboard_users '
                '(id, customer_id, email, password_hash, role, client_org_id, created_at, active) '
                'VALUES (?,?,?,?,?,?,?,1)',
                (uid, customer_id, email.lower().strip(), self._hash_pw(password), role, client_org_id, now),
            )
        return {'id': uid, 'customer_id': customer_id,
                'email': email.lower().strip(), 'role': role, 'client_org_id': client_org_id}

    def authenticate_user(self, email: str, password: str) -> dict | None:
        with self._lock, self._conn() as conn:
            row = conn.execute(
                'SELECT id, customer_id, email, password_hash, role, client_org_id FROM dashboard_users '
                'WHERE email=? AND active=1',
                (email.lower().strip(),),
            ).fetchone()
        if row is None or not self._verify_pw(password, row['password_hash']):
            return None
        return {'id': row['id'], 'customer_id': row['customer_id'],
                'email': row['email'], 'role': row['role'],
                'client_org_id': row['client_org_id']}

    def list_users(self, customer_id: str) -> list[dict]:
        with self._lock, self._conn() as conn:
            rows = conn.execute(
                'SELECT id, email, role, client_org_id, created_at, active FROM dashboard_users '
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
                'SELECT s.user_id, s.customer_id, s.email, u.role, u.client_org_id '
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
