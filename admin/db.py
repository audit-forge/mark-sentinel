import sqlite3
import os
import time
from contextlib import contextmanager

DB_PATH = os.environ.get("DB_PATH", "/data/sentinel.db")


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with get_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS customers (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1,
                tier TEXT NOT NULL DEFAULT 'standard',
                license_expires_at TEXT,
                max_seats INTEGER NOT NULL DEFAULT 5,
                current_agents INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                customer_id TEXT REFERENCES customers(id),
                created_at TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS license_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                customer_id TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                agent_count INTEGER NOT NULL,
                max_seats INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS password_resets (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                token TEXT UNIQUE NOT NULL,
                expires_at TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                occurred_at  INTEGER NOT NULL,
                actor_id     TEXT NOT NULL DEFAULT '',
                actor_name   TEXT NOT NULL DEFAULT '',
                actor_role   TEXT NOT NULL DEFAULT '',
                customer_id  TEXT NOT NULL DEFAULT '',
                action       TEXT NOT NULL DEFAULT '',
                target       TEXT NOT NULL DEFAULT '',
                details      TEXT NOT NULL DEFAULT '',
                ip_address   TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_audit_log_time ON audit_log(occurred_at DESC);
            CREATE INDEX IF NOT EXISTS idx_audit_log_customer ON audit_log(customer_id, occurred_at DESC);
        """)
        for col, defn in [
            ('tier',                "TEXT NOT NULL DEFAULT 'standard'"),
            ('license_expires_at',  "TEXT"),
            ('max_seats',           "INTEGER NOT NULL DEFAULT 5"),
            ('current_agents',      "INTEGER NOT NULL DEFAULT 0"),
            ('port',                "INTEGER"),
            ('agent_token',         "TEXT"),
        ]:
            try:
                conn.execute(f"ALTER TABLE customers ADD COLUMN {col} {defn}")
            except Exception:
                pass


def log_audit(actor_id, actor_name, actor_role, customer_id, action,
              target='', details='', ip_address=''):
    now = int(time.time())
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO audit_log
               (occurred_at, actor_id, actor_name, actor_role,
                customer_id, action, target, details, ip_address)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (now, actor_id, actor_name, actor_role,
             customer_id, action, target, details, ip_address),
        )
        return cur.lastrowid


def get_audit_log(limit=200, customer_id=None):
    with get_conn() as conn:
        if customer_id:
            rows = conn.execute(
                """SELECT * FROM audit_log WHERE customer_id=?
                   ORDER BY occurred_at DESC LIMIT ?""",
                (customer_id, limit)
            ).fetchall()
        else:
            rows = conn.execute(
                """SELECT * FROM audit_log ORDER BY occurred_at DESC LIMIT ?""",
                (limit,)
            ).fetchall()
    return [dict(r) for r in rows]


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()
