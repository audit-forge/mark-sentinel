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
            CREATE TABLE IF NOT EXISTS renewal_reminders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                customer_id TEXT NOT NULL REFERENCES customers(id),
                days_before INTEGER NOT NULL,
                recipient TEXT NOT NULL,
                recipient_type TEXT NOT NULL,
                sent_at TEXT NOT NULL,
                UNIQUE(customer_id, days_before, recipient)
            );
            CREATE TABLE IF NOT EXISTS password_resets (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                token TEXT UNIQUE NOT NULL,
                expires_at TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS maintenance_notices (
                id TEXT PRIMARY KEY,
                message TEXT NOT NULL,
                scheduled_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_by TEXT NOT NULL,
                created_at TEXT NOT NULL,
                active INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                occurred_at TEXT NOT NULL,
                actor_name TEXT,
                actor_role TEXT,
                customer_id TEXT,
                action TEXT,
                target TEXT,
                details TEXT,
                ip_address TEXT
            );
        """)
        for col, defn in [
            ('tier',                "TEXT NOT NULL DEFAULT 'standard'"),
            ('license_expires_at',  "TEXT"),
            ('max_seats',           "INTEGER NOT NULL DEFAULT 5"),
            ('current_agents',      "INTEGER NOT NULL DEFAULT 0"),
            ('port',                "INTEGER"),
            ('agent_token',         "TEXT"),
            ('parent_customer_id',  "TEXT"),
            ('is_reseller',         "INTEGER NOT NULL DEFAULT 0"),
            ('is_msp',              "INTEGER NOT NULL DEFAULT 0"),
            ('baseline_profile',    "TEXT NOT NULL DEFAULT 'default'"),
            # Suspension is a reversible service hold. It blocks agent tokens
            # at the shared gateway but preserves dashboards, data, and agents.
            ('service_suspended',   "INTEGER NOT NULL DEFAULT 0"),
            ('service_suspended_at', "TEXT"),
            ('service_suspended_by', "TEXT"),
        ]:
            try:
                conn.execute(f"ALTER TABLE customers ADD COLUMN {col} {defn}")
            except Exception:
                pass
        try:
            conn.execute("ALTER TABLE users ADD COLUMN client_org_id TEXT")
        except Exception:
            pass


class StaleSessionError(Exception):
    """A session's user row no longer backs the session's claims."""


def revalidate_user(user_id) -> dict:
    """Return the active user's current authorization attributes.

    JWT claims are snapshots; role and organization changes must apply on the
    next request rather than after the token's normal expiration.
    """
    if not user_id:
        raise StaleSessionError("session carries no user id")
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE id=?", (str(user_id),)).fetchone()
    if row is None or not row["active"]:
        raise StaleSessionError("session user is missing or inactive")
    columns = row.keys()
    return {
        "sub": row["id"],
        "email": row["email"],
        "role": row["role"],
        "customer_id": row["customer_id"],
        "client_org_id": row["client_org_id"] if "client_org_id" in columns else None,
    }


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()
