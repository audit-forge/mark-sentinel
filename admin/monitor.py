import os
import threading
import time
from datetime import datetime, timezone

import urllib.request
import urllib.error
import json

from db import get_conn
from mailer import send_alert

MONITOR_INTERVAL = int(os.environ.get("MONITOR_INTERVAL_H", "1")) * 3600
ALERT_TO         = os.environ.get("ALERT_TO", "")
_SENTINEL_TIMEOUT = 5


def start_monitor():
    t = threading.Thread(target=_loop, daemon=True, name="seat-monitor")
    t.start()
    print("[monitor] seat monitor started", flush=True)


def _loop():
    while True:
        try:
            _check_all_customers()
        except Exception as e:
            print(f"[monitor] check failed: {e}", flush=True)
        time.sleep(MONITOR_INTERVAL)


def _check_all_customers():
    with get_conn() as conn:
        customers = conn.execute(
            "SELECT id, name, max_seats, tier FROM customers WHERE active=1"
        ).fetchall()

    for c in customers:
        agent_count = _query_agent_count(c["id"])
        if agent_count is None:
            continue
        _store_agent_count(c["id"], agent_count)
        if agent_count > c["max_seats"]:
            _handle_overage(dict(c), agent_count)


def _query_agent_count(customer_id: str) -> int | None:
    import subprocess
    container = f"sentinel-{customer_id}"
    # The sentinel server stores agents.db under /app/data/customers/<customer_id>/agents.db
    # Use glob so this works regardless of what customer_id slug is in the license.
    try:
        find = subprocess.run(
            ["docker", "exec", container, "find", "/app/data", "-name", "agents.db"],
            capture_output=True, text=True, timeout=10
        )
        if find.returncode != 0 or not find.stdout.strip():
            return None
        db_path = find.stdout.strip().splitlines()[0]
        result = subprocess.run(
            ["docker", "exec", container, "python3", "-c",
             f"import sqlite3,time; conn=sqlite3.connect('{db_path}'); "
             "cutoff=int(time.time())-1800; "
             "print(conn.execute('SELECT COUNT(*) FROM devices WHERE last_seen>=?',(cutoff,)).fetchone()[0])"],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return int(result.stdout.strip())
    except Exception:
        pass
    return None


def _store_agent_count(customer_id: str, count: int):
    with get_conn() as conn:
        conn.execute(
            "UPDATE customers SET current_agents=? WHERE id=?",
            (count, customer_id)
        )


def _handle_overage(customer: dict, agent_count: int):
    today = datetime.now(timezone.utc).date().isoformat()
    with get_conn() as conn:
        already = conn.execute(
            "SELECT id FROM license_alerts WHERE customer_id=? AND DATE(created_at)=? AND alert_type='overage'",
            (customer["id"], today)
        ).fetchone()
        if already:
            return
        conn.execute(
            "INSERT INTO license_alerts (customer_id, alert_type, agent_count, max_seats, created_at) VALUES (?,?,?,?,?)",
            (customer["id"], "overage", agent_count, customer["max_seats"],
             datetime.now(timezone.utc).isoformat())
        )

    overage = agent_count - customer["max_seats"]
    tier_label = "Pro" if customer["tier"] == "plus" else "Standard"

    body_text = (
        f"Seat overage detected for customer: {customer['name']}\n\n"
        f"Plan:            {tier_label}\n"
        f"Licensed seats:  {customer['max_seats']}\n"
        f"Active agents:   {agent_count}\n"
        f"Overage:         {overage} seat(s)\n\n"
        f"Log in to the admin panel to review or upgrade their license."
    )
    body_html = f"""
<div style="font-family:monospace;background:#0a0a0a;color:#e0e0e0;padding:24px;max-width:520px">
  <div style="color:#00ff88;font-weight:bold;letter-spacing:3px;margin-bottom:16px">M.A.R.K. SENTINEL</div>
  <div style="font-size:16px;color:#fff;margin-bottom:20px">Seat Overage Alert</div>
  <table style="border-collapse:collapse;width:100%;font-size:13px">
    <tr><td style="color:#666;padding:6px 0;width:160px">Customer</td><td style="color:#fff">{customer['name']}</td></tr>
    <tr><td style="color:#666;padding:6px 0">Plan</td><td style="color:#fff">{tier_label}</td></tr>
    <tr><td style="color:#666;padding:6px 0">Licensed seats</td><td style="color:#fff">{customer['max_seats']}</td></tr>
    <tr><td style="color:#666;padding:6px 0">Active agents</td><td style="color:#ff5555;font-weight:bold">{agent_count}</td></tr>
    <tr><td style="color:#666;padding:6px 0">Overage</td><td style="color:#ff5555;font-weight:bold">+{overage} seat(s)</td></tr>
  </table>
  <div style="margin-top:20px;font-size:12px;color:#555">Log in to the admin panel to review or upgrade their license.</div>
</div>
"""
    send_alert(
        subject=f"[Sentinel] Seat overage — {customer['name']} ({agent_count}/{customer['max_seats']})",
        body_text=body_text,
        body_html=body_html,
    )
    print(f"[monitor] overage alert sent for {customer['id']}: {agent_count}/{customer['max_seats']}", flush=True)
