import os
import threading
import time
from datetime import datetime, timezone


from db import get_conn
from mailer import send_alert, send_renewal_reminder

MONITOR_INTERVAL = int(os.environ.get("MONITOR_INTERVAL_H", "1")) * 3600
ALERT_TO         = os.environ.get("ALERT_TO", "")
_SENTINEL_TIMEOUT = 5
_RENEWAL_REMINDER_DAYS = (90, 60, 30, 14, 7, 1)


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
            "SELECT id, name, max_seats, tier, license_expires_at FROM customers WHERE active=1"
        ).fetchall()

    for c in customers:
        _handle_renewal_reminder(dict(c))
        agent_count = _query_agent_count(c["id"])
        if agent_count is None:
            continue
        _store_agent_count(c["id"], agent_count)
        if agent_count > c["max_seats"]:
            _handle_overage(dict(c), agent_count)


def _renewal_milestone(days_remaining: int) -> int | None:
    """Return the current reminder window, catching up after short downtime."""
    if days_remaining < 0:
        return None
    return min((days for days in _RENEWAL_REMINDER_DAYS if days_remaining <= days), default=None)


def _handle_renewal_reminder(customer: dict) -> None:
    """Send a once-per-window renewal reminder without changing service state."""
    try:
        expires_on = datetime.fromisoformat(customer["license_expires_at"]).date()
    except (TypeError, ValueError):
        return
    days_remaining = (expires_on - datetime.now(timezone.utc).date()).days
    milestone = _renewal_milestone(days_remaining)
    if milestone is None:
        return

    with get_conn() as conn:
        customer_contacts = [r[0] for r in conn.execute(
            "SELECT email FROM users WHERE customer_id=? AND role='customer_admin' AND active=1",
            (customer["id"],),
        ).fetchall()]

    recipients = [("customer", email) for email in customer_contacts]
    if ALERT_TO:
        recipients.append(("internal", ALERT_TO))
    if not recipients:
        print(f"[monitor] renewal reminder skipped for {customer['id']}: no recipients", flush=True)
        return

    subject = f"[Arckon] Renewal reminder - {customer['name']} expires in {days_remaining} day(s)"
    body_text = (
        f"Arckon service renewal reminder\n\n"
        f"Customer: {customer['name']}\n"
        f"License expiry: {expires_on.isoformat()}\n"
        f"Days remaining: {days_remaining}\n\n"
        "This is a renewal planning reminder only. Service remains active and will not be interrupted by this notification. "
        "Please contact RiskRaven or renew in the admin panel before the license expiry date."
    )
    body_html = f"""
<div style="font-family:'Segoe UI',system-ui,sans-serif;max-width:560px;color:#172554">
  <h2 style="margin-bottom:8px">Arckon Renewal Reminder</h2>
  <p>Your Arckon subscription renewal is approaching.</p>
  <table style="border-collapse:collapse">
    <tr><td style="padding:5px 20px 5px 0;color:#64748B">Customer</td><td><strong>{customer['name']}</strong></td></tr>
    <tr><td style="padding:5px 20px 5px 0;color:#64748B">License expiry</td><td><strong>{expires_on.isoformat()}</strong></td></tr>
    <tr><td style="padding:5px 20px 5px 0;color:#64748B">Days remaining</td><td><strong>{days_remaining}</strong></td></tr>
  </table>
  <p>This is a planning reminder only. Service remains active and is not interrupted by this notification.</p>
  <p>Please contact RiskRaven or renew in the admin panel before the license expiry date.</p>
</div>
"""

    for recipient_type, recipient in recipients:
        with get_conn() as conn:
            already_sent = conn.execute(
                "SELECT 1 FROM renewal_reminders WHERE customer_id=? AND days_before=? AND recipient=?",
                (customer["id"], milestone, recipient),
            ).fetchone()
        if already_sent:
            continue
        if send_renewal_reminder(recipient, subject, body_text, body_html):
            with get_conn() as conn:
                conn.execute(
                    "INSERT OR IGNORE INTO renewal_reminders "
                    "(customer_id, days_before, recipient, recipient_type, sent_at) VALUES (?,?,?,?,?)",
                    (customer["id"], milestone, recipient, recipient_type,
                     datetime.now(timezone.utc).isoformat()),
                )
    print(f"[monitor] renewal reminder processed for {customer['id']}: {days_remaining} day(s) remaining", flush=True)


def _query_agent_count(customer_id: str) -> int | None:
    import subprocess
    container = f"sentinel-{customer_id}"
    # _get_store() in server.py always resolves the live per-customer DB to this exact
    # path. Querying it directly (rather than globbing /app/data for any agents.db)
    # matters because customer containers accumulate stale/orphaned agents.db files
    # from old provisioning attempts (UUID-named dirs, default/, legacy /app/data/agents.db,
    # etc.) — globbing and taking the first match silently counts the wrong database
    # (almost always 0 devices), which is why overage alerts never fired.
    db_path = f"/app/data/customers/{customer_id}/agents.db"
    try:
        # Count every device ever registered, not just ones active in a recent
        # window — a customer shouldn't be able to accumulate more registrations
        # than their seat count without it surfacing as an overage, even if some
        # of those devices have since gone offline/decommissioned.
        result = subprocess.run(
            ["docker", "exec", container, "python3", "-c",
             f"import sqlite3; conn=sqlite3.connect('{db_path}'); "
             "print(conn.execute('SELECT COUNT(*) FROM devices').fetchone()[0])"],
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
  <div style="color:#00ff88;font-weight:bold;letter-spacing:3px;margin-bottom:16px">RISKRAVEN ARCKON</div>
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
        subject=f"[Arckon] Seat overage — {customer['name']} ({agent_count}/{customer['max_seats']})",
        body_text=body_text,
        body_html=body_html,
    )
    print(f"[monitor] overage alert sent for {customer['id']}: {agent_count}/{customer['max_seats']}", flush=True)
