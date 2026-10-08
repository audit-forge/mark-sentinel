import os
import threading
import time
from datetime import datetime, timedelta, timezone


from db import get_conn
from mailer import send_alert, send_renewal_reminder

MONITOR_INTERVAL = int(os.environ.get("MONITOR_INTERVAL_H", "1")) * 3600
ALERT_TO         = os.environ.get("ALERT_TO", "")
_SENTINEL_TIMEOUT = 5
_RENEWAL_REMINDER_DAYS = (90, 60, 30, 14, 7, 1)
_STALE_REMOVAL_GRACE_DAYS = 30


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
        _handle_stale_agents(dict(c))
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


def _broker_request(path: str, method: str = "GET", payload: dict | None = None) -> dict | None:
    import json
    import urllib.error
    import urllib.request
    token_path = os.environ.get("DEPLOY_TOKEN_FILE", "")
    try:
        with open(token_path, encoding="utf-8") as token_file:
            token = token_file.read().strip()
        request = urllib.request.Request(
            f"http://sentinel-deployer:9000{path}",
            data=json.dumps(payload).encode("utf-8") if payload is not None else None,
            method=method,
            headers={"Content-Type": "application/json", "X-Arckon-Deploy-Token": token},
        )
        with urllib.request.urlopen(request, timeout=15) as response:
            return json.loads(response.read())
    except urllib.error.HTTPError as e:
        print(f"[monitor] broker {method} {path} rejected: HTTP {e.code}", flush=True)
        return None
    except Exception as e:
        print(f"[monitor] broker {method} {path} unreachable: {e}", flush=True)
        return None


def _query_agent_count(customer_id: str) -> int | None:
    result = _broker_request(f"/usage/{customer_id}")
    try:
        return int(result["current_agents"]) if result else None
    except (KeyError, TypeError, ValueError):
        return None


def _stale_recipients(customer_id: str) -> list[tuple[str, str]]:
    with get_conn() as conn:
        contacts = [r[0] for r in conn.execute(
            "SELECT email FROM users WHERE customer_id=? AND role='customer_admin' AND active=1",
            (customer_id,),
        ).fetchall()]
    recipients = [("customer", email) for email in contacts]
    if ALERT_TO and ALERT_TO not in contacts:
        recipients.append(("internal", ALERT_TO))
    return recipients


def _send_stale_notice(customer: dict, agents: list[dict], event_type: str) -> None:
    if not agents:
        return
    if event_type == "warning":
        subject = f"[Arckon] Stale agent warning - {customer['name']}"
        body = (
            f"Arckon stale-device warning\n\nCustomer: {customer['name']}\n\n"
            "The following devices have not reported for at least 26 hours:\n"
        )
    else:
        subject = f"[Arckon] Stale agents removed - {customer['name']}"
        body = (
            f"Arckon removed stale agent registrations after their 30-day grace period.\n\n"
            f"Customer: {customer['name']}\n\nRemoved devices:\n"
        )
    for _recipient_type, recipient in _stale_recipients(customer["id"]):
        with get_conn() as conn:
            unsent = [agent for agent in agents if conn.execute(
                "SELECT 1 FROM stale_agent_notifications WHERE customer_id=? AND device_id=? AND event_type=? AND recipient=?",
                (customer["id"], agent["device_id"], event_type, recipient),
            ).fetchone() is None]
        if not unsent:
            continue
        device_lines = []
        for agent in unsent:
            last_seen = datetime.fromtimestamp(agent["last_seen"], timezone.utc).isoformat()
            if event_type == "warning":
                device_lines.append(
                    f"- {agent['hostname']} (last seen: {last_seen}; removal scheduled: {agent['removal_due_at']})"
                )
            else:
                device_lines.append(f"- {agent['hostname']} (last seen: {last_seen})")
        suffix = (
            "\n\nIf an agent reports again before its removal date, its registration is retained. "
            "If it returns after removal, it will re-register automatically."
            if event_type == "warning" else
            "\n\nIf a device returns, its installed agent will re-register automatically."
        )
        if not send_renewal_reminder(recipient, subject, body + "\n".join(device_lines) + suffix):
            continue
        with get_conn() as conn:
            conn.executemany(
                "INSERT OR IGNORE INTO stale_agent_notifications "
                "(customer_id, device_id, event_type, recipient, sent_at) VALUES (?,?,?,?,?)",
                [(customer["id"], agent["device_id"], event_type, recipient,
                  datetime.now(timezone.utc).isoformat()) for agent in unsent],
            )


def _handle_stale_agents(customer: dict) -> None:
    response = _broker_request(f"/stale/{customer['id']}")
    if response is None:
        return
    stale_agents = response.get("agents", [])
    stale_by_id = {agent["device_id"]: agent for agent in stale_agents}
    now = datetime.now(timezone.utc)
    warnings: list[dict] = []
    with get_conn() as conn:
        tracked = conn.execute(
            "SELECT device_id, last_seen, removal_due_at, removed_at FROM stale_agent_lifecycle WHERE customer_id=?",
            (customer["id"],),
        ).fetchall()
        for item in tracked:
            agent = stale_by_id.get(item["device_id"])
            # Keep completed removals as an audit record. A re-reporting device
            # has a new last_seen value and begins a fresh warning cycle.
            if (agent is not None and agent["last_seen"] != item["last_seen"]) or (
                agent is None and item["removed_at"] is None
            ):
                conn.execute("DELETE FROM stale_agent_lifecycle WHERE customer_id=? AND device_id=?",
                             (customer["id"], item["device_id"]))
                conn.execute("DELETE FROM stale_agent_notifications WHERE customer_id=? AND device_id=?",
                             (customer["id"], item["device_id"]))
        for agent in stale_agents:
            existing = conn.execute(
                "SELECT removal_due_at, removed_at FROM stale_agent_lifecycle WHERE customer_id=? AND device_id=?",
                (customer["id"], agent["device_id"]),
            ).fetchone()
            if existing:
                continue
            due_at = (now + timedelta(days=_STALE_REMOVAL_GRACE_DAYS)).isoformat()
            conn.execute(
                "INSERT INTO stale_agent_lifecycle "
                "(customer_id, device_id, hostname, last_seen, notified_at, removal_due_at) VALUES (?,?,?,?,?,?)",
                (customer["id"], agent["device_id"], agent["hostname"], agent["last_seen"],
                 now.isoformat(), due_at),
            )
            warnings.append({**agent, "removal_due_at": due_at})

    _send_stale_notice(customer, warnings, "warning")

    with get_conn() as conn:
        due = conn.execute(
            "SELECT device_id, hostname, last_seen, removal_due_at FROM stale_agent_lifecycle "
            "WHERE customer_id=? AND removed_at IS NULL AND removal_due_at <= ?",
            (customer["id"], now.isoformat()),
        ).fetchall()
    removed: list[dict] = []
    for item in due:
        agent = dict(item)
        result = _broker_request("/stale/remove", "POST", {
            "customer_id": customer["id"], "device_id": agent["device_id"], "last_seen": agent["last_seen"],
        })
        if not result or not result.get("removed"):
            continue
        with get_conn() as conn:
            conn.execute(
                "UPDATE stale_agent_lifecycle SET removed_at=? WHERE customer_id=? AND device_id=?",
                (datetime.now(timezone.utc).isoformat(), customer["id"], agent["device_id"]),
            )
        removed.append(agent)
    _send_stale_notice(customer, removed, "removal")


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
