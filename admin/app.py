import os
import uuid
import json
import secrets
import string
import subprocess
import time
from collections import defaultdict
from datetime import datetime, date, timezone, timedelta
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from typing import Union

from db import init_db, get_conn, log_audit, get_audit_log
from auth import hash_password, verify_password, create_token, get_current_user, require_super_admin
from monitor import start_monitor

app = FastAPI(docs_url=None, redoc_url=None)
templates = Jinja2Templates(directory="templates")

# Brute-force protection: track failed attempts per IP
_login_attempts: dict[str, list[float]] = defaultdict(list)
_LOGIN_WINDOW   = 300   # 5 minutes
_LOGIN_MAX      = 10    # max attempts per window
_LOCKOUT_SECS   = 600   # 10 minute lockout after exceeding limit

def _check_rate_limit(ip: str) -> bool:
    """Return True if the IP is allowed to attempt login, False if locked out."""
    now = time.time()
    attempts = [t for t in _login_attempts[ip] if now - t < _LOGIN_WINDOW]
    _login_attempts[ip] = attempts
    return len(attempts) < _LOGIN_MAX

def _record_failed_login(ip: str) -> None:
    _login_attempts[ip].append(time.time())

ADMIN_EMAIL    = os.environ.get("ADMIN_EMAIL", "admin@sentinel.local")
MAX_CUSTOMERS  = int(os.environ.get("MAX_CUSTOMERS", "0"))  # 0 = unlimited
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "changeme")
PUBLIC_IP = os.environ.get("PUBLIC_IP", "35.255.19.236")


@app.on_event("startup")
def startup():
    init_db()
    _ensure_super_admin()
    start_monitor()


def _ensure_super_admin():
    with get_conn() as conn:
        row = conn.execute("SELECT id FROM users WHERE role='super_admin' LIMIT 1").fetchone()
        if not row:
            conn.execute(
                "INSERT INTO users (id, email, password_hash, role, customer_id, created_at) VALUES (?,?,?,?,?,?)",
                (str(uuid.uuid4()), ADMIN_EMAIL, hash_password(ADMIN_PASSWORD),
                 "super_admin", None, datetime.now(timezone.utc).isoformat())
            )


def _sentinel_url(customer_id: Union[str, None]) -> str:
    """Return the Sentinel dashboard URL for a given customer_id."""
    if not customer_id:
        return "/login"
    with get_conn() as conn:
        row = conn.execute("SELECT port FROM customers WHERE id=?", (customer_id,)).fetchone()
    if not row or not row["port"]:
        return "/login"
    return f"http://{PUBLIC_IP}:{row['port']}"


# ── Auth ──────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def root():
    return RedirectResponse("/dashboard")


@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    next_url = request.query_params.get("next", "")
    return templates.TemplateResponse("login.html", {"request": request, "error": None, "next": next_url})


@app.post("/login")
async def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    next: str = Form(""),
):
    client_ip = request.client.host if request.client else "unknown"
    if not _check_rate_limit(client_ip):
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Too many failed attempts. Try again in 10 minutes.",
            "next": next,
        }, status_code=429)
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE email=? AND active=1", (email,)
        ).fetchone()
    if not row or not verify_password(password, row["password_hash"]) or (row["customer_id"] and not _check_customer_active(row["customer_id"])):
        _record_failed_login(client_ip)
        log_audit(
            actor_id="unknown", actor_name=email, actor_role="unknown",
            customer_id="", action="login.failed", target=email,
            details="Invalid credentials", ip_address=client_ip
        )
        return templates.TemplateResponse("login.html", {
            "request": request, "error": "Invalid credentials", "next": next
        })
    token = create_token(row["id"], row["role"], row["customer_id"], row["email"])
    log_audit(
        actor_id=row["id"], actor_name=row["email"], actor_role=row["role"],
        customer_id=row["customer_id"] or "", action="login.success", target=email,
        details="User logged in successfully", ip_address=client_ip
    )
    if not next:
        destination = "/dashboard" if row["role"] == "super_admin" else _sentinel_url(row["customer_id"])
    else:
        destination = next
    resp = RedirectResponse(destination, status_code=303)
    resp.set_cookie("token", token, httponly=True, max_age=28800, samesite="lax")
    return resp


@app.get("/logout")
async def logout(request: Request, next: str = None):
    user = None
    try:
        user = get_current_user(request)
    except Exception:
        pass # user might be already logged out or invalid token

    if user:
        log_audit(
            actor_id=user["sub"], actor_name=user["email"], actor_role=user["role"],
            customer_id=user["customer_id"] or "", action="logout", target=user["email"],
            details="User logged out", ip_address=request.client.host if request.client else "unknown"
        )

    if next and next.startswith('http'):
        dest = next
    else:
        try:
            user = get_current_user(request)
            dest = "/login" if user.get("role") == "super_admin" else _sentinel_url(user.get("customer_id"))
        except Exception:
            dest = "/login"
    resp = RedirectResponse(dest, status_code=303)
    resp.delete_cookie("token")
    return resp


@app.get("/auth/verify")
async def auth_verify(request: Request):
    from fastapi.responses import Response
    try:
        user = get_current_user(request)
    except HTTPException:
        return Response(status_code=401)
    customer_id = request.headers.get("X-Customer-ID", "")
    if customer_id and user["role"] != "super_admin":
        if user.get("customer_id") != customer_id:
            return Response(status_code=403)
    with get_conn() as conn:
        row = conn.execute("SELECT email FROM users WHERE id=?", (user["sub"],)).fetchone()
    email = row["email"] if row else ""
    return Response(status_code=200, headers={
        "X-Sentinel-User-Email":    email,
        "X-Sentinel-User-Role":     user.get("role", ""),
        "X-Sentinel-Customer-ID":   user.get("customer_id", ""),
    })


# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    try:
        user = get_current_user(request)
    except HTTPException:
        return RedirectResponse("/login")
    if user.get("role") != "super_admin":
        return RedirectResponse(_sentinel_url(user.get("customer_id")))
    with get_conn() as conn:
        customer_count = conn.execute(
            "SELECT COUNT(*) FROM customers WHERE active=1"
        ).fetchone()[0]
        user_count = conn.execute(
            "SELECT COUNT(*) FROM users WHERE active=1 AND role != 'super_admin'"
        ).fetchone()[0]
        seat_rows = conn.execute(
            "SELECT id, name, tier, max_seats, current_agents FROM customers WHERE active=1 ORDER BY name"
        ).fetchall()
        alert_rows = conn.execute(
            "SELECT a.*, c.name as customer_name FROM license_alerts a "
            "JOIN customers c ON a.customer_id = c.id "
            "ORDER BY a.created_at DESC LIMIT 20"
        ).fetchall()
    seats = [dict(r) for r in seat_rows]
    overages = sum(1 for s in seats if s["current_agents"] > s["max_seats"])
    return templates.TemplateResponse("dashboard.html", {
        "request": request, "user": user,
        "customer_count": customer_count, "user_count": user_count,
        "ip": PUBLIC_IP,
        "seats": seats,
        "overages": overages,
        "alerts": [dict(r) for r in alert_rows],
    })


# ── Deploy ────────────────────────────────────────────────────────────────────

@app.post("/admin/dismiss-alert")
async def dismiss_alert(request: Request, alert_id: int = Form(...)):
    try:
        user = require_super_admin(request)
    except HTTPException:
        return RedirectResponse("/login")
    client_ip = request.client.host if request.client else "unknown"
    with get_conn() as conn:
        conn.execute("DELETE FROM license_alerts WHERE id=?", (alert_id,))
    log_audit(
        actor_id=user["sub"], actor_name=user["email"], actor_role=user["role"],
        customer_id="", action="alert.dismiss", target=str(alert_id),
        details="Dismissed license alert", ip_address=client_ip
    )
    return RedirectResponse("/dashboard", status_code=303)


@app.post("/admin/refresh-seats")
async def refresh_seats(request: Request):
    try:
        user = require_super_admin(request)
    except HTTPException:
        return RedirectResponse("/login")
    client_ip = request.client.host if request.client else "unknown"
    import threading
    from monitor import _check_all_customers
    threading.Thread(target=_check_all_customers, daemon=True).start()
    log_audit(
        actor_id=user["sub"], actor_name=user["email"], actor_role=user["role"],
        customer_id="", action="seats.refresh", target="",
        details="Triggered manual seat-count refresh for all customers", ip_address=client_ip
    )
    return RedirectResponse("/dashboard?seats_refreshed=1", status_code=303)


@app.post("/admin/deploy")
async def deploy(request: Request):
    try:
        user = require_super_admin(request)
    except HTTPException:
        return RedirectResponse("/login")
    client_ip = request.client.host if request.client else "unknown"
    import urllib.request as urlreq
    try:
        req = urlreq.Request("http://sentinel-deployer:9000/deploy", method="POST", data=b"")
        with urlreq.urlopen(req, timeout=5) as r:
            code = r.status
        result = "started" if code == 202 else "busy" if code == 409 else "failed"
    except Exception:
        result = "failed"
    log_audit(
        actor_id=user["sub"], actor_name=user["email"], actor_role=user["role"],
        customer_id="", action="deploy.trigger", target="",
        details=f"Triggered deploy — result: {result}", ip_address=client_ip
    )
    return RedirectResponse(f"/dashboard?deploy={result}", status_code=303)


# ── Test email ────────────────────────────────────────────────────────────────

@app.post("/admin/test-email")
async def test_email(request: Request):
    try:
        user = require_super_admin(request)
    except HTTPException:
        return RedirectResponse("/login")
    client_ip = request.client.host if request.client else "unknown"
    from mailer import send_alert
    ok = send_alert(
        subject="[Sentinel] Test alert — email is working",
        body_text="This is a test alert from M.A.R.K. Sentinel admin panel.\n\nIf you received this, email alerts are configured correctly.",
        body_html="""
<div style="font-family:monospace;background:#0a0a0a;color:#e0e0e0;padding:24px;max-width:520px">
  <div style="color:#00ff88;font-weight:bold;letter-spacing:3px;margin-bottom:16px">M.A.R.K. SENTINEL</div>
  <div style="font-size:15px;color:#fff;margin-bottom:12px">Test Alert</div>
  <div style="font-size:13px;color:#aaa">Email alerts are configured correctly.</div>
</div>
""",
    )
    result = "ok" if ok else "fail"
    log_audit(
        actor_id=user["sub"], actor_name=user["email"], actor_role=user["role"],
        customer_id="", action="email.test", target="",
        details=f"Sent test alert email — result: {result}", ip_address=client_ip
    )
    return RedirectResponse(f"/dashboard?email_test={result}", status_code=303)


# ── Installer scripts (served publicly — no secrets embedded) ─────────────────

@app.get("/install/{filename}")
async def serve_installer(filename: str):
    from fastapi.responses import FileResponse
    allowed = {"install.sh", "install.ps1"}
    if filename not in allowed:
        raise HTTPException(404)
    path = f"/app/{filename}"
    if not os.path.exists(path):
        raise HTTPException(404)
    media_type = "text/plain"
    return FileResponse(path, media_type=media_type, filename=filename)


# ── Customers ─────────────────────────────────────────────────────────────────

@app.get("/customers", response_class=HTMLResponse)
async def customers_page(request: Request):
    try:
        user = require_super_admin(request)
    except HTTPException:
        return RedirectResponse("/login")
    status = request.query_params.get("status", "active")
    with get_conn() as conn:
        if status == "inactive":
            rows = conn.execute("SELECT * FROM customers WHERE active=0 ORDER BY created_at DESC").fetchall()
        elif status == "all":
            rows = conn.execute("SELECT * FROM customers ORDER BY created_at DESC").fetchall()
        else:
            rows = conn.execute("SELECT * FROM customers WHERE active=1 ORDER BY created_at DESC").fetchall()
    customers = []
    for r in rows:
        c = dict(r)
        try:
            c["days_remaining"] = (date.fromisoformat(c["license_expires_at"]) - date.today()).days
        except (TypeError, ValueError):
            c["days_remaining"] = None
        customers.append(c)
    return templates.TemplateResponse("customers.html", {
        "request": request, "user": user,
        "customers": customers, "ip": PUBLIC_IP, "status": status,
    })


@app.post("/customers/add")
async def add_customer(
    request: Request,
    customer_id: str = Form(...),
    customer_name: str = Form(...),
    customer_email: str = Form(""),
    tier: str = Form("standard"),
    max_seats: int = Form(5),
):
    try:
        user = require_super_admin(request)
    except HTTPException:
        return RedirectResponse("/login")
    client_ip = request.client.host if request.client else "unknown"
    cid = customer_id.lower().strip().replace(" ", "-")
    if tier not in ("standard", "plus"):
        tier = "standard"
    expires = (date.today() + timedelta(days=365)).isoformat()
    agent_token = secrets.token_urlsafe(32)
    with get_conn() as conn:
        if MAX_CUSTOMERS > 0:
            active_count = conn.execute(
                "SELECT COUNT(*) FROM customers WHERE active=1"
            ).fetchone()[0]
            if active_count >= MAX_CUSTOMERS:
                log_audit(
                    actor_id=user["sub"], actor_name=user["email"], actor_role=user["role"],
                    customer_id="", action="customer.add.failed", target=cid,
                    details="Exceeded max customer limit", ip_address=client_ip
                )
                return RedirectResponse("/customers?error=cap", status_code=303)
        exists = conn.execute("SELECT id FROM customers WHERE id=?", (cid,)).fetchone()
        if exists:
            log_audit(
                actor_id=user["sub"], actor_name=user["email"], actor_role=user["role"],
                customer_id="", action="customer.add.failed", target=cid,
                details="Customer ID already exists", ip_address=client_ip
            )
            return RedirectResponse("/customers?error=exists", status_code=303)
        max_port = conn.execute("SELECT MAX(port) FROM customers").fetchone()[0]
        port = (max_port or 7000) + 1
        conn.execute(
            "INSERT INTO customers (id, name, created_at, active, tier, license_expires_at, max_seats, port, agent_token) VALUES (?,?,?,1,?,?,?,?,?)",
            (cid, customer_name.strip(), datetime.now(timezone.utc).isoformat(), tier, expires, max_seats, port, agent_token)
        )
        if customer_email.strip():
            email = customer_email.strip().lower()
            existing = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
            if existing:
                conn.execute("UPDATE users SET active=1, customer_id=?, role='customer_admin' WHERE email=?",
                             (cid, email))
                log_audit(
                    actor_id=user["sub"], actor_name=user["email"], actor_role=user["role"],
                    customer_id=cid, action="user.reactivate", target=email,
                    details=f"Reactivated existing user {email} as customer admin for {customer_name}", ip_address=client_ip
                )
            else:
                temp_password = _generate_temp_password()
                conn.execute(
                    "INSERT INTO users (id, email, password_hash, role, customer_id, created_at) VALUES (?,?,?,?,?,?)",
                    (str(uuid.uuid4()), email, hash_password(temp_password),
                     "customer_admin", cid, datetime.now(timezone.utc).isoformat())
                )
                login_url = f"http://{PUBLIC_IP}/login"
                from mailer import send_welcome_email
                send_welcome_email(email, customer_name.strip(), login_url, temp_password)
                log_audit(
                    actor_id=user["sub"], actor_name=user["email"], actor_role=user["role"],
                    customer_id=cid, action="user.add", target=email,
                    details=f"Created new customer admin {email} for {customer_name}", ip_address=client_ip
                )
    _write_license_file(cid, customer_name.strip(), tier, expires, max_seats)
    _run_script("provision_customer.sh", cid, PUBLIC_IP, tier, expires, str(max_seats), customer_name.strip(), str(port), agent_token)
    log_audit(
        actor_id=user["sub"], actor_name=user["email"], actor_role=user["role"],
        customer_id=cid, action="customer.add", target=customer_name.strip(),
        details=f"Added new customer {customer_name} (Tier: {tier}, Seats: {max_seats})", ip_address=client_ip
    )
    return RedirectResponse("/customers", status_code=303)


@app.post("/customers/renew")
async def renew_customer(request: Request, customer_id: str = Form(...)):
    try:
        user = require_super_admin(request)
    except HTTPException:
        return RedirectResponse("/login")
    client_ip = request.client.host if request.client else "unknown"
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM customers WHERE id=?", (customer_id,)).fetchone()
        if not row:
            log_audit(
                actor_id=user["sub"], actor_name=user["email"], actor_role=user["role"],
                customer_id=customer_id, action="customer.renew.failed", target=customer_id,
                details="Customer not found", ip_address=client_ip
            )
            return RedirectResponse("/customers", status_code=303)
        current_expiry = row["license_expires_at"]
        try:
            base = max(date.fromisoformat(current_expiry), date.today())
        except (TypeError, ValueError):
            base = date.today()
        new_expiry = (base + timedelta(days=365)).isoformat()
        conn.execute(
            "UPDATE customers SET license_expires_at=? WHERE id=?",
            (new_expiry, customer_id)
        )
        tier = row["tier"]
        max_seats = row["max_seats"]
        name = row["name"]
    _write_license_file(customer_id, name, tier, new_expiry, max_seats)
    _run_script("restart_customer.sh", customer_id)
    log_audit(
        actor_id=user["sub"], actor_name=user["email"], actor_role=user["role"],
        customer_id=customer_id, action="customer.renew", target=name,
        details=f"Renewed license for {name} until {new_expiry}", ip_address=client_ip
    )
    return RedirectResponse("/customers", status_code=303)


@app.post("/customers/seats")
async def update_seats(request: Request, customer_id: str = Form(...), max_seats: int = Form(...)):
    try:
        user = require_super_admin(request)
    except HTTPException:
        return RedirectResponse("/login")
    client_ip = request.client.host if request.client else "unknown"
    if max_seats < 1:
        log_audit(
            actor_id=user["sub"], actor_name=user["email"], actor_role=user["role"],
            customer_id=customer_id, action="customer.seats.failed", target=customer_id,
            details=f"Invalid seat count: {max_seats}", ip_address=client_ip
        )
        return RedirectResponse("/customers?error=invalid_seats", status_code=303)
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM customers WHERE id=?", (customer_id,)).fetchone()
        if not row:
            log_audit(
                actor_id=user["sub"], actor_name=user["email"], actor_role=user["role"],
                customer_id=customer_id, action="customer.seats.failed", target=customer_id,
                details="Customer not found", ip_address=client_ip
            )
            return RedirectResponse("/customers?error=notfound", status_code=303)
        old_max_seats = row["max_seats"]
        conn.execute("UPDATE customers SET max_seats=? WHERE id=?", (max_seats, customer_id))
        name    = row["name"]
        tier    = row["tier"]
        expires = row["license_expires_at"]
    _write_license_file(customer_id, name, tier, expires, max_seats)
    _run_script("restart_customer.sh", customer_id)
    log_audit(
        actor_id=user["sub"], actor_name=user["email"], actor_role=user["role"],
        customer_id=customer_id, action="customer.seats.update", target=name,
        details=f"Updated seats for {name} from {old_max_seats} to {max_seats}", ip_address=client_ip
    )
    return RedirectResponse("/customers?seats_updated=" + customer_id, status_code=303)


@app.post("/customers/upgrade")
async def upgrade_customer(request: Request, customer_id: str = Form(...), tier: str = Form(...)):
    try:
        user = require_super_admin(request)
    except HTTPException:
        return RedirectResponse("/login")
    client_ip = request.client.host if request.client else "unknown"
    if tier not in ("standard", "plus"):
        log_audit(
            actor_id=user["sub"], actor_name=user["email"], actor_role=user["role"],
            customer_id=customer_id, action="customer.upgrade.failed", target=customer_id,
            details=f"Invalid tier: {tier}", ip_address=client_ip
        )
        return RedirectResponse("/customers?error=invalid_tier", status_code=303)
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM customers WHERE id=?", (customer_id,)).fetchone()
        if not row:
            log_audit(
                actor_id=user["sub"], actor_name=user["email"], actor_role=user["role"],
                customer_id=customer_id, action="customer.upgrade.failed", target=customer_id,
                details="Customer not found", ip_address=client_ip
            )
            return RedirectResponse("/customers?error=notfound", status_code=303)
        old_tier = row["tier"]
        conn.execute("UPDATE customers SET tier=? WHERE id=?", (tier, customer_id))
        name    = row["name"]
        expires = row["license_expires_at"]
        max_seats = row["max_seats"]
    _write_license_file(customer_id, name, tier, expires, max_seats)
    _run_script("restart_customer.sh", customer_id)
    log_audit(
        actor_id=user["sub"], actor_name=user["email"], actor_role=user["role"],
        customer_id=customer_id, action="customer.upgrade", target=name,
        details=f"Upgraded plan for {name} from {old_tier} to {tier}", ip_address=client_ip
    )
    return RedirectResponse("/customers?plan_updated=" + customer_id, status_code=303)


@app.post("/customers/remove")
async def remove_customer(request: Request, customer_id: str = Form(...)):
    try:
        user = require_super_admin(request)
    except HTTPException:
        return RedirectResponse("/login")
    client_ip = request.client.host if request.client else "unknown"
    with get_conn() as conn:
        # Get customer name before deactivating
        customer_name_row = conn.execute("SELECT name FROM customers WHERE id=?", (customer_id,)).fetchone()
        customer_name = customer_name_row["name"] if customer_name_row else customer_id

        conn.execute("UPDATE customers SET active=0 WHERE id=?", (customer_id,))
        conn.execute("UPDATE users SET active=0 WHERE customer_id=?", (customer_id,))

    _run_script("remove_customer.sh", customer_id)
    log_audit(
        actor_id=user["sub"], actor_name=user["email"], actor_role=user["role"],
        customer_id=customer_id, action="customer.remove", target=customer_name,
        details=f"Deactivated customer {customer_name} and all associated users", ip_address=client_ip
    )
    return RedirectResponse("/customers", status_code=303)


@app.post("/customers/restore")
async def restore_customer(request: Request, customer_id: str = Form(...)):
    try:
        user = require_super_admin(request)
    except HTTPException:
        return RedirectResponse("/login")
    client_ip = request.client.host if request.client else "unknown"
    with get_conn() as conn:
        # Get customer name before reactivating
        customer_name_row = conn.execute("SELECT name FROM customers WHERE id=?", (customer_id,)).fetchone()
        customer_name = customer_name_row["name"] if customer_name_row else customer_id

        conn.execute("UPDATE customers SET active=1 WHERE id=?", (customer_id,))
    _run_script("provision_customer.sh", customer_id, PUBLIC_IP)
    log_audit(
        actor_id=user["sub"], actor_name=user["email"], actor_role=user["role"],
        customer_id=customer_id, action="customer.restore", target=customer_name,
        details=f"Restored customer {customer_name}", ip_address=client_ip
    )
    return RedirectResponse("/customers", status_code=303)


@app.post("/customers/delete")
async def delete_customer(request: Request, customer_id: str = Form(...)):
    try:
        user = require_super_admin(request)
    except HTTPException:
        return RedirectResponse("/login")
    client_ip = request.client.host if request.client else "unknown"
    with get_conn() as conn:
        # Get customer name before deleting
        customer_name_row = conn.execute("SELECT name FROM customers WHERE id=?", (customer_id,)).fetchone()
        customer_name = customer_name_row["name"] if customer_name_row else customer_id

        conn.execute("DELETE FROM customers WHERE id=? AND active=0", (customer_id,))
        conn.execute("DELETE FROM users WHERE customer_id=?", (customer_id,))
    _run_script("remove_customer.sh", customer_id)
    log_audit(
        actor_id=user["sub"], actor_name=user["email"], actor_role=user["role"],
        customer_id=customer_id, action="customer.delete", target=customer_name,
        details=f"Permanently deleted inactive customer {customer_name} and all associated users", ip_address=client_ip
    )
    return RedirectResponse("/customers?status=inactive", status_code=303)


@app.post("/customers/rotate-token")
async def rotate_customer_token(request: Request):
    """Rotate agent token with 48h rollover window.
    Old token stays valid while agents self-update via in-band delivery and set_config push."""
    try:
        require_super_admin(request)
    except HTTPException:
        return JSONResponse({"error": "unauthorized"}, status_code=403)
    try:
        body = await request.json()
        customer_id = str(body.get("customer_id", "")).strip()
    except Exception:
        return JSONResponse({"error": "invalid_request"}, status_code=400)
    if not customer_id:
        return JSONResponse({"error": "customer_id required"}, status_code=400)

    new_token = secrets.token_urlsafe(32)
    rollover_hours = 48
    expires_at = int(__import__("time").time()) + rollover_hours * 3600

    with get_conn() as conn:
        row = conn.execute(
            "SELECT id, name, port, agent_token FROM customers WHERE id=? AND active=1", (customer_id,)
        ).fetchone()
        if not row:
            log_audit(
                actor_id=user["sub"], actor_name=user["email"], actor_role=user["role"],
                customer_id=customer_id, action="customer.rotate_token.failed", target=customer_id,
                details="Customer not found", ip_address=client_ip
            )
            return JSONResponse({"error": "customer not found"}, status_code=404)
        old_token_prefix = row["agent_token"][:8]
        # Migrate columns if needed
        existing_cols = {r[1] for r in conn.execute("PRAGMA table_info(customers)").fetchall()}
        if "agent_token_prev" not in existing_cols:
            conn.execute("ALTER TABLE customers ADD COLUMN agent_token_prev TEXT DEFAULT NULL")
        if "token_prev_expires" not in existing_cols:
            conn.execute("ALTER TABLE customers ADD COLUMN token_prev_expires INTEGER DEFAULT 0")
        conn.execute(
            "UPDATE customers SET agent_token_prev=agent_token, token_prev_expires=?, agent_token=? WHERE id=?",
            (expires_at, new_token, customer_id),
        )

    # Tell the Sentinel server for this customer to push set_config to all known devices
    push_count = 0
    port = row["port"] if row["port"] else 7001
    sentinel_url = f"http://127.0.0.1:{port}/api/fleet/push-token"
    try:
        import httpx
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.post(sentinel_url)
            if r.status_code == 200:
                push_count = r.json().get("device_count", 0)
    except Exception as e:
        log_audit(
            actor_id=user["sub"], actor_name=user["email"], actor_role=user["role"],
            customer_id=customer_id, action="customer.rotate_token.push_failed", target=row["name"],
            details=f"Failed to push new token to customer's Sentinel server: {e}", ip_address=client_ip
        )
        pass  # push is best-effort; in-band delivery still works

    log_audit(
        actor_id=user["sub"], actor_name=user["email"], actor_role=user["role"],
        customer_id=customer_id, action="customer.rotate_token", target=row["name"],
        details=f"Rotated agent token for {row["name"]}. Old token (ends {old_token_prefix}) valid for {rollover_hours}h.", ip_address=client_ip
    )

    return JSONResponse({
        "token": new_token,
        "customer_id": customer_id,
        "name": row["name"],
        "rollover_hours": rollover_hours,
        "expires_at": expires_at,
        "push_queued": push_count,
    })


# ── Audit log (super-admin, platform-wide) ────────────────────────────────────

@app.get("/audit-log", response_class=HTMLResponse)
async def audit_log_page(request: Request):
    try:
        user = require_super_admin(request)
    except HTTPException:
        return RedirectResponse("/login")
    customer_id = request.query_params.get("customer_id", "").strip()
    action = request.query_params.get("action", "").strip()
    with get_conn() as conn:
        customers = [dict(r) for r in conn.execute(
            "SELECT id, name FROM customers ORDER BY name"
        ).fetchall()]
        actions = [r["action"] for r in conn.execute(
            "SELECT DISTINCT action FROM audit_log WHERE action != '' ORDER BY action"
        ).fetchall()]
    entries = get_audit_log(limit=300, customer_id=customer_id or None)
    if action:
        entries = [e for e in entries if e["action"] == action]
    for e in entries:
        e["occurred_at_display"] = datetime.fromtimestamp(e["occurred_at"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return templates.TemplateResponse("audit_log.html", {
        "request": request, "user": user,
        "entries": entries, "customers": customers, "actions": actions,
        "customer_id": customer_id, "action": action,
    })


@app.get("/audit-log/csv")
async def audit_log_csv(request: Request):
    import io, csv
    from fastapi.responses import Response
    try:
        require_super_admin(request)
    except HTTPException:
        return RedirectResponse("/login")
    customer_id = request.query_params.get("customer_id", "").strip()
    action = request.query_params.get("action", "").strip()
    entries = get_audit_log(limit=2000, customer_id=customer_id or None)
    if action:
        entries = [e for e in entries if e["action"] == action]
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["Timestamp (UTC)", "Actor", "Role", "Customer", "Action", "Target", "Details", "IP Address"])
    for e in entries:
        writer.writerow([
            datetime.fromtimestamp(e["occurred_at"], tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            e["actor_name"] or e["actor_id"], e["actor_role"], e["customer_id"],
            e["action"], e["target"], e["details"], e["ip_address"],
        ])
    fname = f'sentinel_admin_audit_log_{datetime.now(timezone.utc).strftime("%Y%m%d")}.csv'
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{fname}"'},
    )


# ── Forgot / Reset password ───────────────────────────────────────────────────

@app.get("/forgot-password", response_class=HTMLResponse)
async def forgot_password_page(request: Request):
    return templates.TemplateResponse("forgot_password.html", {"request": request, "sent": False})


@app.post("/forgot-password", response_class=HTMLResponse)
async def forgot_password_submit(request: Request, email: str = Form(...)):
    client_ip = request.client.host if request.client else "unknown"
    addr = email.strip().lower()
    with get_conn() as conn:
        row = conn.execute(
            "SELECT id FROM users WHERE email=? AND active=1", (addr,)
        ).fetchone()
        if row:
            token = secrets.token_urlsafe(32)
            expires = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
            conn.execute(
                "INSERT INTO password_resets (id, user_id, token, expires_at) VALUES (?,?,?,?)",
                (str(uuid.uuid4()), row["id"], token, expires)
            )
            reset_url = f"http://{PUBLIC_IP}/reset-password?token={token}"
            from mailer import send_password_reset_email
            send_password_reset_email(addr, reset_url)
            log_audit(
                actor_id=row["id"], actor_name=addr, actor_role="unknown",
                customer_id="", action="password.reset.requested", target=addr,
                details="Password reset email sent", ip_address=client_ip
            )
    return templates.TemplateResponse("forgot_password.html", {"request": request, "sent": True})


@app.get("/reset-password", response_class=HTMLResponse)
async def reset_password_page(request: Request, token: str = ""):
    valid = False
    if token:
        with get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM password_resets WHERE token=? AND used=0", (token,)
            ).fetchone()
            if row:
                expires = datetime.fromisoformat(row["expires_at"])
                if expires > datetime.now(timezone.utc):
                    valid = True
    return templates.TemplateResponse("reset_password.html", {
        "request": request, "token": token, "valid": valid, "done": False, "error": None
    })


@app.post("/reset-password", response_class=HTMLResponse)
async def reset_password_submit(
    request: Request,
    token: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
):
    client_ip = request.client.host if request.client else "unknown"
    if new_password != confirm_password:
        return templates.TemplateResponse("reset_password.html", {
            "request": request, "token": token, "valid": True,
            "done": False, "error": "Passwords do not match"
        })
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM password_resets WHERE token=? AND used=0", (token,)
        ).fetchone()
        if not row:
            return templates.TemplateResponse("reset_password.html", {
                "request": request, "token": token, "valid": False, "done": False, "error": None
            })
        expires = datetime.fromisoformat(row["expires_at"])
        if expires <= datetime.now(timezone.utc):
            return templates.TemplateResponse("reset_password.html", {
                "request": request, "token": token, "valid": False, "done": False, "error": None
            })
        user_row = conn.execute("SELECT email FROM users WHERE id=?", (row["user_id"],)).fetchone()
        conn.execute("UPDATE users SET password_hash=? WHERE id=?",
                     (hash_password(new_password), row["user_id"]))
        conn.execute("UPDATE password_resets SET used=1 WHERE token=?", (token,))
        log_audit(
            actor_id=row["user_id"], actor_name=user_row["email"] if user_row else "", actor_role="unknown",
            customer_id="", action="password.reset.completed", target=user_row["email"] if user_row else "",
            details="Password reset via emailed token", ip_address=client_ip
        )
    return templates.TemplateResponse("reset_password.html", {
        "request": request, "token": "", "valid": False, "done": True, "error": None
    })


# ── Account ───────────────────────────────────────────────────────────────────

@app.get("/account", response_class=HTMLResponse)
async def account_page(request: Request):
    try:
        user = get_current_user(request)
    except HTTPException:
        return RedirectResponse("/login")
    return templates.TemplateResponse("account.html", {"request": request, "user": user})


@app.post("/account/password")
async def account_change_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
):
    try:
        user = get_current_user(request)
    except HTTPException:
        return RedirectResponse("/login")
    client_ip = request.client.host if request.client else "unknown"
    if new_password != confirm_password:
        return RedirectResponse("/account?error=mismatch", status_code=303)
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE id=?", (user["sub"],)).fetchone()
        if not row or not verify_password(current_password, row["password_hash"]):
            return RedirectResponse("/account?error=wrong_password", status_code=303)
        conn.execute(
            "UPDATE users SET password_hash=? WHERE id=?",
            (hash_password(new_password), user["sub"])
        )
    log_audit(
        actor_id=user["sub"], actor_name=user["email"], actor_role=user["role"],
        customer_id=user["customer_id"] or "", action="password.change", target=user["email"],
        details="User changed their own password from account page", ip_address=client_ip
    )
    return RedirectResponse("/account?pw_changed=1", status_code=303)


# ── Users ─────────────────────────────────────────────────────────────────────

@app.get("/users", response_class=HTMLResponse)
async def users_page(request: Request):
    try:
        user = get_current_user(request)
    except HTTPException:
        return RedirectResponse("/login")
    with get_conn() as conn:
        if user["role"] == "super_admin":
            rows = conn.execute("""
                SELECT u.*, c.name as customer_name
                FROM users u LEFT JOIN customers c ON u.customer_id = c.id
                WHERE u.active=1
                ORDER BY u.role='super_admin' DESC, u.created_at DESC
            """).fetchall()
            customers = conn.execute(
                "SELECT id, name FROM customers WHERE active=1 ORDER BY name"
            ).fetchall()
        else:
            rows = conn.execute("""
                SELECT u.*, c.name as customer_name
                FROM users u LEFT JOIN customers c ON u.customer_id = c.id
                WHERE u.active=1 AND u.customer_id=? AND u.role != 'super_admin'
                ORDER BY u.created_at DESC
            """, (user["customer_id"],)).fetchall()
            customers = []
    with get_conn() as conn:
        if user["role"] == "super_admin":
            all_users = conn.execute("""
                SELECT u.*, c.name as customer_name
                FROM users u LEFT JOIN customers c ON u.customer_id = c.id
                WHERE u.active=1 ORDER BY u.email
            """).fetchall()
        else:
            all_users = conn.execute("""
                SELECT u.*, c.name as customer_name
                FROM users u LEFT JOIN customers c ON u.customer_id = c.id
                WHERE u.active=1 AND u.customer_id=? AND u.role != 'super_admin'
                ORDER BY u.email
            """, (user["customer_id"],)).fetchall()
    return templates.TemplateResponse("users.html", {
        "request": request, "user": user,
        "current_user_id": user["sub"],
        "users": [dict(r) for r in rows],
        "all_users": [dict(r) for r in all_users],
        "customers": [dict(r) for r in customers],
    })


@app.post("/users/add")
async def add_user(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    role: str = Form(...),
    customer_id: str = Form(None),
):
    try:
        user = get_current_user(request)
    except HTTPException:
        return RedirectResponse("/login")
    client_ip = request.client.host if request.client else "unknown"
    if user["role"] == "customer_admin":
        customer_id = user["customer_id"]
        if role not in ("customer_admin", "user"):
            return RedirectResponse("/users?error=forbidden", status_code=303)
    addr = email.strip().lower()
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO users (id, email, password_hash, role, customer_id, created_at) VALUES (?,?,?,?,?,?)",
            (str(uuid.uuid4()), addr, hash_password(password),
             role, customer_id or None, datetime.now(timezone.utc).isoformat())
        )
    log_audit(
        actor_id=user["sub"], actor_name=user["email"], actor_role=user["role"],
        customer_id=customer_id or "", action="user.add", target=addr,
        details=f"Added user {addr} with role {role}", ip_address=client_ip
    )
    return RedirectResponse("/users", status_code=303)


@app.post("/users/edit")
async def edit_user(
    request: Request,
    user_id: str = Form(...),
    role: str = Form(...),
    customer_id: str = Form(None),
):
    try:
        user = get_current_user(request)
    except HTTPException:
        return RedirectResponse("/login")
    client_ip = request.client.host if request.client else "unknown"
    if user["role"] != "super_admin":
        return RedirectResponse("/users?error=forbidden", status_code=303)
    if role not in ("super_admin", "customer_admin", "user"):
        role = "user"
    with get_conn() as conn:
        target = conn.execute("SELECT email FROM users WHERE id=?", (user_id,)).fetchone()
        conn.execute(
            "UPDATE users SET role=?, customer_id=? WHERE id=?",
            (role, customer_id or None, user_id)
        )
    log_audit(
        actor_id=user["sub"], actor_name=user["email"], actor_role=user["role"],
        customer_id=customer_id or "", action="user.edit", target=target["email"] if target else user_id,
        details=f"Changed role to {role}", ip_address=client_ip
    )
    return RedirectResponse("/users?edited=1", status_code=303)


@app.post("/users/password")
async def change_password(
    request: Request,
    user_id: str = Form(...),
    new_password: str = Form(...),
):
    try:
        user = get_current_user(request)
    except HTTPException:
        return RedirectResponse("/login")
    client_ip = request.client.host if request.client else "unknown"
    with get_conn() as conn:
        target = conn.execute("SELECT * FROM users WHERE id=? AND active=1", (user_id,)).fetchone()
        if not target:
            return RedirectResponse("/users?error=notfound", status_code=303)
        if user["role"] != "super_admin":
            if target["customer_id"] != user["customer_id"]:
                return RedirectResponse("/users?error=forbidden", status_code=303)
            if target["role"] == "super_admin":
                return RedirectResponse("/users?error=forbidden", status_code=303)
        conn.execute(
            "UPDATE users SET password_hash=? WHERE id=?",
            (hash_password(new_password), user_id)
        )
    log_audit(
        actor_id=user["sub"], actor_name=user["email"], actor_role=user["role"],
        customer_id=target["customer_id"] or "", action="user.password.reset", target=target["email"],
        details=f"Reset password for {target['email']}", ip_address=client_ip
    )
    return RedirectResponse("/users?pw_changed=1", status_code=303)


@app.post("/users/remove")
async def remove_user(request: Request, user_id: str = Form(...)):
    try:
        user = get_current_user(request)
    except HTTPException:
        return RedirectResponse("/login")
    client_ip = request.client.host if request.client else "unknown"
    with get_conn() as conn:
        target = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not target:
            return RedirectResponse("/users", status_code=303)
        if target["id"] == user["sub"]:
            return RedirectResponse("/users?error=forbidden", status_code=303)
        if user["role"] == "customer_admin" and target["customer_id"] != user["customer_id"]:
            return RedirectResponse("/users?error=forbidden", status_code=303)
        if user["role"] != "super_admin" and target["role"] == "super_admin":
            return RedirectResponse("/users?error=forbidden", status_code=303)
        conn.execute("UPDATE users SET active=0 WHERE id=?", (user_id,))
    log_audit(
        actor_id=user["sub"], actor_name=user["email"], actor_role=user["role"],
        customer_id=target["customer_id"] or "", action="user.remove", target=target["email"],
        details=f"Removed user {target['email']}", ip_address=client_ip
    )
    return RedirectResponse("/users", status_code=303)


# ── Telemetry — receives usage heartbeats from running customer containers ─────

@app.post("/api/telemetry")
async def receive_telemetry(request: Request):
    from fastapi.responses import JSONResponse
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse({"error": "bad_request"}, status_code=400)
    customer_id    = payload.get("customer_id")
    current_agents = payload.get("current_agents")
    if not customer_id or current_agents is None:
        return JSONResponse({"error": "missing_fields"}, status_code=400)
    try:
        current_agents = int(current_agents)
    except (TypeError, ValueError):
        return JSONResponse({"error": "invalid_agent_count"}, status_code=400)
    with get_conn() as conn:
        row = conn.execute("SELECT id, max_seats FROM customers WHERE id=? AND active=1", (customer_id,)).fetchone()
        if not row:
            return JSONResponse({"error": "unknown_customer"}, status_code=404)
        conn.execute("UPDATE customers SET current_agents=? WHERE id=?", (current_agents, customer_id))
    return JSONResponse({"status": "ok", "current_agents": current_agents, "max_seats": row["max_seats"]})


# ── JSON API — used by Sentinel dashboard in cloud/proxy mode ─────────────────

@app.get("/api/users")
async def api_users_list(request: Request):
    from fastapi.responses import JSONResponse
    try:
        user = get_current_user(request)
    except HTTPException:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    with get_conn() as conn:
        if user["role"] == "super_admin":
            rows = conn.execute(
                "SELECT id, email, role, created_at FROM users WHERE active=1 ORDER BY role='super_admin' DESC, email"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, email, role, created_at FROM users WHERE active=1 AND customer_id=? AND role != 'super_admin' ORDER BY email",
                (user["customer_id"],),
            ).fetchall()
        me_row = conn.execute("SELECT email FROM users WHERE id=?", (user.get("sub"),)).fetchone()
    current_user_email = me_row["email"] if me_row else ""
    return JSONResponse({"users": [dict(r) for r in rows], "current_user": current_user_email})


@app.post("/api/users/add")
async def api_add_user(request: Request):
    from fastapi.responses import JSONResponse
    try:
        user = get_current_user(request)
    except HTTPException:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    if user["role"] not in ("super_admin", "customer_admin"):
        return JSONResponse({"error": "forbidden"}, status_code=403)
    body = await request.json()
    email    = str(body.get("email", "")).strip().lower()
    password = str(body.get("password", ""))
    role     = str(body.get("role", "customer_admin"))
    if user["role"] == "customer_admin" and role not in ("customer_admin", "user"):
        return JSONResponse({"error": "forbidden"}, status_code=403)
    if "@" not in email or len(password) < 8:
        return JSONResponse({"error": "invalid email or password too short"}, status_code=400)
    customer_id = user["customer_id"] if user["role"] != "super_admin" else body.get("customer_id")
    client_ip = request.client.host if request.client else "unknown"
    try:
        with get_conn() as conn:
            conn.execute(
                "INSERT INTO users (id, email, password_hash, role, customer_id, created_at) VALUES (?,?,?,?,?,?)",
                (str(uuid.uuid4()), email, hash_password(password), role,
                 customer_id or None, datetime.now(timezone.utc).isoformat()),
            )
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=400)
    log_audit(
        actor_id=user["sub"], actor_name=user["email"], actor_role=user["role"],
        customer_id=customer_id or "", action="user.add", target=email,
        details=f"Added user {email} with role {role} (API)", ip_address=client_ip
    )
    return JSONResponse({"ok": True})


@app.post("/api/users/password/{user_id}")
async def api_change_user_password(request: Request, user_id: str):
    from fastapi.responses import JSONResponse
    try:
        user = get_current_user(request)
    except HTTPException:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    if user["role"] not in ("super_admin", "customer_admin"):
        return JSONResponse({"error": "forbidden"}, status_code=403)
    body = await request.json()
    new_password = str(body.get("new_password", ""))
    if len(new_password) < 8:
        return JSONResponse({"error": "password too short"}, status_code=400)
    client_ip = request.client.host if request.client else "unknown"
    with get_conn() as conn:
        target = conn.execute("SELECT * FROM users WHERE id=? AND active=1", (user_id,)).fetchone()
        if not target:
            return JSONResponse({"error": "not found"}, status_code=404)
        if user["role"] == "customer_admin":
            if target["customer_id"] != user["customer_id"] or target["role"] == "super_admin":
                return JSONResponse({"error": "forbidden"}, status_code=403)
        conn.execute("UPDATE users SET password_hash=? WHERE id=?", (hash_password(new_password), user_id))
    log_audit(
        actor_id=user["sub"], actor_name=user["email"], actor_role=user["role"],
        customer_id=target["customer_id"] or "", action="user.password.reset", target=target["email"],
        details=f"Reset password for {target['email']} (API)", ip_address=client_ip
    )
    return JSONResponse({"ok": True})


@app.post("/api/users/remove/{user_id}")
async def api_remove_user(request: Request, user_id: str):
    from fastapi.responses import JSONResponse
    try:
        user = get_current_user(request)
    except HTTPException:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    if user["role"] not in ("super_admin", "customer_admin"):
        return JSONResponse({"error": "forbidden"}, status_code=403)
    client_ip = request.client.host if request.client else "unknown"
    with get_conn() as conn:
        target = conn.execute("SELECT * FROM users WHERE id=? AND active=1", (user_id,)).fetchone()
        if not target:
            return JSONResponse({"error": "not found"}, status_code=404)
        if target["id"] == user["sub"]:
            return JSONResponse({"error": "cannot remove yourself"}, status_code=400)
        if user["role"] == "customer_admin":
            if target["customer_id"] != user["customer_id"] or target["role"] == "super_admin":
                return JSONResponse({"error": "forbidden"}, status_code=403)
        conn.execute("UPDATE users SET active=0 WHERE id=?", (user_id,))
    log_audit(
        actor_id=user["sub"], actor_name=user["email"], actor_role=user["role"],
        customer_id=target["customer_id"] or "", action="user.remove", target=target["email"],
        details=f"Removed user {target['email']} (API)", ip_address=client_ip
    )
    return JSONResponse({"ok": True})


# ── Helpers ───────────────────────────────────────────────────────────────────

def _generate_temp_password(length: int = 14) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.isupper() for c in pw) and any(c.islower() for c in pw)
                and any(c.isdigit() for c in pw)):
            return pw


def _run_script(name: str, *args: str):
    script = f"/app/{name}"
    if os.path.exists(script):
        subprocess.Popen(["bash", script, *args])


def _write_license_file(customer_id: str, name: str, tier: str, expires: str, max_seats: int):
    licenses_dir = os.environ.get("LICENSES_DIR", "/licenses")
    customer_dir = os.path.join(licenses_dir, customer_id)
    os.makedirs(customer_dir, exist_ok=True)
    telemetry_url = f"http://sentinel-admin:8000/api/telemetry"
    payload = {
        "customer_id":        customer_id,
        "licensed_to":        name,
        "max_agents":         max_seats,
        "grace_pct":          10,
        "expires_at":         expires,
        "issued_at":          date.today().isoformat(),
        "issued_by":          "M.A.R.K. AI Systems",
        "plan":               tier,
        "telemetry_url":      telemetry_url,
        "telemetry_interval_h": 1,
    }
    path = os.path.join(customer_dir, "license.json")
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)
