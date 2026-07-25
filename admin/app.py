import os
import uuid
import json
import secrets
import sqlite3
import string
import subprocess
import time
from collections import defaultdict
from datetime import datetime, date, timezone, timedelta
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from db import init_db, get_conn
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

def _load_admin_password() -> str:
    """ADMIN_PASSWORD env, or ADMIN_PASSWORD_FILE (mounted secret — keeps the
    credential out of container env vars, same pattern as SECRET_KEY_FILE)."""
    pw = os.environ.get("ADMIN_PASSWORD", "")
    if not pw:
        path = os.environ.get("ADMIN_PASSWORD_FILE", "")
        if path:
            try:
                import pathlib
                p = pathlib.Path(path)
                pw = p.read_text().strip() if p.is_file() else ""
            except Exception:
                pw = ""
    return pw or "changeme"

ADMIN_EMAIL    = os.environ.get("ADMIN_EMAIL", "admin@sentinel.local")
MAX_CUSTOMERS  = int(os.environ.get("MAX_CUSTOMERS", "0"))  # 0 = unlimited
ADMIN_PASSWORD = _load_admin_password()
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


def _get_shadow_ai_devices(customer_id: str) -> list[dict]:
    """Query the Sentinel app database for detected shadow AI devices."""
    try:
        cmd = [
            "sudo", "docker", "exec", f"sentinel-{customer_id}", "python3", "-c",
            f"""
import sqlite3
import json
try:
    db = sqlite3.connect('/app/data/customers/{customer_id}/agents.db')
    db.row_factory = sqlite3.Row
    rows = db.execute('SELECT reporter_hostname, host, service, models_json, source, last_seen FROM shadow_devices WHERE dismissed=0 ORDER BY last_seen DESC').fetchall()
    devices = [dict(r) for r in rows]
    print(json.dumps(devices))
except Exception as e:
    print(json.dumps([]))
"""
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            import json
            return json.loads(result.stdout.strip() or "[]")
        else:
            return []
    except Exception as e:
        print(f"Error in _get_shadow_ai_devices: {e}")
        return []


def _get_client_orgs(customer_id: str) -> list[dict]:
    """Read the client_orgs table from a customer's own bind-mounted customers.db.

    Each customer container owns its own isolated customers.db (bind-mounted from
    /opt/sentinel-data/{customer_id}); the admin container mounts the whole parent
    dir at /data, so it can read it read-only without going through that customer's API.
    """
    db_file = f"/data/{customer_id}/customers.db"
    if not os.path.isfile(db_file):
        return []
    try:
        conn = sqlite3.connect(db_file)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT id, name FROM client_orgs WHERE active=1 ORDER BY name"
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []


def _get_all_client_orgs() -> list[dict]:
    """Flat list of every client org across every customer, for the super_admin Users page."""
    results = []
    try:
        for entry in os.listdir("/data"):
            for org in _get_client_orgs(entry):
                org["customer_id"] = entry
                results.append(org)
    except Exception:
        pass
    return results


def _sentinel_url(customer_id: str | None) -> str:
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
    if not row or not verify_password(password, row["password_hash"]):
        _record_failed_login(client_ip)
        return templates.TemplateResponse("login.html", {
            "request": request, "error": "Invalid credentials", "next": next
        })
    token = create_token(row["id"], row["role"], row["customer_id"], row["email"],
                          row["client_org_id"] if "client_org_id" in row.keys() else None)
    if not next:
        destination = "/dashboard" if row["role"] == "super_admin" else _sentinel_url(row["customer_id"])
    else:
        destination = next
    resp = RedirectResponse(destination, status_code=303)
    resp.set_cookie("token", token, httponly=True, max_age=28800, samesite="lax")
    return resp


@app.get("/logout")
async def logout(request: Request, next: str = None):
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
        is_reseller = False
        is_msp      = False
        if user.get("customer_id"):
            cust = conn.execute(
                "SELECT is_reseller, is_msp FROM customers WHERE id=?", (user["customer_id"],)
            ).fetchone()
            is_reseller = bool(cust and cust["is_reseller"])
            is_msp      = bool(cust and cust["is_msp"])
    # An impersonation token's "sub" is a synthetic marker, not a real users.id row --
    # fall back to the JWT's own email claim rather than blanking it out.
    email = row["email"] if row else (user.get("email") or "")
    return Response(status_code=200, headers={
        "X-Sentinel-User-Email":    email or "",
        "X-Sentinel-User-Role":     user.get("role") or "",
        "X-Sentinel-Customer-ID":   user.get("customer_id") or "",
        "X-Sentinel-Client-Org-ID": user.get("client_org_id") or "",
        "X-Sentinel-Is-Reseller":   "1" if is_reseller else "",
        "X-Sentinel-Is-MSP":        "1" if is_msp else "",
        "X-Sentinel-Impersonated-By": user.get("impersonated_by") or "",
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
        "shadow_ai_devices": _get_shadow_ai_devices(user["customer_id"]) if user.get("customer_id") else []})


# ── Deploy ────────────────────────────────────────────────────────────────────

@app.post("/admin/dismiss-alert")
async def dismiss_alert(request: Request, alert_id: int = Form(...)):
    try:
        require_super_admin(request)
    except HTTPException:
        return RedirectResponse("/login")
    with get_conn() as conn:
        conn.execute("DELETE FROM license_alerts WHERE id=?", (alert_id,))
    return RedirectResponse("/dashboard", status_code=303)


@app.post("/admin/refresh-seats")
async def refresh_seats(request: Request):
    try:
        require_super_admin(request)
    except HTTPException:
        return RedirectResponse("/login")
    import threading
    from monitor import _check_all_customers
    threading.Thread(target=_check_all_customers, daemon=True).start()
    return RedirectResponse("/dashboard?seats_refreshed=1", status_code=303)


@app.post("/admin/deploy")
async def deploy(request: Request):
    try:
        require_super_admin(request)
    except HTTPException:
        return RedirectResponse("/login")
    import urllib.request as urlreq
    try:
        req = urlreq.Request("http://sentinel-deployer:9000/deploy", method="POST", data=b"")
        with urlreq.urlopen(req, timeout=5) as r:
            code = r.status
        result = "started" if code == 202 else "busy" if code == 409 else "failed"
    except Exception:
        result = "failed"
    return RedirectResponse(f"/dashboard?deploy={result}", status_code=303)


# ── Test email ────────────────────────────────────────────────────────────────

@app.post("/admin/test-email")
async def test_email(request: Request):
    try:
        require_super_admin(request)
    except HTTPException:
        return RedirectResponse("/login")
    from mailer import send_alert
    ok = send_alert(
        subject="[Arckon] Test alert — email is working",
        body_text="This is a test alert from the RiskRaven Arckon admin panel.\n\nIf you received this, email alerts are configured correctly.",
        body_html="""
<div style="font-family:monospace;background:#0a0a0a;color:#e0e0e0;padding:24px;max-width:520px">
  <div style="color:#00ff88;font-weight:bold;letter-spacing:3px;margin-bottom:16px">RISKRAVEN ARCKON</div>
  <div style="font-size:15px;color:#fff;margin-bottom:12px">Test Alert</div>
  <div style="font-size:13px;color:#aaa">Email alerts are configured correctly.</div>
</div>
""",
    )
    result = "ok" if ok else "fail"
    return RedirectResponse(f"/dashboard?email_test={result}", status_code=303)


# ── Installer scripts (served publicly — no secrets embedded) ─────────────────

@app.get("/install/{filename}")
async def serve_installer(filename: str):
    from fastapi.responses import FileResponse
    allowed = {"install.sh", "install.ps1", "install.bat"}
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
    parent_filter = request.query_params.get("parent", "").strip()
    with get_conn() as conn:
        if status == "inactive":
            rows = conn.execute("SELECT * FROM customers WHERE active=0 ORDER BY created_at DESC").fetchall()
        elif status == "all":
            rows = conn.execute("SELECT * FROM customers ORDER BY created_at DESC").fetchall()
        else:
            rows = conn.execute("SELECT * FROM customers WHERE active=1 ORDER BY created_at DESC").fetchall()
        all_names = {r["id"]: r["name"] for r in conn.execute("SELECT id, name FROM customers").fetchall()}
        resellers = conn.execute(
            "SELECT id, name FROM customers WHERE is_reseller=1 AND active=1 ORDER BY name"
        ).fetchall()
    customers = []
    for r in rows:
        c = dict(r)
        try:
            c["days_remaining"] = (date.fromisoformat(c["license_expires_at"]) - date.today()).days
        except (TypeError, ValueError):
            c["days_remaining"] = None
        c["parent_name"] = all_names.get(c.get("parent_customer_id")) if c.get("parent_customer_id") else None
        customers.append(c)
    if parent_filter:
        customers = [c for c in customers if c.get("parent_customer_id") == parent_filter]
    return templates.TemplateResponse("customers.html", {
        "request": request, "user": user,
        "customers": customers, "ip": PUBLIC_IP, "status": status,
        "resellers": [dict(r) for r in resellers],
        "parent_filter": parent_filter,
        "parent_filter_name": all_names.get(parent_filter, parent_filter) if parent_filter else None,
    })


@app.post("/customers/add")
async def add_customer(
    request: Request,
    customer_id: str = Form(...),
    customer_name: str = Form(...),
    customer_email: str = Form(""),
    tier: str = Form("standard"),
    max_seats: int = Form(5),
    parent_customer_id: str = Form(""),
):
    try:
        require_super_admin(request)
    except HTTPException:
        return RedirectResponse("/login")
    cid = customer_id.lower().strip().replace(" ", "-")
    if tier not in ("standard", "plus"):
        tier = "standard"
    expires = (date.today() + timedelta(days=365)).isoformat()
    agent_token = secrets.token_urlsafe(32)
    parent_customer_id = parent_customer_id.strip() or None
    with get_conn() as conn:
        if MAX_CUSTOMERS > 0:
            active_count = conn.execute(
                "SELECT COUNT(*) FROM customers WHERE active=1"
            ).fetchone()[0]
            if active_count >= MAX_CUSTOMERS:
                return RedirectResponse("/customers?error=cap", status_code=303)
        exists = conn.execute("SELECT id FROM customers WHERE id=?", (cid,)).fetchone()
        if exists:
            return RedirectResponse("/customers?error=exists", status_code=303)
        if parent_customer_id:
            # Only an account explicitly flagged as a reseller MSP can be a parent --
            # keeps the hierarchy intentional rather than letting any customer nest another.
            parent = conn.execute(
                "SELECT id FROM customers WHERE id=? AND is_reseller=1", (parent_customer_id,)
            ).fetchone()
            if not parent:
                return RedirectResponse("/customers?error=badparent", status_code=303)
        max_port = conn.execute("SELECT MAX(port) FROM customers").fetchone()[0]
        port = (max_port or 7000) + 1
        conn.execute(
            "INSERT INTO customers (id, name, created_at, active, tier, license_expires_at, max_seats, port, agent_token, parent_customer_id) "
            "VALUES (?,?,?,1,?,?,?,?,?,?)",
            (cid, customer_name.strip(), datetime.now(timezone.utc).isoformat(), tier, expires, max_seats, port,
             agent_token, parent_customer_id)
        )
        if customer_email.strip():
            email = customer_email.strip().lower()
            existing = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
            if existing:
                conn.execute("UPDATE users SET active=1, customer_id=?, role='customer_admin' WHERE email=?",
                             (cid, email))
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
    _write_license_file(cid, customer_name.strip(), tier, expires, max_seats)
    _run_script("provision_customer.sh", cid, PUBLIC_IP, tier, expires, str(max_seats), customer_name.strip(), str(port), agent_token)
    return RedirectResponse("/customers", status_code=303)


@app.post("/customers/set-reseller")
async def set_reseller(request: Request, customer_id: str = Form(...), is_reseller: str = Form("0")):
    try:
        require_super_admin(request)
    except HTTPException:
        return RedirectResponse("/login")
    flag = 1 if is_reseller in ("1", "true", "on") else 0
    with get_conn() as conn:
        if not flag:
            # Refuse to unflag a reseller that still has children -- would silently
            # orphan their parent link rather than something the owner clearly intended.
            children = conn.execute(
                "SELECT COUNT(*) FROM customers WHERE parent_customer_id=?", (customer_id,)
            ).fetchone()[0]
            if children:
                return RedirectResponse("/customers?error=hasresold", status_code=303)
        conn.execute("UPDATE customers SET is_reseller=? WHERE id=?", (flag, customer_id))
    return RedirectResponse("/customers", status_code=303)


@app.post("/customers/set-msp")
async def set_msp(request: Request, customer_id: str = Form(...), is_msp: str = Form("0")):
    try:
        require_super_admin(request)
    except HTTPException:
        return RedirectResponse("/login")
    flag = 1 if is_msp in ("1", "true", "on") else 0
    with get_conn() as conn:
        conn.execute("UPDATE customers SET is_msp=? WHERE id=?", (flag, customer_id))
    return RedirectResponse("/customers?msp_updated=1", status_code=303)


@app.post("/customers/renew")
async def renew_customer(request: Request, customer_id: str = Form(...)):
    try:
        require_super_admin(request)
    except HTTPException:
        return RedirectResponse("/login")
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM customers WHERE id=?", (customer_id,)).fetchone()
        if not row:
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
    return RedirectResponse("/customers", status_code=303)


@app.post("/customers/seats")
async def update_seats(request: Request, customer_id: str = Form(...), max_seats: int = Form(...)):
    try:
        require_super_admin(request)
    except HTTPException:
        return RedirectResponse("/login")
    if max_seats < 1:
        return RedirectResponse("/customers?error=invalid_seats", status_code=303)
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM customers WHERE id=?", (customer_id,)).fetchone()
        if not row:
            return RedirectResponse("/customers?error=notfound", status_code=303)
        conn.execute("UPDATE customers SET max_seats=? WHERE id=?", (max_seats, customer_id))
        name    = row["name"]
        tier    = row["tier"]
        expires = row["license_expires_at"]
    _write_license_file(customer_id, name, tier, expires, max_seats)
    _run_script("restart_customer.sh", customer_id)
    return RedirectResponse("/customers?seats_updated=" + customer_id, status_code=303)


@app.post("/customers/upgrade")
async def upgrade_customer(request: Request, customer_id: str = Form(...), tier: str = Form(...)):
    try:
        require_super_admin(request)
    except HTTPException:
        return RedirectResponse("/login")
    if tier not in ("standard", "plus"):
        return RedirectResponse("/customers?error=invalid_tier", status_code=303)
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM customers WHERE id=?", (customer_id,)).fetchone()
        if not row:
            return RedirectResponse("/customers?error=notfound", status_code=303)
        conn.execute("UPDATE customers SET tier=? WHERE id=?", (tier, customer_id))
        name    = row["name"]
        expires = row["license_expires_at"]
        max_seats = row["max_seats"]
    _write_license_file(customer_id, name, tier, expires, max_seats)
    _run_script("restart_customer.sh", customer_id)
    return RedirectResponse("/customers?plan_updated=" + customer_id, status_code=303)


@app.post("/customers/remove")
async def remove_customer(request: Request, customer_id: str = Form(...)):
    try:
        require_super_admin(request)
    except HTTPException:
        return RedirectResponse("/login")
    with get_conn() as conn:
        conn.execute("UPDATE customers SET active=0 WHERE id=?", (customer_id,))
        conn.execute("UPDATE users SET active=0 WHERE customer_id=?", (customer_id,))
    _run_script("remove_customer.sh", customer_id)
    return RedirectResponse("/customers", status_code=303)


@app.post("/customers/restore")
async def restore_customer(request: Request, customer_id: str = Form(...)):
    try:
        require_super_admin(request)
    except HTTPException:
        return RedirectResponse("/login")
    with get_conn() as conn:
        conn.execute("UPDATE customers SET active=1 WHERE id=?", (customer_id,))
    _run_script("provision_customer.sh", customer_id, PUBLIC_IP)
    return RedirectResponse("/customers", status_code=303)


@app.post("/customers/delete")
async def delete_customer(request: Request, customer_id: str = Form(...)):
    try:
        require_super_admin(request)
    except HTTPException:
        return RedirectResponse("/login")
    with get_conn() as conn:
        conn.execute("DELETE FROM customers WHERE id=? AND active=0", (customer_id,))
        conn.execute("DELETE FROM users WHERE customer_id=?", (customer_id,))
    _run_script("remove_customer.sh", customer_id)
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
            "SELECT id, name, port FROM customers WHERE id=? AND active=1", (customer_id,)
        ).fetchone()
        if not row:
            return JSONResponse({"error": "customer not found"}, status_code=404)
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
    except Exception:
        pass  # push is best-effort; in-band delivery still works

    return JSONResponse({
        "token": new_token,
        "customer_id": customer_id,
        "name": row["name"],
        "rollover_hours": rollover_hours,
        "expires_at": expires_at,
        "push_queued": push_count,
    })


# ── Agent update push ─────────────────────────────────────────────────────────
#
# Each customer's own Sentinel server already has a working, tested
# POST /api/fleet/update/all that queues the (also already-working) agent
# 'update_self' command for every device it knows about (server.py's
# _api_fleet_update_all + agent.py's self_update()). What's missing is a
# super-admin action that triggers that across every customer at once —
# this endpoint is just the fan-out.
#
# NOTE on auth: unlike rotate_customer_token's push above (which calls this
# same style of endpoint with no auth headers at all — that call is
# silently swallowed by _require_dashboard_auth() on the receiving end,
# saved only by the documented in-band-delivery fallback), this sends the
# customer server's own trusted-proxy headers so the call actually
# authenticates instead of quietly 401'ing.

async def _push_customer_update_all(customer_id: str, port: int, actor_email: str) -> dict:
    import httpx
    url = f"http://127.0.0.1:{port}/api/fleet/update/all"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(url, headers={
                "X-Sentinel-User-Email": actor_email or "super_admin@system",
                "X-Sentinel-User-Role": "admin",
                "X-Sentinel-Customer-ID": customer_id,
            })
        if r.status_code == 200:
            data = r.json()
            return {"customer_id": customer_id, "ok": True, "device_count": data.get("count", 0)}
        return {"customer_id": customer_id, "ok": False, "error": f"HTTP {r.status_code}"}
    except Exception as e:
        return {"customer_id": customer_id, "ok": False, "error": str(e)}


@app.post("/api/agents/update-all")
async def push_agent_updates_all_customers(request: Request):
    """Super-admin action: queue the update_self command for every device,
    across every active customer. Fans out to each customer's own already-
    working /api/fleet/update/all."""
    try:
        user = require_super_admin(request)
    except HTTPException:
        return JSONResponse({"error": "unauthorized"}, status_code=403)

    with get_conn() as conn:
        customers = conn.execute(
            "SELECT id, name, port FROM customers WHERE active=1"
        ).fetchall()

    results = []
    for cust in customers:
        port = cust["port"] or 7001
        results.append(await _push_customer_update_all(cust["id"], port, user.get("email", "")))

    total_devices = sum(r.get("device_count", 0) for r in results if r["ok"])
    return JSONResponse({
        "customers_attempted": len(results),
        "customers_succeeded": sum(1 for r in results if r["ok"]),
        "total_devices_queued": total_devices,
        "results": [{**r, "name": next((c["name"] for c in customers if c["id"] == r["customer_id"]), r["customer_id"])} for r in results],
    })


# ── Maintenance notices ────────────────────────────────────────────────────────
#
# Super-admin schedules a maintenance window; every customer dashboard polls
# /api/maintenance/active (proxied through their own server.py, since
# customer browsers can't reach this admin service directly — see the
# _api_maintenance_notice relay added in server.py) and shows a banner if a
# notice is currently active or upcoming.

@app.post("/api/maintenance/schedule")
async def schedule_maintenance(request: Request):
    try:
        user = require_super_admin(request)
    except HTTPException:
        return JSONResponse({"error": "unauthorized"}, status_code=403)
    try:
        body = await request.json()
        message = str(body.get("message", "")).strip()
        scheduled_at = str(body.get("scheduled_at", "")).strip()  # ISO 8601
        expires_at = str(body.get("expires_at", "")).strip()      # ISO 8601
    except Exception:
        return JSONResponse({"error": "invalid_request"}, status_code=400)
    if not message or not scheduled_at or not expires_at:
        return JSONResponse({"error": "message, scheduled_at, and expires_at are required"}, status_code=400)
    try:
        datetime.fromisoformat(scheduled_at)
        datetime.fromisoformat(expires_at)
    except ValueError:
        return JSONResponse({"error": "scheduled_at/expires_at must be ISO 8601 timestamps"}, status_code=400)

    notice_id = str(uuid.uuid4())
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO maintenance_notices (id, message, scheduled_at, expires_at, created_by, created_at, active) "
            "VALUES (?,?,?,?,?,?,1)",
            (notice_id, message, scheduled_at, expires_at, user.get("email", ""), datetime.now(timezone.utc).isoformat()),
        )
    return JSONResponse({"ok": True, "id": notice_id})


@app.get("/api/maintenance/list")
async def list_maintenance_notices(request: Request):
    try:
        require_super_admin(request)
    except HTTPException:
        return JSONResponse({"error": "unauthorized"}, status_code=403)
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, message, scheduled_at, expires_at, created_by, created_at, active "
            "FROM maintenance_notices ORDER BY scheduled_at DESC"
        ).fetchall()
    return JSONResponse({"notices": [dict(r) for r in rows]})


@app.post("/api/maintenance/cancel/{notice_id}")
async def cancel_maintenance_notice(notice_id: str, request: Request):
    try:
        require_super_admin(request)
    except HTTPException:
        return JSONResponse({"error": "unauthorized"}, status_code=403)
    with get_conn() as conn:
        cur = conn.execute("UPDATE maintenance_notices SET active=0 WHERE id=?", (notice_id,))
    return JSONResponse({"ok": cur.rowcount > 0})


@app.get("/api/maintenance/active")
async def get_active_maintenance_notice():
    """No auth — every customer server.py instance relays this to its own
    browser clients. Returns the single most-relevant active notice: an
    in-progress one if any, otherwise the soonest upcoming one. None if
    nothing is currently active or upcoming within the next 14 days (so a
    long-forgotten notice a super-admin never cancelled doesn't linger
    forever)."""
    now = datetime.now(timezone.utc).isoformat()
    horizon = (datetime.now(timezone.utc) + timedelta(days=14)).isoformat()
    with get_conn() as conn:
        row = conn.execute(
            "SELECT id, message, scheduled_at, expires_at FROM maintenance_notices "
            "WHERE active=1 AND expires_at > ? AND scheduled_at < ? "
            "ORDER BY scheduled_at ASC LIMIT 1",
            (now, horizon),
        ).fetchone()
    if not row:
        return JSONResponse({"notice": None})
    in_progress = row["scheduled_at"] <= now <= row["expires_at"]
    return JSONResponse({"notice": {**dict(row), "in_progress": in_progress}})


# ── Forgot / Reset password ───────────────────────────────────────────────────

@app.get("/forgot-password", response_class=HTMLResponse)
async def forgot_password_page(request: Request):
    return templates.TemplateResponse("forgot_password.html", {"request": request, "sent": False})


@app.post("/forgot-password", response_class=HTMLResponse)
async def forgot_password_submit(request: Request, email: str = Form(...)):
    with get_conn() as conn:
        row = conn.execute(
            "SELECT id FROM users WHERE email=? AND active=1", (email.strip().lower(),)
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
            send_password_reset_email(email.strip().lower(), reset_url)
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
        conn.execute("UPDATE users SET password_hash=? WHERE id=?",
                     (hash_password(new_password), row["user_id"]))
        conn.execute("UPDATE password_resets SET used=1 WHERE token=?", (token,))
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
    if user["role"] == "super_admin":
        client_orgs = _get_all_client_orgs()
        cust_names = {c["id"]: c["name"] for c in [dict(r) for r in customers]}
        for org in client_orgs:
            org["customer_name"] = cust_names.get(org["customer_id"], org["customer_id"])
    else:
        client_orgs = _get_client_orgs(user["customer_id"])

    org_names = {o["id"]: o["name"] for o in client_orgs}
    users_out = []
    for r in rows:
        d = dict(r)
        d["client_org_name"] = org_names.get(d.get("client_org_id")) if d.get("client_org_id") else None
        users_out.append(d)
    all_users_out = []
    for r in all_users:
        d = dict(r)
        d["client_org_name"] = org_names.get(d.get("client_org_id")) if d.get("client_org_id") else None
        all_users_out.append(d)

    return templates.TemplateResponse("users.html", {
        "request": request, "user": user,
        "current_user_id": user["sub"],
        "users": users_out,
        "all_users": all_users_out,
        "customers": [dict(r) for r in customers],
        "client_orgs": client_orgs,
    })


@app.post("/users/add")
async def add_user(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    role: str = Form(...),
    customer_id: str = Form(None),
    client_org_id: str = Form(None),
):
    try:
        user = get_current_user(request)
    except HTTPException:
        return RedirectResponse("/login")
    if user["role"] == "customer_admin":
        customer_id = user["customer_id"]
        if role not in ("customer_admin", "user", "client_viewer"):
            return RedirectResponse("/users?error=forbidden", status_code=303)
    elif user["role"] != "super_admin":
        return RedirectResponse("/users?error=forbidden", status_code=303)

    if role == "client_viewer":
        valid_orgs = {o["id"] for o in _get_client_orgs(customer_id)} if customer_id else set()
        if not client_org_id or client_org_id not in valid_orgs:
            return RedirectResponse("/users?error=noclientorg", status_code=303)
    else:
        client_org_id = None

    with get_conn() as conn:
        existing = conn.execute(
            "SELECT id FROM users WHERE email=?", (email.strip().lower(),)
        ).fetchone()
        if existing:
            return RedirectResponse("/users?error=exists", status_code=303)
        conn.execute(
            "INSERT INTO users (id, email, password_hash, role, customer_id, client_org_id, created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), email.strip().lower(), hash_password(password),
             role, customer_id or None, client_org_id, datetime.now(timezone.utc).isoformat())
        )
    return RedirectResponse("/users", status_code=303)


@app.post("/users/edit")
async def edit_user(
    request: Request,
    user_id: str = Form(...),
    role: str = Form(...),
    customer_id: str = Form(None),
    client_org_id: str = Form(None),
):
    try:
        user = get_current_user(request)
    except HTTPException:
        return RedirectResponse("/login")

    with get_conn() as conn:
        target = conn.execute("SELECT * FROM users WHERE id=? AND active=1", (user_id,)).fetchone()
    if not target:
        return RedirectResponse("/users?error=notfound", status_code=303)

    if user["role"] == "customer_admin":
        # Scoped to their own customer, can't touch a super_admin account,
        # can't grant super_admin, and can't reassign to a different customer —
        # same containment rules already applied to /users/remove and /users/password.
        if target["customer_id"] != user["customer_id"] or target["role"] == "super_admin":
            return RedirectResponse("/users?error=forbidden", status_code=303)
        customer_id = user["customer_id"]
        if role not in ("customer_admin", "user", "client_viewer"):
            return RedirectResponse("/users?error=forbidden", status_code=303)
    elif user["role"] != "super_admin":
        return RedirectResponse("/users?error=forbidden", status_code=303)
    elif role not in ("super_admin", "customer_admin", "user", "client_viewer"):
        role = "user"

    if role == "client_viewer":
        valid_orgs = {o["id"] for o in _get_client_orgs(customer_id)} if customer_id else set()
        if not client_org_id or client_org_id not in valid_orgs:
            return RedirectResponse("/users?error=noclientorg", status_code=303)
    else:
        client_org_id = None
    with get_conn() as conn:
        conn.execute(
            "UPDATE users SET role=?, customer_id=?, client_org_id=? WHERE id=?",
            (role, customer_id or None, client_org_id, user_id)
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
    return RedirectResponse("/users?pw_changed=1", status_code=303)


@app.post("/users/remove")
async def remove_user(request: Request, user_id: str = Form(...)):
    try:
        user = get_current_user(request)
    except HTTPException:
        return RedirectResponse("/login")
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
    return RedirectResponse("/users", status_code=303)


# ── JSON API for the customer-dashboard-embedded Users tab ────────────────────
# server.py's own "Users" nav item proxies here (via _proxy_to_admin) when
# SENTINEL_TRUSTED_PROXY is set, i.e. on every real production deployment.
# Mirrors the same permission/scoping rules as the HTML routes above.

@app.get("/api/users")
async def api_users_list(request: Request):
    try:
        user = get_current_user(request)
    except HTTPException:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    with get_conn() as conn:
        if user["role"] == "super_admin":
            rows = conn.execute(
                "SELECT * FROM users WHERE active=1 ORDER BY created_at DESC"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM users WHERE active=1 AND customer_id=? AND role != 'super_admin' "
                "ORDER BY created_at DESC",
                (user["customer_id"],)
            ).fetchall()
    users_out = [
        {
            "id": r["id"], "email": r["email"], "role": r["role"],
            "client_org_id": r["client_org_id"] if "client_org_id" in r.keys() else None,
            "active": bool(r["active"]), "created_at": r["created_at"],
        }
        for r in rows
    ]
    return JSONResponse({"users": users_out, "current_user": user.get("email", "")})


@app.post("/api/users/add")
async def api_users_add(request: Request):
    try:
        user = get_current_user(request)
    except HTTPException:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    try:
        body = await request.json()
    except Exception:
        body = {}
    email = str(body.get("email", "")).strip().lower()
    password = str(body.get("password", ""))
    role = str(body.get("role", "user"))
    if role == "admin":
        # The customer-dashboard-embedded Users tab (server.py) predates the
        # customer_admin/user/client_viewer naming and still sends "admin".
        role = "customer_admin"
    client_org_id = body.get("client_org_id") or None

    if not email or "@" not in email or len(password) < 8:
        return JSONResponse({"error": "invalid email or password"}, status_code=400)

    if user["role"] == "customer_admin":
        customer_id = user["customer_id"]
        if role not in ("customer_admin", "user", "client_viewer"):
            return JSONResponse({"error": "forbidden"}, status_code=403)
    elif user["role"] != "super_admin":
        return JSONResponse({"error": "forbidden"}, status_code=403)
    else:
        customer_id = body.get("customer_id") or None

    if role == "client_viewer":
        valid_orgs = {o["id"] for o in _get_client_orgs(customer_id)} if customer_id else set()
        if not client_org_id or client_org_id not in valid_orgs:
            return JSONResponse({"error": "select a valid client org for the client viewer role"}, status_code=400)
    else:
        client_org_id = None

    with get_conn() as conn:
        existing = conn.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
        if existing:
            return JSONResponse({"error": "a user with that email already exists"}, status_code=409)
        new_id = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO users (id, email, password_hash, role, customer_id, client_org_id, created_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (new_id, email, hash_password(password), role, customer_id, client_org_id,
             datetime.now(timezone.utc).isoformat())
        )
    return JSONResponse({"ok": True, "user": {"id": new_id, "email": email, "role": role}})


@app.post("/api/users/remove/{user_id}")
async def api_users_remove(request: Request, user_id: str):
    try:
        user = get_current_user(request)
    except HTTPException:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    if user["role"] not in ("customer_admin", "super_admin"):
        return JSONResponse({"error": "forbidden"}, status_code=403)
    with get_conn() as conn:
        target = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not target:
            return JSONResponse({"ok": True})
        if target["id"] == user["sub"]:
            return JSONResponse({"error": "cannot remove your own account"}, status_code=403)
        if user["role"] == "customer_admin" and target["customer_id"] != user["customer_id"]:
            return JSONResponse({"error": "forbidden"}, status_code=403)
        if user["role"] != "super_admin" and target["role"] == "super_admin":
            return JSONResponse({"error": "forbidden"}, status_code=403)
        conn.execute("UPDATE users SET active=0 WHERE id=?", (user_id,))
    return JSONResponse({"ok": True})


@app.post("/api/users/password/{user_id}")
async def api_users_password(request: Request, user_id: str):
    try:
        user = get_current_user(request)
    except HTTPException:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    if user["role"] not in ("customer_admin", "super_admin"):
        return JSONResponse({"error": "forbidden"}, status_code=403)
    try:
        body = await request.json()
    except Exception:
        body = {}
    new_password = str(body.get("new_password", ""))
    if len(new_password) < 8:
        return JSONResponse({"error": "password must be at least 8 characters"}, status_code=400)
    with get_conn() as conn:
        target = conn.execute("SELECT * FROM users WHERE id=? AND active=1", (user_id,)).fetchone()
        if not target:
            return JSONResponse({"error": "not found"}, status_code=404)
        if user["role"] != "super_admin" and target["customer_id"] != user["customer_id"]:
            return JSONResponse({"error": "forbidden"}, status_code=403)
        conn.execute(
            "UPDATE users SET password_hash=? WHERE id=?",
            (hash_password(new_password), user_id)
        )
    return JSONResponse({"ok": True})


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


# ── Reseller view ─────────────────────────────────────────────────────────────
# server.py's own dashboard proxies here (via _proxy_to_admin) so a reseller
# MSP's customer_admin sees their resold customers natively in their own
# dashboard, without needing separate admin-panel credentials.

@app.get("/api/reseller/customers")
async def api_reseller_customers(request: Request):
    try:
        user = get_current_user(request)
    except HTTPException:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    if user["role"] not in ("customer_admin", "super_admin") or not user.get("customer_id"):
        return JSONResponse({"error": "forbidden"}, status_code=403)
    with get_conn() as conn:
        me = conn.execute("SELECT is_reseller FROM customers WHERE id=?", (user["customer_id"],)).fetchone()
        if not me or not me["is_reseller"]:
            return JSONResponse({"error": "this account is not flagged as a reseller MSP"}, status_code=403)
        rows = conn.execute(
            "SELECT * FROM customers WHERE parent_customer_id=? ORDER BY created_at DESC",
            (user["customer_id"],)
        ).fetchall()
    customers_out = []
    for r in rows:
        d = dict(r)
        customers_out.append({
            "id": d["id"], "name": d["name"], "active": bool(d["active"]),
            "tier": d["tier"], "max_seats": d["max_seats"], "current_agents": d["current_agents"],
            "license_expires_at": d["license_expires_at"],
            "dashboard_url": f"http://{PUBLIC_IP}:{d['port']}" if d.get("port") and d["active"] else None,
        })
    return JSONResponse({"customers": customers_out})


@app.post("/api/reseller/impersonate")
async def reseller_impersonate(request: Request):
    """Mint a short-lived, single-purpose session for a reseller MSP's
    customer_admin to enter one of their resold customers' dashboards without
    re-authenticating. Every start/end is written to audit_log."""
    try:
        user = get_current_user(request)
    except HTTPException:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    if user["role"] != "customer_admin" or not user.get("customer_id"):
        return JSONResponse({"error": "forbidden"}, status_code=403)
    try:
        body = await request.json()
    except Exception:
        body = {}
    target_id = str(body.get("customer_id", "")).strip()
    if not target_id:
        return JSONResponse({"error": "customer_id is required"}, status_code=400)
    client_ip = request.client.host if request.client else ""
    with get_conn() as conn:
        me = conn.execute("SELECT is_reseller, port FROM customers WHERE id=?", (user["customer_id"],)).fetchone()
        if not me or not me["is_reseller"]:
            return JSONResponse({"error": "this account is not flagged as a reseller MSP"}, status_code=403)
        target = conn.execute(
            "SELECT * FROM customers WHERE id=? AND parent_customer_id=? AND active=1",
            (target_id, user["customer_id"])
        ).fetchone()
        if not target or not target["port"]:
            return JSONResponse({"error": "customer not found or not resold by this account"}, status_code=404)
        actor_row = conn.execute("SELECT email FROM users WHERE id=?", (user["sub"],)).fetchone()
        actor_email = actor_row["email"] if actor_row else (user.get("email") or "")
        conn.execute(
            "INSERT INTO audit_log (occurred_at, actor_name, actor_role, customer_id, action, target, details, ip_address) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (datetime.now(timezone.utc).isoformat(), actor_email, "customer_admin", user["customer_id"],
             "impersonate_start", target_id, f"Started support session in {target['name']}", client_ip)
        )
    impersonation_token = create_token(
        user_id=f"impersonate:{user['sub']}:{target_id}", role="customer_admin", customer_id=target_id,
        email=actor_email, impersonated_by=actor_email, expire_minutes=30,
    )
    return JSONResponse({
        "ok": True,
        "token": impersonation_token,
        "dashboard_url": f"http://{PUBLIC_IP}:{target['port']}",
        "return_url": f"http://{PUBLIC_IP}:{me['port']}" if me["port"] else "",
        "customer_name": target["name"],
    })


@app.post("/api/reseller/impersonate/end")
async def reseller_impersonate_end(request: Request):
    """Log the end of a support session. Called with the impersonation
    token still active, before server.py swaps the browser's cookie back."""
    try:
        user = get_current_user(request)
    except HTTPException:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    impersonated_by = user.get("impersonated_by")
    if impersonated_by:
        client_ip = request.client.host if request.client else ""
        with get_conn() as conn:
            target = conn.execute("SELECT name FROM customers WHERE id=?", (user.get("customer_id"),)).fetchone()
            conn.execute(
                "INSERT INTO audit_log (occurred_at, actor_name, actor_role, customer_id, action, target, details, ip_address) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (datetime.now(timezone.utc).isoformat(), impersonated_by, "customer_admin", user.get("customer_id"),
                 "impersonate_end", user.get("customer_id"),
                 f"Ended support session in {target['name'] if target else user.get('customer_id')}", client_ip)
            )
    return JSONResponse({"ok": True})


# ── Audit Log ─────────────────────────────────────────────────────────────────

@app.get("/audit-log", response_class=HTMLResponse)
async def audit_log_page(request: Request):
    try:
        user = require_super_admin(request)
    except HTTPException:
        return RedirectResponse("/login")
    customer_id = request.query_params.get("customer_id", "")
    action      = request.query_params.get("action", "")
    with get_conn() as conn:
        customers = [dict(r) for r in conn.execute(
            "SELECT id, name FROM customers WHERE active=1 ORDER BY name"
        ).fetchall()]
        actions = [r[0] for r in conn.execute(
            "SELECT DISTINCT action FROM audit_log WHERE action IS NOT NULL ORDER BY action"
        ).fetchall()]
        q = "SELECT * FROM audit_log"
        params, clauses = [], []
        if customer_id:
            clauses.append("customer_id=?"); params.append(customer_id)
        if action:
            clauses.append("action=?"); params.append(action)
        if clauses:
            q += " WHERE " + " AND ".join(clauses)
        q += " ORDER BY occurred_at DESC LIMIT 500"
        raw = conn.execute(q, params).fetchall()
    entries = []
    for r in raw:
        e = dict(r)
        try:
            from datetime import datetime as _dt
            ts = _dt.fromisoformat(e["occurred_at"].replace("Z", "+00:00"))
            e["occurred_at_display"] = ts.strftime("%Y-%m-%d %H:%M UTC")
        except Exception:
            e["occurred_at_display"] = e.get("occurred_at", "")
        entries.append(e)
    return templates.TemplateResponse("audit_log.html", {
        "request": request, "user": user,
        "entries": entries, "customers": customers,
        "actions": actions, "customer_id": customer_id, "action": action,
    })


@app.get("/audit-log/csv")
async def audit_log_csv(request: Request):
    try:
        require_super_admin(request)
    except HTTPException:
        return RedirectResponse("/login")
    import csv
    import io as _io
    customer_id = request.query_params.get("customer_id", "")
    action      = request.query_params.get("action", "")
    with get_conn() as conn:
        q = "SELECT occurred_at,actor_name,actor_role,customer_id,action,target,details,ip_address FROM audit_log"
        params, clauses = [], []
        if customer_id:
            clauses.append("customer_id=?"); params.append(customer_id)
        if action:
            clauses.append("action=?"); params.append(action)
        if clauses:
            q += " WHERE " + " AND ".join(clauses)
        q += " ORDER BY occurred_at DESC"
        rows = conn.execute(q, params).fetchall()
    buf = _io.StringIO()
    w = csv.writer(buf)
    w.writerow(["Time", "Actor", "Role", "Customer", "Action", "Target", "Details", "IP Address"])
    for r in rows:
        w.writerow(list(r))
    from fastapi.responses import Response as _Resp
    return _Resp(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit_log.csv"},
    )


# ── DNS Inventory ─────────────────────────────────────────────────────────────

@app.get("/dns-inventory", response_class=HTMLResponse)
async def dns_inventory_page(request: Request):
    try:
        user = get_current_user(request)
    except HTTPException:
        return RedirectResponse("/login")
    return templates.TemplateResponse("dns_inventory.html", {"request": request, "user": user})


@app.post("/dns-inventory/analyze")
async def dns_inventory_analyze(request: Request):
    try:
        get_current_user(request)
    except HTTPException:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    import sys
    import os as _os
    _base = _os.path.dirname(_os.path.abspath(__file__))
    _connector_path = _os.path.join(_base, "dns_connector.py")
    if _os.path.isfile(_connector_path) and _base not in sys.path:
        sys.path.insert(0, _base)
    try:
        from dns_connector import connect as dns_connect
    except ImportError as e:
        return JSONResponse({"error": f"DNS connector not available: {e}"}, status_code=500)
    form = await request.form(max_part_size=200*1024*1024)
    log_content = ""
    upload = form.get("log_file")
    if upload and hasattr(upload, "read"):
        raw = await upload.read()
        log_content = raw.decode("utf-8", errors="replace")
        del raw
    else:
        log_content = form.get("log_text", "")
    if not log_content or not log_content.strip():
        return JSONResponse({"error": "No log content provided."}, status_code=400)
    approved_raw = form.get("approved_domains", "")
    approved = [d.strip() for d in approved_raw.replace(",", "\n").splitlines() if d.strip()] or None
    try:
        result = dns_connect(log_content=log_content, approved_domains=approved)
        return JSONResponse(result)
    except Exception as exc:
        import traceback as _tb
        return JSONResponse({"error": f"Analysis failed: {exc}", "detail": _tb.format_exc()}, status_code=500)


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
    telemetry_url = "http://sentinel-admin:8000/api/telemetry"
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
