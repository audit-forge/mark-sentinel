import os
import uuid
import json
import secrets
import string
import subprocess
from datetime import datetime, date, timezone, timedelta
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from db import init_db, get_conn
from auth import hash_password, verify_password, create_token, get_current_user, require_super_admin
from monitor import start_monitor

app = FastAPI(docs_url=None, redoc_url=None)
templates = Jinja2Templates(directory="templates")

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
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE email=? AND active=1", (email,)
        ).fetchone()
    if not row or not verify_password(password, row["password_hash"]):
        return templates.TemplateResponse("login.html", {
            "request": request, "error": "Invalid credentials", "next": next
        })
    token = create_token(row["id"], row["role"], row["customer_id"])
    destination = next if next else "/dashboard"
    resp = RedirectResponse(destination, status_code=303)
    resp.set_cookie("token", token, httponly=True, max_age=28800, samesite="lax")
    return resp


@app.get("/logout")
async def logout():
    resp = RedirectResponse("/login", status_code=303)
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
    return Response(status_code=200)


# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    try:
        user = get_current_user(request)
    except HTTPException:
        return RedirectResponse("/login")
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
    return RedirectResponse(f"/dashboard?email_test={result}", status_code=303)


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
        require_super_admin(request)
    except HTTPException:
        return RedirectResponse("/login")
    cid = customer_id.lower().strip().replace(" ", "-")
    if tier not in ("standard", "plus"):
        tier = "standard"
    expires = (date.today() + timedelta(days=365)).isoformat()
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
        max_port = conn.execute("SELECT MAX(port) FROM customers").fetchone()[0]
        port = (max_port or 7000) + 1
        conn.execute(
            "INSERT INTO customers (id, name, created_at, active, tier, license_expires_at, max_seats, port) VALUES (?,?,?,1,?,?,?,?)",
            (cid, customer_name.strip(), datetime.now(timezone.utc).isoformat(), tier, expires, max_seats, port)
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
    _run_script("provision_customer.sh", cid, PUBLIC_IP, tier, expires, str(max_seats), customer_name.strip(), str(port))
    return RedirectResponse("/customers", status_code=303)


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
    return RedirectResponse("/customers?seats_updated=" + customer_id, status_code=303)


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
                WHERE u.active=1 AND u.role != 'super_admin'
                ORDER BY u.created_at DESC
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
        all_users = conn.execute("""
            SELECT u.*, c.name as customer_name
            FROM users u LEFT JOIN customers c ON u.customer_id = c.id
            WHERE u.active=1 ORDER BY u.email
        """).fetchall()
    return templates.TemplateResponse("users.html", {
        "request": request, "user": user,
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
    if user["role"] == "customer_admin":
        customer_id = user["customer_id"]
        if role not in ("customer_admin", "user"):
            return RedirectResponse("/users?error=forbidden", status_code=303)
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO users (id, email, password_hash, role, customer_id, created_at) VALUES (?,?,?,?,?,?)",
            (str(uuid.uuid4()), email.strip().lower(), hash_password(password),
             role, customer_id or None, datetime.now(timezone.utc).isoformat())
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
    if user["role"] != "super_admin":
        return RedirectResponse("/users?error=forbidden", status_code=303)
    if role not in ("super_admin", "customer_admin", "user"):
        role = "user"
    with get_conn() as conn:
        conn.execute(
            "UPDATE users SET role=?, customer_id=? WHERE id=?",
            (role, customer_id or None, user_id)
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
        if user["role"] == "customer_admin" and target["customer_id"] != user["customer_id"]:
            return RedirectResponse("/users?error=forbidden", status_code=303)
        conn.execute("UPDATE users SET active=0 WHERE id=?", (user_id,))
    return RedirectResponse("/users", status_code=303)


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
    payload = {
        "customer_id":   customer_id,
        "licensed_to":   name,
        "max_agents":    max_seats,
        "grace_pct":     10,
        "expires_at":    expires,
        "issued_at":     date.today().isoformat(),
        "issued_by":     "M.A.R.K. AI Systems",
        "plan":          tier,
    }
    path = os.path.join(customer_dir, "license.json")
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)
