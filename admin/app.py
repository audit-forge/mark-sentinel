import os
import uuid
import subprocess
from datetime import datetime, timezone
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from db import init_db, get_conn
from auth import hash_password, verify_password, create_token, get_current_user, require_super_admin

app = FastAPI(docs_url=None, redoc_url=None)
templates = Jinja2Templates(directory="templates")

ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@sentinel.local")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "changeme")
PUBLIC_IP = os.environ.get("PUBLIC_IP", "35.255.19.236")


@app.on_event("startup")
def startup():
    init_db()
    _ensure_super_admin()


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
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/login")
async def login(request: Request, email: str = Form(...), password: str = Form(...)):
    with get_conn() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE email=? AND active=1", (email,)
        ).fetchone()
    if not row or not verify_password(password, row["password_hash"]):
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid credentials"})
    token = create_token(row["id"], row["role"], row["customer_id"])
    resp = RedirectResponse("/dashboard", status_code=303)
    resp.set_cookie("token", token, httponly=True, max_age=28800, samesite="lax")
    return resp


@app.get("/logout")
async def logout():
    resp = RedirectResponse("/login", status_code=303)
    resp.delete_cookie("token")
    return resp


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
    return templates.TemplateResponse("dashboard.html", {
        "request": request, "user": user,
        "customer_count": customer_count, "user_count": user_count,
        "ip": PUBLIC_IP,
    })


# ── Customers ─────────────────────────────────────────────────────────────────

@app.get("/customers", response_class=HTMLResponse)
async def customers_page(request: Request):
    try:
        user = require_super_admin(request)
    except HTTPException:
        return RedirectResponse("/login")
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM customers ORDER BY created_at DESC"
        ).fetchall()
    return templates.TemplateResponse("customers.html", {
        "request": request, "user": user,
        "customers": [dict(r) for r in rows], "ip": PUBLIC_IP,
    })


@app.post("/customers/add")
async def add_customer(request: Request, customer_id: str = Form(...), customer_name: str = Form(...)):
    try:
        require_super_admin(request)
    except HTTPException:
        return RedirectResponse("/login")
    cid = customer_id.lower().strip().replace(" ", "-")
    with get_conn() as conn:
        exists = conn.execute("SELECT id FROM customers WHERE id=?", (cid,)).fetchone()
        if exists:
            return RedirectResponse("/customers?error=exists", status_code=303)
        conn.execute(
            "INSERT INTO customers (id, name, created_at, active) VALUES (?,?,?,1)",
            (cid, customer_name.strip(), datetime.now(timezone.utc).isoformat())
        )
    _run_script("provision_customer.sh", cid, PUBLIC_IP)
    return RedirectResponse("/customers", status_code=303)


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
    return templates.TemplateResponse("users.html", {
        "request": request, "user": user,
        "users": [dict(r) for r in rows],
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

def _run_script(name: str, *args: str):
    script = f"/app/{name}"
    if os.path.exists(script):
        subprocess.Popen(["bash", script, *args])
