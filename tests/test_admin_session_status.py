"""Real admin ASGI session checks and the shared browser session guard."""

import importlib.util
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from fastapi.templating import Jinja2Templates


REPO = Path(__file__).resolve().parents[1]
ADMIN = "https://admin.riskraven.ai"


@pytest.fixture
def admin(monkeypatch, tmp_path):
    monkeypatch.syspath_prepend(str(REPO / "admin"))
    monkeypatch.setenv("SECRET_KEY", "admin-session-test-key-not-for-production")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "admin.db"))
    modules = {}
    for name in ("db", "auth", "mailer", "monitor", "aws_marketplace", "browser_security", "app"):
        spec = importlib.util.spec_from_file_location(name, REPO / "admin" / f"{name}.py")
        module = importlib.util.module_from_spec(spec)
        monkeypatch.setitem(sys.modules, name, module)
        spec.loader.exec_module(module)
        modules[name] = module
    app = modules["app"]
    app.templates = Jinja2Templates(directory=str(REPO / "admin" / "templates"))
    modules["db"].init_db()
    with app.get_conn() as conn:
        conn.execute("INSERT INTO customers (id, name, created_at, agent_token, port) VALUES (?,?,?,?,?)",
                     ("tenant", "Tenant", "2026-01-01", "machine-secret", 80))
        for user_id, role, customer in (("operator", "super_admin", None),
                                        ("customer", "customer_admin", "tenant")):
            conn.execute("INSERT INTO users (id, email, password_hash, role, customer_id, created_at) VALUES (?,?,?,?,?,?)",
                         (user_id, user_id + "@example.test", "unused", role, customer, "2026-01-01"))
    # Avoid production startup/monitor; no password hashing or login is needed.
    with_client = TestClient(app.app, base_url=ADMIN, follow_redirects=False)
    yield app, with_client
    with_client.close()


def set_session(app, client, user="operator", **kwargs):
    role, customer = ("super_admin", None) if user == "operator" else ("customer_admin", "tenant")
    token = app.create_token(user, role, customer, user + "@example.test", **kwargs)
    client.cookies.set("token", token, domain="admin.riskraven.ai", path="/")
    return token


@pytest.mark.parametrize("user", ["operator", "customer"])
def test_authenticated_session_is_private_and_not_refreshed(admin, user):
    app, client = admin
    token = set_session(app, client, user)
    for _ in range(2):
        response = client.get("/api/auth/session")
        assert response.status_code == 200
        assert response.json() == {"authenticated": True}
        assert response.headers["cache-control"] == "no-store"
        assert "set-cookie" not in response.headers
        assert token not in response.text
        assert client.cookies.get("token") == token
    if user == "operator":
        assert client.get("/auth/verify").status_code == 401


@pytest.mark.parametrize("kind", ["missing", "malformed", "expired", "deactivated", "deleted"])
def test_rejected_sessions(admin, kind):
    app, client = admin
    if kind == "malformed":
        client.cookies.set("token", "not-a-jwt", domain="admin.riskraven.ai", path="/")
    elif kind != "missing":
        set_session(app, client, expire_minutes=-1 if kind == "expired" else None)
        with app.get_conn() as conn:
            if kind == "deactivated":
                conn.execute("UPDATE users SET active=0 WHERE id='operator'")
            elif kind == "deleted":
                conn.execute("DELETE FROM users WHERE id='operator'")
    response = client.get("/api/auth/session")
    assert response.status_code == 401
    assert response.json() == {"authenticated": False}
    assert response.headers["cache-control"] == "no-store"
    assert "set-cookie" not in response.headers
    assert "location" not in response.headers


def test_guard_render_order_syntax_and_behavior(admin):
    app, client = admin
    set_session(app, client)
    response = client.get("/dashboard")
    assert response.status_code == 200
    assert response.text.index('id="admin-session-guard"') < response.text.index('<main>')
    script = re.search(r'<script id="admin-session-guard">(.*?)</script>', response.text, re.S).group(1)
    node = shutil.which("node")
    assert node, "Node.js is required to verify the browser guard"
    result = subprocess.run([node, "--check"], input=script, text=True, capture_output=True)
    assert result.returncode == 0, result.stderr
    result = subprocess.run([node, str(REPO / "tests/admin_session_guard_harness.js")],
                            input=script, text=True, capture_output=True)
    assert result.returncode == 0, result.stdout + result.stderr
