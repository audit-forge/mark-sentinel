"""Exercise the real admin ASGI application with its installed dependencies."""

import importlib.util
import re
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from fastapi.templating import Jinja2Templates


REPO = Path(__file__).resolve().parents[1]
ADMIN = "https://admin.riskraven.ai"
DASHBOARD = "https://arckon.riskraven.ai"


@pytest.fixture
def admin(monkeypatch, tmp_path):
    monkeypatch.syspath_prepend(str(REPO / "admin"))
    monkeypatch.setenv("SECRET_KEY", "browser-security-test-key-not-for-production")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "admin.db"))
    modules = {}
    for name in ("db", "auth", "mailer", "monitor", "aws_marketplace", "browser_security", "app"):
        spec = importlib.util.spec_from_file_location(name, REPO / "admin" / f"{name}.py")
        module = importlib.util.module_from_spec(spec)
        monkeypatch.setitem(sys.modules, name, module)
        spec.loader.exec_module(module)
        modules[name] = module
    app = modules["app"]
    monkeypatch.setattr(app, "PUBLIC_ADMIN_URL", ADMIN)
    monkeypatch.setattr(app, "PUBLIC_DASHBOARD_URL", DASHBOARD)
    monkeypatch.setattr(app, "AUTH_COOKIE_DOMAIN", ".riskraven.ai")
    app.templates = Jinja2Templates(directory=str(REPO / "admin" / "templates"))
    modules["db"].init_db()
    password_hash = app.hash_password("correct-password")
    with app.get_conn() as conn:
        conn.execute("INSERT INTO customers (id, name, created_at, agent_token, port) VALUES (?,?,?,?,?)",
                     ("tenant", "Tenant", "2026-01-01", "machine-secret", 80))
        for user_id, role, customer in (("operator", "super_admin", None), ("customer", "customer_admin", "tenant")):
            conn.execute("INSERT INTO users (id, email, password_hash, role, customer_id, created_at) VALUES (?,?,?,?,?,?)",
                         (user_id, user_id + "@example.test", password_hash, role, customer, "2026-01-01"))
    # No lifespan context: avoid the production monitor thread and startup password requirement.
    client = TestClient(app.app, base_url=ADMIN, follow_redirects=False)
    yield app, client, modules["browser_security"]
    client.close()


@pytest.mark.parametrize("target", [
    "/dashboard?tab=users#active", DASHBOARD, DASHBOARD + "/devices?name=a%2Db",
    ADMIN + "/account", "https://ARCKON.riskraven.ai:443/", "/devices",
])
def test_safe_targets(admin, target):
    assert admin[2].safe_return_url(target, (ADMIN, DASHBOARD)) == target


@pytest.mark.parametrize("target", [
    "https://evil.test/", "//evil.test", "///evil.test", "https://arckon.riskraven.ai.evil.test/",
    "https://arckon.riskraven.ai@evil.test/", "https://evil.test@arckon.riskraven.ai/",
    "https://arckon.riskraven.ai:444/", "http://arckon.riskraven.ai/", "javascript:alert(1)",
    "/\\evil.test", "/%5cevil.test", "/%2fevil.test", "/%252fevil.test", "/a/..//evil.test",
    "/%2e%2e//evil.test", " /dashboard", "/dashboard\r\nLocation:https://evil.test",
    "/%0d%0aevil", "https://[broken/", "/%zz", "dashboard", "https://arckon.riskraven.ai:0/",
])
def test_unsafe_targets(admin, target):
    assert admin[2].safe_return_url(target, (ADMIN, DASHBOARD)) == ""


def login(client, *, user="customer", target="", headers=None):
    return client.post("/login", data={"email": user + "@example.test", "password": "correct-password", "next": target},
                       headers=headers if headers is not None else {"Origin": ADMIN})


def test_login_redirects_and_shared_cookie_contract(admin):
    _, client, _ = admin
    response = login(client, target=DASHBOARD + "/devices")
    assert response.status_code == 303
    assert response.headers["location"] == DASHBOARD + "/devices"
    cookie = response.headers["set-cookie"]
    for part in ("token=", "Domain=.riskraven.ai", "HttpOnly", "Max-Age=28800", "Path=/", "SameSite=lax", "Secure"):
        assert part in cookie
    verified = client.get("/auth/verify", headers={"X-Customer-ID": "tenant"})
    assert verified.status_code == 200
    assert verified.headers["X-Arckon-Customer-ID"] == "tenant"
    assert verified.headers["X-Arckon-User-Email"] == "customer@example.test"
    assert client.get("/auth/verify", headers={"X-Customer-ID": "other"}).status_code == 403
    assert client.get("/login", params={"next": DASHBOARD + "/devices"}).headers["location"] == DASHBOARD + "/devices"
    assert login(client, target="https://evil.test").headers["location"] == DASHBOARD
    assert login(client, user="operator", target=DASHBOARD + "/devices").headers["location"] == "/dashboard"
    assert client.get("/login", params={"next": DASHBOARD}).headers["location"] == "/dashboard"


@pytest.mark.parametrize("path,template", [
    ("/login", "login.html"),
    ("/forgot-password", "forgot_password.html"),
    ("/reset-password?token=invalid", "reset_password.html"),
])
def test_public_templates_render_with_real_starlette(admin, path, template):
    response = admin[1].get(path)
    assert response.status_code == 200
    assert response.template.name == template
    assert response.context["request"].url.path == path.split("?")[0]


@pytest.mark.parametrize("path,template", [
    ("/dashboard", "dashboard.html"), ("/communications", "communications.html"),
    ("/customers", "customers.html"), ("/account", "account.html"),
    ("/users", "users.html"), ("/audit-log", "audit_log.html"),
    ("/dns-inventory", "dns_inventory.html"),
])
def test_authenticated_templates_render_with_real_starlette(admin, path, template):
    _, client, _ = admin
    assert login(client, user="operator").status_code == 303
    response = client.get(path)
    assert response.status_code == 200
    assert response.template.name == template
    assert response.context["user"]["role"] == "super_admin"


def test_password_reset_form_templates_with_real_multipart(admin):
    app, client, _ = admin
    headers = {"Origin": ADMIN}
    response = client.post("/forgot-password", data={"email": "missing@example.test"}, headers=headers)
    assert response.status_code == 200
    assert response.context["sent"] is True
    data = {"token": "invalid", "new_password": "new-password", "confirm_password": "mismatch"}
    response = client.post("/reset-password", data=data, headers=headers)
    assert response.status_code == 200
    assert response.context["error"] == "Passwords do not match"
    data["confirm_password"] = data["new_password"]
    response = client.post("/reset-password", data=data, headers=headers)
    assert response.status_code == 200
    assert response.context["valid"] is False
    app._login_attempts["testclient"] = [app.time.time()] * app._LOGIN_MAX
    assert client.post("/forgot-password", data={"email": "missing@example.test"}, headers=headers).status_code == 429
    response = login(client)
    assert response.status_code == 429
    assert response.template.name == "login.html"


@pytest.mark.parametrize("kind", ["expired", "wrong-key", "unsigned", "wrong-algorithm"])
def test_real_pyjwt_rejects_invalid_session_tokens(admin, kind):
    import jwt

    _, client, _ = admin
    claims = {"sub": "customer", "role": "customer_admin", "customer_id": "tenant", "exp": 4102444800}
    key = "browser-security-test-key-not-for-production"
    algorithm = "HS256"
    if kind == "expired":
        claims["exp"] = 1
    elif kind == "wrong-key":
        key = "different-test-key-not-for-production"
    elif kind == "unsigned":
        key, algorithm = "", "none"
    else:
        algorithm = "HS384"
        key = key * 2
    client.cookies.set("token", jwt.encode(claims, key, algorithm=algorithm), domain=".riskraven.ai", path="/")
    assert client.get("/auth/verify").status_code == 401


def test_login_get_post_and_logout_sanitize_return_targets(admin):
    _, client, _ = admin
    response = client.get("/login", params={"next": "https://evil.test"})
    assert response.status_code == 200
    assert "https://evil.test" not in response.text
    response = client.post("/login", data={"email": "wrong", "password": "wrong", "next": "//evil.test"}, headers={"Origin": ADMIN})
    assert "//evil.test" not in response.text
    login(client)
    assert client.get("/logout", params={"next": "https://evil.test"}).headers["location"] == DASHBOARD
    response = client.get("/logout", params={"next": "/login"})
    assert response.headers["location"] == "/login"
    assert "Domain=.riskraven.ai" in response.headers["set-cookie"]
    assert "Max-Age=0" in response.headers["set-cookie"]


@pytest.mark.parametrize("headers,allowed", [
    ({}, False), ({"Origin": ADMIN}, True), ({"Origin": DASHBOARD}, True),
    ({"Referer": ADMIN + "/login?next=x"}, True), ({"Origin": "null", "Referer": ADMIN}, False),
    ({"Origin": ADMIN + ".evil.test"}, False), ({"Origin": "http://admin.riskraven.ai"}, False),
    ({"Origin": ADMIN + ":444"}, False), ({"Origin": ADMIN + "/"}, False),
    ({"Origin": ADMIN + "?"}, False), ({"Origin": ADMIN + "#"}, False),
    ({"Referer": "https://evil.test@admin.riskraven.ai/login"}, False),
    ({"Origin": ADMIN + " " + DASHBOARD}, False),
    ({"Origin": "https://admin.riskraven.ai:443"}, True),
])
def test_login_requires_exact_browser_provenance(admin, headers, allowed):
    response = login(admin[1], headers=headers)
    assert response.status_code == (303 if allowed else 403)


def test_cookie_mutations_fail_closed_even_with_bearer_or_forwarded_headers(admin):
    app, client, _ = admin
    login(client, user="operator")
    for path in ("/admin/dismiss-alert", "/api/users/add", "/api/reseller/impersonate", "/marketplace/aws/activate"):
        response = client.post(path, headers={"Authorization": "Bearer arbitrary", "X-Forwarded-Host": "admin.riskraven.ai", "Sec-Fetch-Site": "same-origin"})
        assert response.status_code == 403
        assert response.json()["error"] == "untrusted_browser_origin"
    assert client.post("/admin/dismiss-alert", data={"alert_id": 999}, headers={"Origin": ADMIN}).status_code == 303
    assert client.post("/admin/dismiss-alert", data={"alert_id": 999}, headers={"Referer": DASHBOARD + "/"}).status_code == 303
    assert client.post("/admin/dismiss-alert", data={"alert_id": 999}, headers=[("Origin", ADMIN), ("Origin", "https://evil.test")]).status_code == 403
    client.cookies.clear()
    client.cookies.set("token", "")
    assert client.post("/admin/dismiss-alert", data={"alert_id": 999}).status_code == 403


def test_machine_routes_keep_their_own_authentication(admin):
    _, client, _ = admin
    assert client.get("/auth/agent-lookup", headers={"Authorization": "Bearer machine-secret"}).status_code == 200
    assert client.get("/auth/agent-lookup", headers={"Authorization": "Bearer wrong"}).status_code == 401
    payload = {"customer_id": "tenant", "current_agents": 3}
    assert client.post("/api/telemetry", json=payload).status_code == 401
    assert client.post("/api/telemetry", json=payload, headers={"X-Sentinel-Agent-Token": "wrong"}).status_code == 401
    response = client.post("/api/telemetry", json=payload, headers={"X-Sentinel-Agent-Token": "machine-secret"})
    assert response.status_code == 200
    assert response.json()["current_agents"] == 3
    assert client.get("/api/maintenance/active").status_code == 200
    assert client.post("/api/users/add", json={}, headers={"Authorization": "Bearer machine-secret"}).status_code == 401


def test_unconfigured_origins_do_not_trust_request_host(admin, monkeypatch):
    app, client, _ = admin
    monkeypatch.setattr(app, "PUBLIC_ADMIN_URL", "")
    monkeypatch.setattr(app, "PUBLIC_DASHBOARD_URL", "")
    assert login(client).status_code == 403
    assert admin[2].safe_return_url(ADMIN + "/dashboard", ("", "")) == ""
    assert admin[2].safe_return_url("/dashboard", ("", "")) == "/dashboard"


def test_nginx_authenticated_locations_clear_all_legacy_aliases():
    source = (REPO / "deploy/gcp/nginx/arckon.conf").read_text()
    for location in ("/api/", "/"):
        block = source.split(f"location {location} {{", 1)[1].split("}", 1)[0]
        for claim in ("User-Email", "User-Role", "Customer-ID", "Client-Org-ID", "Is-Reseller", "Is-MSP", "Impersonated-By"):
            assert re.search(r"proxy_set_header X-Arckon-" + claim + r'\s+"";', block)
        assert "auth_request /_auth;" in block
        assert "proxy_pass http://$sentinel_upstream;" in block
    assert "return 302 https://admin.riskraven.ai/login?next=https://arckon.riskraven.ai$request_uri;" in source
