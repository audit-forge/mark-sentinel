"""Rendered dashboard session guard behavior and real HTTP session expiry."""

import html
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

import server
from .test_server_security_boundaries import dashboard  # noqa: F401


@pytest.mark.parametrize("cloud", [False, True], ids=["local", "cloud"])
def test_rendered_dashboard_session_guard(monkeypatch, cloud):
    monkeypatch.setattr(server, "_trusted_proxy_token", lambda: "proxy-secret" if cloud else "")
    page = server._build_fleet_html([], store=None)
    login = re.search(r'data-session-login-url="([^"]+)"', page)
    assert login is not None
    login_url = html.unescape(login.group(1))
    assert login_url == ("https://admin.riskraven.ai/login?next=" if cloud else "/login?next=")
    # Only execute the auth prefix, not the rest of the large dashboard UI.
    prefix = page.split("// \u2500\u2500 Theme", 1)
    assert len(prefix) == 2, "dashboard theme boundary missing"
    script = prefix[0].rsplit("<script>", 1)
    assert len(script) == 2, "dashboard guard script missing"
    node = shutil.which("node")
    assert node, "Node.js is required to verify the dashboard session guard"
    result = subprocess.run(
        [node, str(Path(__file__).with_name("dashboard_session_guard_harness.js"))],
        input=json.dumps({"script": script[1], "loginUrl": login_url}),
        text=True, capture_output=True, timeout=30,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "Dashboard session guard behavior checks passed" in result.stdout


def test_auth_me_without_session_is_401_no_store(dashboard):
    response = dashboard.request("GET", "/api/auth/me", role=None)
    assert response.status == 401
    assert response.headers["Cache-Control"] == "no-store"
    assert "Location" not in response.headers
    assert "Set-Cookie" not in response.headers


def test_auth_me_rejects_expired_legacy_cookie_in_database(dashboard):
    token = dashboard.cookies["admin"].split("=", 1)[1]
    before = dashboard.request("GET", "/api/auth/me")
    assert before.status == 200
    assert before.headers["Cache-Control"] == "no-store"
    with dashboard.registry._conn() as conn:
        updated = conn.execute(
            "UPDATE dashboard_sessions SET expires_at=0 WHERE token=?", (token,)
        )
        assert updated.rowcount == 1
    assert dashboard.registry.get_session(token) is None
    # Keep sending the same cookie: expiry must be enforced by the database.
    response = dashboard.request("GET", "/api/auth/me")
    assert response.status == 401
    assert response.headers["Cache-Control"] == "no-store"
    assert "Location" not in response.headers
    assert "Set-Cookie" not in response.headers
