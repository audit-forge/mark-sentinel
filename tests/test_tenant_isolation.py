"""Regression tests for MSP tenant isolation (client_viewer scoping).

Two halves, matching the two halves of the bug:

  * the authenticated identity's client_org_id has to survive the whole trip
    from /auth/verify -> nginx -> the customer container, and
  * once it arrives (or fails to), server.py has to scope every query to it
    and *deny* rather than widen when it cannot be resolved.

The nginx half is asserted against the checked-in vhost and against the
config the provisioner actually renders (via real bash), rather than by
booting nginx -- the live config names running containers as upstreams, so
`nginx -t` here would only prove that those names don't resolve.
"""

import importlib
import io
import json
import re
import shutil
import subprocess
import sys
import types
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
ADMIN_APP = REPO / "admin" / "app.py"
LIVE_CONF = REPO / "deploy" / "gcp" / "nginx" / "mfdynamicsllc.conf"
PROVISION = REPO / "deploy" / "gcp" / "provision_customer.sh"


# -- nginx: identity propagation ----------------------------------------------

def _auth_verify_headers() -> set[str]:
    """The X-Sentinel-* headers /auth/verify hands back to nginx.

    Read out of admin/app.py rather than hard-coded, so that adding a header
    there without teaching nginx to forward it fails this suite."""
    src = ADMIN_APP.read_text()
    m = re.search(r"async def auth_verify\(.*?(?=^@app\.)", src, re.S | re.M)
    assert m, "could not locate /auth/verify in admin/app.py"
    names = set(re.findall(r'"(X-Sentinel-[\w-]+)"\s*:', m.group(0)))
    assert names, "no X-Sentinel-* headers found in /auth/verify"
    return names


def _location_blocks(conf: str) -> dict[str, str]:
    """Split an nginx server block into {location spec: body}."""
    blocks = {}
    for m in re.finditer(r"location\s+([^\n{]+?)\s*\{", conf):
        depth, i = 1, m.end()
        while depth and i < len(conf):
            if conf[i] == "{":
                depth += 1
            elif conf[i] == "}":
                depth -= 1
            i += 1
        blocks[m.group(1).strip()] = conf[m.end():i - 1]
    return blocks


def _upstream_var(header: str) -> str:
    return "upstream_http_" + header.lower().replace("-", "_")


def _assert_identity_propagated(conf: str, label: str):
    """The auth_request-protected location must capture *and* re-set every
    header /auth/verify emits. Capturing without re-setting is the exact
    shape of the original bug: nginx quietly passes the browser's own value
    through instead of the authenticated one."""
    blocks = _location_blocks(conf)
    assert "/" in blocks, label + ": no `location /` block"
    body = blocks["/"]
    assert "auth_request /_auth;" in body, label + ": `location /` is not auth-gated"
    for header in sorted(_auth_verify_headers()):
        # Customer identity is deliberately pinned to the vhost rather than
        # trusting a value returned for a potentially broader admin session.
        if header == "X-Sentinel-Customer-ID":
            continue
        setter = re.search(
            r"proxy_set_header\s+" + re.escape(header) + r"\s+\$(\w+)\s*;", body, re.I
        )
        assert setter, label + ": " + header + " is never forwarded to the customer container"
        var = setter.group(1)
        assert re.search(
            r"auth_request_set\s+\$" + re.escape(var) + r"\s+\$" + _upstream_var(header) + r"\s*;",
            body, re.I,
        ), label + ": $" + var + " is forwarded but never captured from " + header


def _assert_unauthenticated_locations_strip_identity(conf: str, label: str):
    """Locations that bypass auth_request must blank every X-Sentinel-*
    header. The upstream requires a proxy capability in addition to authenticated
    identity, so unauthenticated routes must not receive either value."""
    headers = _auth_verify_headers()
    for spec, body in _location_blocks(conf).items():
        if "proxy_pass" not in body or "auth_request" in body or "internal;" in body:
            continue
        for header in sorted(headers):
            assert re.search(
                r"proxy_set_header\s+" + re.escape(header) + r'\s+""\s*;', body, re.I
            ), label + ": `location " + spec + "` bypasses auth but does not blank " + header


def test_live_vhost_propagates_client_org_id():
    _assert_identity_propagated(LIVE_CONF.read_text(), "mfdynamicsllc.conf")


def test_live_vhost_strips_spoofed_identity_on_unauthenticated_routes():
    _assert_unauthenticated_locations_strip_identity(
        LIVE_CONF.read_text(), "mfdynamicsllc.conf")


def _render_provisioned_conf(tmp_path: Path) -> str:
    """Render provision_customer.sh's vhost heredoc with real bash, so the
    test exercises the same expansion and escaping the provisioner does."""
    src = PROVISION.read_text()
    m = re.search(r"^cat > .*? <<EOF\n(.*?)\n^EOF$", src, re.S | re.M)
    assert m, "could not locate the vhost heredoc in provision_customer.sh"
    script = tmp_path / "render.sh"
    script.write_text(
        "set -euo pipefail\n"
        'CUSTOMER_ID="acme"\n'
        'CONTAINER_NAME="sentinel-acme"\n'
        'PORT="7002"\n'
        'PUBLIC_IP="203.0.113.9"\n'
        'PUBLIC_ADMIN_URL="https://admin.example.test"\n'
        'PUBLIC_DASHBOARD_URL="https://dashboard.example.test"\n'
        'PROXY_TOKEN="test-proxy-token"\n'
        "cat <<EOF\n" + m.group(1) + "\nEOF\n"
    )
    return subprocess.run(["bash", str(script)], capture_output=True,
                          text=True, check=True).stdout


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_provisioner_renders_vhost_that_propagates_client_org_id(tmp_path):
    conf = _render_provisioned_conf(tmp_path)
    assert "sentinel-acme:7331" in conf, "heredoc did not expand as expected"
    _assert_identity_propagated(conf, "provision_customer.sh")


@pytest.mark.skipif(shutil.which("bash") is None, reason="bash not available")
def test_provisioner_renders_vhost_that_strips_spoofed_identity(tmp_path):
    _assert_unauthenticated_locations_strip_identity(
        _render_provisioned_conf(tmp_path), "provision_customer.sh")


# -- server: authorization boundary -------------------------------------------

@pytest.fixture(scope="module")
def srv():
    # server.py pip-installs (and re-execs!) on import if these are missing.
    # Prefer the real packages; stub only what isn't installed, so importing
    # the module under test can never shell out.
    for name in ("fpdf", "yaml"):
        try:
            importlib.import_module(name)
        except ImportError:
            sys.modules[name] = types.ModuleType(name)
    sys.path.insert(0, str(REPO))
    return importlib.import_module("server")


ORGS = {
    "org-a":   {"id": "org-a",   "customer_id": "acme",   "name": "Org A", "active": 1},
    "org-b":   {"id": "org-b",   "customer_id": "acme",   "name": "Org B", "active": 1},
    "org-off": {"id": "org-off", "customer_id": "acme",   "name": "Gone",  "active": 0},
    "org-x":   {"id": "org-x",   "customer_id": "globex", "name": "Other", "active": 1},
}


class _FakeRegistry:
    def get_client_org(self, org_id):
        return ORGS.get(org_id)


def _report(profile=""):
    return {"scan_date": "2026-07-25", "profile": profile,
            "summary": {"fail": 0, "warn": 0, "pass": 1}}


@pytest.fixture
def store(tmp_path):
    from storage import AgentStore
    st = AgentStore(tmp_path / "agents.db")
    report = _report()
    st.upsert_report("dev-a1", "a1.acme", report, client_org_id="org-a")
    st.upsert_report("dev-a2", "a2.acme", report, client_org_id="org-a")
    st.upsert_report("dev-b1", "b1.acme", report, client_org_id="org-b")
    st.upsert_report("dev-none", "unassigned.acme", report)
    # A second, profile-tagged scan for a subset of the fleet, so
    # ?profile=fedramp exercises list_devices_by_profile() and so a test that
    # asserts on it can tell org filtering apart from profile filtering.
    # dev-a2 is deliberately left with only the untagged scan.
    fedramp = _report("fedramp")
    st.upsert_report("dev-a1", "a1.acme", fedramp, client_org_id="org-a")
    st.upsert_report("dev-b1", "b1.acme", fedramp, client_org_id="org-b")
    st.upsert_report("dev-none", "unassigned.acme", fedramp)
    return st


@pytest.fixture
def wired(srv, store, monkeypatch):
    monkeypatch.setenv("SENTINEL_TRUSTED_PROXY_TOKEN", "test-proxy-token")
    monkeypatch.setattr(srv, "_registry", _FakeRegistry())
    monkeypatch.setattr(srv, "_get_store", lambda customer_id="default": store)
    return srv


def _viewer(org_id=None, email="viewer@acme.test", customer="acme"):
    headers = {
        "X-Sentinel-Proxy-Token": "test-proxy-token",
        "X-Sentinel-User-Email": email,
        "X-Sentinel-User-Role": "client_viewer",
        "X-Sentinel-Customer-ID": customer,
    }
    if org_id is not None:
        headers["X-Sentinel-Client-Org-ID"] = org_id
    return headers


def _admin(org_id=None):
    headers = {
        "X-Sentinel-Proxy-Token": "test-proxy-token",
        "X-Sentinel-User-Email": "msp@acme.test",
        "X-Sentinel-User-Role": "admin",
        "X-Sentinel-Customer-ID": "acme",
        "X-Sentinel-Is-MSP": "1",
    }
    if org_id is not None:
        headers["X-Sentinel-Client-Org-ID"] = org_id
    return headers


def _request(srv, path, headers, method="GET"):
    """Drive one real request through _Handler without opening a socket."""
    raw = method + " " + path + " HTTP/1.1\r\nHost: sentinel.test\r\n"
    for k, v in headers.items():
        raw += k + ": " + v + "\r\n"
    raw += "Content-Length: 0\r\nConnection: close\r\n\r\n"
    h = srv._Handler.__new__(srv._Handler)
    h.rfile = io.BytesIO(raw.encode())
    h.wfile = io.BytesIO()
    h.client_address = ("127.0.0.1", 0)
    h.server = None
    h.connection = None
    h.handle_one_request()
    head, _, body = h.wfile.getvalue().partition(b"\r\n\r\n")
    status = int(head.split(b"\r\n")[0].split()[1])
    return status, body


def _device_ids(srv, path, headers):
    status, body = _request(srv, path, headers)
    assert status == 200, path + " -> " + str(status) + ": " + repr(body[:200])
    return {d["device_id"] for d in json.loads(body)["devices"]}


def test_two_client_orgs_cannot_cross_read(wired):
    a = _device_ids(wired, "/api/devices", _viewer("org-a", "a@acme.test"))
    b = _device_ids(wired, "/api/devices", _viewer("org-b", "b@acme.test"))
    assert a == {"dev-a1", "dev-a2"}
    assert b == {"dev-b1"}
    assert not a & b
    # ...and neither sees the unassigned, MSP-only device
    assert "dev-none" not in a | b


def test_client_viewer_cannot_widen_scope_via_query_param(wired):
    viewer_a = _viewer("org-a", "a@acme.test")
    for qs in ("?client_org=org-b", "?client_org=all", "?client_org=",
               "?client_org=__unassigned__"):
        assert _device_ids(wired, "/api/devices" + qs, viewer_a) == {"dev-a1", "dev-a2"}, qs


def test_client_viewer_cannot_borrow_another_customers_org(wired):
    """Even if a forged header reaches the server, the org has to belong to
    the session's own customer -- org-x is another customer's."""
    status, body = _request(wired, "/api/devices", _viewer("org-x"))
    assert status == 403
    assert b"dev-" not in body


@pytest.mark.parametrize("org_id, why", [
    (None, "no client_org_id at all"),
    ("", "blank client_org_id"),
    ("org-does-not-exist", "unknown org"),
    ("org-off", "deactivated org"),
])
def test_client_viewer_without_valid_org_is_denied_not_widened(wired, org_id, why):
    status, body = _request(wired, "/api/devices", _viewer(org_id))
    assert status == 403, why + ": expected 403, got " + str(status) + " " + repr(body[:200])
    assert b"dev-" not in body, why + ": leaked device data in a denial"


def test_scoped_client_org_never_returns_none_for_a_client_viewer(srv, monkeypatch):
    """The invariant behind the fix: None means "no filter -> whole MSP
    fleet", so a client_viewer must never be able to reach it."""
    monkeypatch.setattr(srv, "_registry", _FakeRegistry())
    for org_id in (None, "", "org-does-not-exist", "org-off", "org-x"):
        h = srv._Handler.__new__(srv._Handler)
        h.path = "/api/devices?client_org=all"
        user = {"email": "v@acme.test", "role": "client_viewer",
                "customer_id": "acme", "client_org_id": org_id}
        monkeypatch.setattr(srv._Handler, "_session_user", lambda self, u=user: u)
        with pytest.raises(srv._TenantScopeError):
            h._scoped_client_org()


# -- fleet report: the ?profile= branch is scoped too (ARCKON-SEC-002) --------
#
# /api/fleet/report is the one non-trivial route on the client_viewer
# allowlist, and its ?profile= branch used to call list_devices_by_profile()
# with no org filter at all -- so a scoped viewer got the whole MSP fleet back
# just by adding a profile to the query string.

FLEET_FEDRAMP = "/api/fleet/report?tier=ciso&fmt=json&profile=fedramp"


def test_client_viewer_profile_report_cannot_see_other_org_devices(wired):
    a = _device_ids(wired, FLEET_FEDRAMP, _viewer("org-a", "a@acme.test"))
    assert a == {"dev-a1"}, "profile report leaked outside the viewer's org"
    b = _device_ids(wired, FLEET_FEDRAMP, _viewer("org-b", "b@acme.test"))
    assert b == {"dev-b1"}
    assert not a & b
    # org-b's device and the unassigned MSP-only device are the two things
    # org-a must not be able to see through this route.
    assert "dev-b1" not in a
    assert "dev-none" not in a | b


def test_client_viewer_profile_report_ignores_client_org_query_param(wired):
    """?client_org= must not widen the profile branch either -- the viewer's
    own org wins, same rule as /api/devices."""
    viewer_a = _viewer("org-a", "a@acme.test")
    for qs in ("&client_org=org-b", "&client_org=all", "&client_org=__unassigned__"):
        assert _device_ids(wired, FLEET_FEDRAMP + qs, viewer_a) == {"dev-a1"}, qs


def test_client_viewer_without_valid_org_is_denied_on_profile_report(wired):
    """Fail closed, not open: an unresolvable scope must 403 rather than fall
    through to an unfiltered list_devices_by_profile() call."""
    for org_id in (None, "", "org-does-not-exist", "org-off", "org-x"):
        status, body = _request(wired, FLEET_FEDRAMP, _viewer(org_id))
        assert status == 403, repr(org_id) + ": expected 403, got " + str(status)
        assert b"dev-" not in body, repr(org_id) + ": leaked device data in a denial"


def test_msp_admin_profile_report_still_returns_every_org(wired):
    """The other half of the fix: scoping the profile branch must not shrink
    the MSP admin's fleet-wide view."""
    assert _device_ids(wired, FLEET_FEDRAMP, _admin()) == {
        "dev-a1", "dev-b1", "dev-none"}


def test_msp_admin_profile_report_filters_by_profile_not_only_by_org(wired):
    """Guards against 'scoping' that accidentally turns into 'return
    everything' -- dev-a2 has no fedramp scan and must stay out."""
    ids = _device_ids(wired, FLEET_FEDRAMP, _admin())
    assert "dev-a2" not in ids
    assert _device_ids(wired, "/api/fleet/report?tier=ciso&fmt=json", _admin()) == {
        "dev-a1", "dev-a2", "dev-b1", "dev-none"}


def test_msp_admin_can_still_drill_into_one_client_on_profile_report(wired):
    admin = _admin()
    assert _device_ids(wired, FLEET_FEDRAMP + "&client_org=org-b", admin) == {"dev-b1"}
    assert _device_ids(wired, FLEET_FEDRAMP + "&client_org=__unassigned__", admin) == {"dev-none"}


def test_list_devices_by_profile_scopes_by_org_at_the_store_layer(store):
    """Asserted directly, so the storage-layer guarantee survives even if the
    handler is refactored."""
    ids = lambda **kw: {d["device_id"] for d in
                        store.list_devices_by_profile(["fedramp"], **kw)}
    assert ids(client_org_id="org-a") == {"dev-a1"}
    assert ids(client_org_id="org-b") == {"dev-b1"}
    assert ids(client_org_id="") == {"dev-none"}, "'' must mean unassigned only"
    assert ids() == {"dev-a1", "dev-b1", "dev-none"}, "None must stay fleet-wide"
    assert ids(client_org_id="org-nope") == set()


def test_evidence_export_stays_off_the_client_viewer_allowlist(wired):
    """Evidence export is unchanged by this fix because a client_viewer can't
    reach it at all. If that ever stops being true, it needs org scoping
    before it is allowlisted."""
    status, body = _request(
        wired, "/api/fleet/evidence-export?profile=fedramp", _viewer("org-a"))
    assert status == 403
    assert b"dev-" not in body


# -- trusted-proxy identity ----------------------------------------------------

def test_missing_proxy_role_header_does_not_grant_admin(wired, monkeypatch):
    """A vhost that forwards the email but drops the role header must not
    mint an MSP admin. Least privilege: no role -> client_viewer, which then
    fails closed on the missing org."""
    headers = {"X-Sentinel-Proxy-Token": "test-proxy-token",
               "X-Sentinel-User-Email": "ghost@acme.test",
               "X-Sentinel-Customer-ID": "acme"}
    h = wired._Handler.__new__(wired._Handler)
    h.headers = headers
    assert h._proxy_session_user()["role"] == "client_viewer"

    status, body = _request(wired, "/api/devices", headers)
    assert status == 403, "roleless proxy identity was served device data"
    assert b"dev-" not in body


def test_identity_headers_without_proxy_capability_are_ignored(wired):
    h = wired._Handler.__new__(wired._Handler)
    h.headers = {
        "X-Sentinel-User-Email": "forged@acme.test",
        "X-Sentinel-User-Role": "admin",
        "X-Sentinel-Customer-ID": "acme",
    }
    assert h._proxy_session_user() is None


def test_identity_headers_with_wrong_proxy_capability_are_ignored(wired):
    h = wired._Handler.__new__(wired._Handler)
    h.headers = {
        "X-Sentinel-Proxy-Token": "attacker-token",
        "X-Sentinel-User-Email": "forged@acme.test",
        "X-Sentinel-User-Role": "admin",
        "X-Sentinel-Customer-ID": "acme",
    }
    assert h._proxy_session_user() is None


def test_trusted_proxy_does_not_fallback_to_a_stale_customer_cookie(wired, monkeypatch):
    h = wired._Handler.__new__(wired._Handler)
    h.headers = {}
    monkeypatch.setattr(wired, "_get_session_cookie", lambda _headers: "stale-session")
    monkeypatch.setattr(wired._Handler, "_proxy_session_user", lambda self: None)

    assert h._session_user() is None


def test_client_viewer_is_still_denied_write_and_rollup_routes(wired):
    viewer = _viewer("org-a")
    assert _request(wired, "/clients", viewer)[0] == 403
    assert _request(wired, "/api/clients", viewer)[0] == 403
    assert _request(wired, "/api/scan", viewer, method="POST")[0] == 403


# -- the MSP side must keep working -------------------------------------------

def test_msp_admin_still_sees_every_org(wired):
    assert _device_ids(wired, "/api/devices", _admin()) == {
        "dev-a1", "dev-a2", "dev-b1", "dev-none"}


def test_msp_admin_can_still_drill_into_one_client(wired):
    admin = _admin()
    assert _device_ids(wired, "/api/devices?client_org=org-b", admin) == {"dev-b1"}
    assert _device_ids(wired, "/api/devices?client_org=__unassigned__", admin) == {"dev-none"}
    assert _device_ids(wired, "/api/devices?client_org=all", admin) == {
        "dev-a1", "dev-a2", "dev-b1", "dev-none"}

def test_admin_pinned_to_an_invalid_org_is_denied_not_widened(wired):
    """An admin session carrying a stale org pin must not silently fall back
    to the fleet-wide view."""
    status, body = _request(wired, "/api/devices", _admin("org-x"))
    assert status == 403
    assert b"dev-" not in body
