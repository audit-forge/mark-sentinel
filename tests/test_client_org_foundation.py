"""Regression tests for the MSP client-org foundation.

Four parts, following one identity from the database to the query:

  * the persisted model -- devices carry a client_org_id, the registry owns
    client_orgs and pins dashboard users to one, and the storage layer
    filters on it;
  * revalidation in the admin app -- the signed session cookie is trusted
    only for *who* is calling, and role/customer/client-org are re-read from
    the users table on every request, so a role change, a client-org move or
    a deactivation takes effect immediately instead of whenever the token
    happens to expire;
  * propagation through nginx -- the customer vhost captures every identity
    header /auth/verify returns, re-sets all of them on the authenticated
    location, and blanks every one of them (both spellings) on the locations
    that bypass the auth subrequest; and
  * enforcement in server.py -- the role/client_org_id pair that arrives on
    the request scopes every reachable query, and *denies* rather than widens
    when it cannot be resolved.
"""

import importlib
import io
import json
import os
import re
import sqlite3
import subprocess
import sys
import types
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
ADMIN = REPO / "admin"


# -- storage: the persisted model ---------------------------------------------

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
    # A second, profile-tagged scan for a subset of the fleet, so ?profile=
    # exercises list_devices_by_profile() and a test asserting on it can tell
    # org filtering apart from profile filtering. dev-a2 is deliberately left
    # with only the untagged scan.
    fedramp = _report("fedramp")
    st.upsert_report("dev-a1", "a1.acme", fedramp, client_org_id="org-a")
    st.upsert_report("dev-b1", "b1.acme", fedramp, client_org_id="org-b")
    st.upsert_report("dev-none", "unassigned.acme", fedramp)
    return st


@pytest.fixture
def registry(tmp_path):
    from storage import CustomerRegistry
    return CustomerRegistry(tmp_path / "customers.db")


def _ids(rows):
    return {d["device_id"] for d in rows}


def test_devices_persist_their_client_org_assignment(store):
    by_id = {d["device_id"]: d for d in store.list_devices()}
    assert by_id["dev-a1"]["client_org_id"] == "org-a"
    assert by_id["dev-b1"]["client_org_id"] == "org-b"
    assert by_id["dev-none"]["client_org_id"] is None


def test_list_devices_scopes_by_org(store):
    assert _ids(store.list_devices(client_org_id="org-a")) == {"dev-a1", "dev-a2"}
    assert _ids(store.list_devices(client_org_id="org-b")) == {"dev-b1"}
    assert _ids(store.list_devices(client_org_id="")) == {"dev-none"}, \
        "'' must mean unassigned only"
    assert _ids(store.list_devices()) == {"dev-a1", "dev-a2", "dev-b1", "dev-none"}, \
        "None must stay fleet-wide"
    assert _ids(store.list_devices(client_org_id="org-nope")) == set()


def test_list_devices_by_profile_scopes_by_org_at_the_store_layer(store):
    """Asserted directly, so the storage-layer guarantee survives even if the
    handler is refactored."""
    def ids(**kw):
        return _ids(store.list_devices_by_profile(["fedramp"], **kw))
    assert ids(client_org_id="org-a") == {"dev-a1"}
    assert ids(client_org_id="org-b") == {"dev-b1"}
    assert ids(client_org_id="") == {"dev-none"}, "'' must mean unassigned only"
    assert ids() == {"dev-a1", "dev-b1", "dev-none"}, "None must stay fleet-wide"
    assert ids(client_org_id="org-nope") == set()


def test_a_checkin_without_a_token_does_not_clear_an_assignment(store):
    """The agent omits client_org_token unless it was explicitly configured,
    so an empty value has to mean "leave it alone", never "unassign"."""
    store.upsert_report("dev-a1", "a1.acme", _report())
    orgs = {d["device_id"]: d["client_org_id"] for d in store.list_devices()}
    assert orgs["dev-a1"] == "org-a"


def test_devices_can_be_reassigned_between_orgs(store):
    assert store.set_device_client_org("dev-a2", "org-b") is True
    assert _ids(store.list_devices(client_org_id="org-a")) == {"dev-a1"}
    assert _ids(store.list_devices(client_org_id="org-b")) == {"dev-a2", "dev-b1"}
    assert store.set_device_client_org("dev-a2", None) is True
    assert _ids(store.list_devices(client_org_id="")) == {"dev-a2", "dev-none"}
    assert store.set_device_client_org("dev-does-not-exist", "org-a") is False


def test_client_orgs_are_scoped_to_their_customer(registry):
    acme = registry.create_customer("Acme MSP")["id"]
    globex = registry.create_customer("Globex MSP")["id"]

    a = registry.create_client_org(acme, "Org A")
    x = registry.create_client_org(globex, "Other")

    assert {o["id"] for o in registry.list_client_orgs(acme)} == {a["id"]}
    assert registry.get_client_org(a["id"])["customer_id"] == acme
    assert registry.get_client_org(x["id"])["customer_id"] == globex
    # Enrollment tokens are per-org and not trivially short.
    assert a["enroll_token"] != x["enroll_token"]
    assert len(a["enroll_token"]) >= 16


def test_enrollment_token_resolves_only_while_the_org_is_active(registry):
    cid = registry.create_customer("Acme MSP")["id"]
    org = registry.create_client_org(cid, "Org A")

    resolved = registry.get_client_org_by_token(org["enroll_token"])
    assert resolved["id"] == org["id"]
    assert resolved["customer_id"] == cid
    assert registry.get_client_org_by_token("not-a-token") is None
    assert registry.get_client_org_by_token("") is None

    assert registry.deactivate_client_org(org["id"], cid) is True
    assert registry.get_client_org_by_token(org["enroll_token"]) is None
    # Soft delete: the row survives so historical device rows still resolve.
    assert registry.get_client_org(org["id"])["active"] == 0


def test_client_org_writes_require_the_owning_customer(registry):
    cid = registry.create_customer("Acme MSP")["id"]
    org = registry.create_client_org(cid, "Org A")

    assert registry.rename_client_org(org["id"], "some-other-customer", "Hijacked") is False
    assert registry.deactivate_client_org(org["id"], "some-other-customer") is False
    assert registry.get_client_org(org["id"])["name"] == "Org A"
    assert registry.get_client_org(org["id"])["active"] == 1

    assert registry.rename_client_org(org["id"], cid, "Org A Renamed") is True
    assert registry.get_client_org(org["id"])["name"] == "Org A Renamed"


def test_dashboard_users_carry_their_client_org_pin_through_login(registry):
    """The pin has to survive create -> authenticate -> session, because that
    is the chain that ends up as the request's client_org_id."""
    cid = registry.create_customer("Acme MSP")["id"]
    org = registry.create_client_org(cid, "Org A")

    viewer = registry.create_user(cid, "viewer@acme.test", "hunter2hunter2",
                                  "client_viewer", org["id"])
    admin = registry.create_user(cid, "msp@acme.test", "hunter2hunter2", "admin")
    assert viewer["client_org_id"] == org["id"]
    assert admin["client_org_id"] is None

    auth = registry.authenticate_user("viewer@acme.test", "hunter2hunter2")
    assert auth["role"] == "client_viewer"
    assert auth["client_org_id"] == org["id"]

    token = registry.create_session(auth["id"], auth["customer_id"], auth["email"])
    session = registry.get_session(token)
    assert session["role"] == "client_viewer"
    assert session["client_org_id"] == org["id"]

    listed = {u["email"]: u for u in registry.list_users(cid)}
    assert listed["viewer@acme.test"]["client_org_id"] == org["id"]
    assert listed["msp@acme.test"]["client_org_id"] is None


def test_rescoping_a_user_takes_effect_on_existing_sessions(registry):
    """get_session() joins to dashboard_users rather than copying the pin, so
    an admin revoking access doesn't have to wait for the session to expire."""
    cid = registry.create_customer("Acme MSP")["id"]
    org = registry.create_client_org(cid, "Org A")
    viewer = registry.create_user(cid, "viewer@acme.test", "hunter2hunter2",
                                  "client_viewer", org["id"])
    token = registry.create_session(viewer["id"], cid, viewer["email"])
    assert registry.get_session(token)["client_org_id"] == org["id"]

    assert registry.deactivate_user(viewer["id"], cid) is True
    assert registry.get_session(token) is None


# -- server: identity and the authorization boundary --------------------------

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

    def has_customers(self):
        return True


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
    """The invariant behind the design: None means "no filter -> whole MSP
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


FLEET_FEDRAMP = "/api/fleet/report?tier=ciso&fmt=json&profile=fedramp"


def test_client_viewer_profile_report_cannot_see_other_org_devices(wired):
    """/api/fleet/report is the one non-trivial route on the allowlist, and
    its ?profile= branch takes a different storage call than the default."""
    a = _device_ids(wired, FLEET_FEDRAMP, _viewer("org-a", "a@acme.test"))
    assert a == {"dev-a1"}, "profile report leaked outside the viewer's org"
    b = _device_ids(wired, FLEET_FEDRAMP, _viewer("org-b", "b@acme.test"))
    assert b == {"dev-b1"}
    assert not a & b
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


def test_client_viewer_is_denied_write_and_unallowlisted_read_routes(wired):
    viewer = _viewer("org-a")
    assert _request(wired, "/api/clients", viewer)[0] == 403
    assert _request(wired, "/api/users", viewer)[0] == 403
    assert _request(wired, "/api/fleet/inventory", viewer)[0] == 403
    assert _request(wired, "/api/scan", viewer, method="POST")[0] == 403
    assert _request(wired, "/api/clients/add", viewer, method="POST")[0] == 403


def test_evidence_export_stays_off_the_client_viewer_allowlist(wired):
    """Evidence export has no org scoping, so a client_viewer must not be able
    to reach it at all. If that ever stops being true, it needs org scoping
    before it is allowlisted."""
    status, body = _request(
        wired, "/api/fleet/evidence-export?profile=fedramp", _viewer("org-a"))
    assert status == 403
    assert b"dev-" not in body


def test_missing_proxy_role_header_does_not_grant_admin(wired):
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


def test_legacy_arckon_headers_still_carry_the_client_org_pin(wired):
    """The proxy emits X-Arckon-* on this branch; both spellings have to
    reach the same scope or the pin is silently dropped."""
    headers = {"X-Sentinel-Proxy-Token": "test-proxy-token",
               "X-Arckon-User-Email": "a@acme.test",
               "X-Arckon-User-Role": "client_viewer",
               "X-Arckon-Customer-ID": "acme",
               "X-Arckon-Client-Org-ID": "org-a"}
    assert _device_ids(wired, "/api/devices", headers) == {"dev-a1", "dev-a2"}


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


def test_msp_admin_profile_report_still_returns_every_org(wired):
    """The other half: scoping the profile branch must not shrink the MSP
    admin's fleet-wide view, and must still filter by profile -- dev-a2 has
    no fedramp scan and must stay out."""
    ids = _device_ids(wired, FLEET_FEDRAMP, _admin())
    assert ids == {"dev-a1", "dev-b1", "dev-none"}
    assert "dev-a2" not in ids
    assert _device_ids(wired, "/api/fleet/report?tier=ciso&fmt=json", _admin()) == {
        "dev-a1", "dev-a2", "dev-b1", "dev-none"}


def test_admin_pinned_to_an_invalid_org_is_denied_not_widened(wired):
    """An admin session carrying a stale or cross-customer org pin must not
    silently fall back to the fleet-wide view."""
    status, body = _request(wired, "/api/devices", _admin("org-x"))
    assert status == 403
    assert b"dev-" not in body
    assert _request(wired, "/api/scan", _admin("org-off"), method="POST")[0] == 403


# -- admin app: the session's identity is re-read, never remembered ------------
#
# The admin app (user-manager) mints an 8-hour JWT at login and is also the
# /auth/verify endpoint every customer vhost asks about on every request.
# Anything it copies out of those claims instead of out of the database is
# access that outlives the change meant to revoke it -- in its own UI *and* in
# the X-Arckon-* headers it hands to every customer container.

@pytest.fixture
def admin_db(tmp_path, monkeypatch):
    """The admin app's own sqlite database, on a temp path.

    admin/db.py is stdlib-only, so the revalidation contract stays testable
    without fastapi/PyJWT/passlib installed (CI installs only
    requirements.txt); the end-to-end tests below skip if they are missing."""
    if str(ADMIN) not in sys.path:
        sys.path.insert(0, str(ADMIN))
    db = importlib.import_module("db")
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "sentinel.db"))
    db.init_db()
    return db


def _add_admin_user(db, user_id, email, role, customer_id=None, client_org_id=None,
                    active=1):
    with db.get_conn() as conn:
        conn.execute(
            "INSERT INTO users (id, email, password_hash, role, customer_id, "
            "client_org_id, created_at, active) VALUES (?,?,?,?,?,?,?,?)",
            (user_id, email, "x", role, customer_id, client_org_id,
             "2026-07-25T00:00:00+00:00", active),
        )
    return user_id


def test_revalidate_user_returns_the_current_role_and_client_org(admin_db):
    _add_admin_user(admin_db, "u1", "viewer@acme.test", "client_viewer",
                    customer_id="acme", client_org_id="org-a")
    assert admin_db.revalidate_user("u1") == {
        "sub": "u1", "email": "viewer@acme.test", "role": "client_viewer",
        "customer_id": "acme", "client_org_id": "org-a",
    }


def test_moving_a_user_to_another_client_org_takes_effect_immediately(admin_db):
    """The whole point: no waiting for the token to expire."""
    _add_admin_user(admin_db, "u1", "viewer@acme.test", "client_viewer",
                    customer_id="acme", client_org_id="org-a")
    with admin_db.get_conn() as conn:
        conn.execute("UPDATE users SET client_org_id='org-b' WHERE id='u1'")
    assert admin_db.revalidate_user("u1")["client_org_id"] == "org-b"

    with admin_db.get_conn() as conn:
        conn.execute("UPDATE users SET role='customer_admin', client_org_id=NULL "
                     "WHERE id='u1'")
    fresh = admin_db.revalidate_user("u1")
    assert fresh["role"] == "customer_admin"
    assert fresh["client_org_id"] is None


def test_revalidate_user_fails_closed_for_missing_and_deactivated_users(admin_db):
    _add_admin_user(admin_db, "u1", "gone@acme.test", "customer_admin",
                    customer_id="acme")
    with admin_db.get_conn() as conn:
        conn.execute("UPDATE users SET active=0 WHERE id='u1'")
    with pytest.raises(admin_db.StaleSessionError):
        admin_db.revalidate_user("u1")

    with admin_db.get_conn() as conn:
        conn.execute("DELETE FROM users WHERE id='u1'")
    with pytest.raises(admin_db.StaleSessionError):
        admin_db.revalidate_user("u1")

    for missing in (None, "", "not-a-user-id"):
        with pytest.raises(admin_db.StaleSessionError):
            admin_db.revalidate_user(missing)


def test_revalidate_user_keeps_the_super_admin_intact(admin_db):
    """A super_admin has no customer_id and no org pin, and must keep both."""
    _add_admin_user(admin_db, "root", "admin@arckon.local", "super_admin")
    assert admin_db.revalidate_user("root") == {
        "sub": "root", "email": "admin@arckon.local", "role": "super_admin",
        "customer_id": None, "client_org_id": None,
    }


def test_revalidate_user_tolerates_a_database_predating_the_org_column(
        tmp_path, monkeypatch):
    """init_db() adds client_org_id on startup, but a lookup must not blow up
    (nor invent an org) if it is ever called against an older file."""
    if str(ADMIN) not in sys.path:
        sys.path.insert(0, str(ADMIN))
    db = importlib.import_module("db")
    legacy = tmp_path / "legacy.db"
    conn = sqlite3.connect(legacy)
    conn.execute("CREATE TABLE users (id TEXT PRIMARY KEY, email TEXT, "
                 "password_hash TEXT, role TEXT, customer_id TEXT, "
                 "created_at TEXT, active INTEGER NOT NULL DEFAULT 1)")
    conn.execute("INSERT INTO users VALUES ('u1','a@acme.test','x','customer_admin',"
                 "'acme','2026-07-25T00:00:00+00:00',1)")
    conn.commit()
    conn.close()
    monkeypatch.setattr(db, "DB_PATH", str(legacy))
    fresh = db.revalidate_user("u1")
    assert fresh["client_org_id"] is None
    assert fresh["role"] == "customer_admin"


# -- admin app, end to end: a live token against a changed user row -----------

@pytest.fixture
def admin_auth(admin_db):
    """admin/auth.py, which needs the admin container's own dependencies."""
    pytest.importorskip("jwt")
    pytest.importorskip("fastapi")
    pytest.importorskip("passlib")
    auth = importlib.import_module("auth")
    assert auth.revalidate_user is admin_db.revalidate_user, \
        "auth.py must revalidate against the same db module the fixture patched"
    return auth


def _cookie_request(token):
    """The only thing get_current_user() reads off the request."""
    return types.SimpleNamespace(cookies={"token": token})


def test_a_token_minted_before_an_org_move_carries_the_new_org(admin_db, admin_auth):
    _add_admin_user(admin_db, "u1", "viewer@acme.test", "client_viewer",
                    customer_id="acme", client_org_id="org-a")
    token = admin_auth.create_token("u1", "client_viewer", "acme",
                                    "viewer@acme.test", "org-a")
    assert admin_auth.get_current_user(_cookie_request(token))["client_org_id"] == "org-a"

    with admin_db.get_conn() as conn:
        conn.execute("UPDATE users SET client_org_id='org-b' WHERE id='u1'")
    user = admin_auth.get_current_user(_cookie_request(token))
    assert user["client_org_id"] == "org-b", "stale org claim survived the move"
    assert user["sub"] == "u1"


def test_a_token_minted_before_a_role_change_carries_the_new_role(admin_db, admin_auth):
    _add_admin_user(admin_db, "u1", "boss@acme.test", "customer_admin",
                    customer_id="acme")
    token = admin_auth.create_token("u1", "customer_admin", "acme", "boss@acme.test")
    with admin_db.get_conn() as conn:
        conn.execute("UPDATE users SET role='client_viewer', client_org_id='org-a' "
                     "WHERE id='u1'")
    user = admin_auth.get_current_user(_cookie_request(token))
    assert user["role"] == "client_viewer"
    assert user["client_org_id"] == "org-a"


def test_deactivating_a_user_kills_their_live_token(admin_db, admin_auth):
    from fastapi import HTTPException
    _add_admin_user(admin_db, "u1", "fired@acme.test", "customer_admin",
                    customer_id="acme")
    token = admin_auth.create_token("u1", "customer_admin", "acme", "fired@acme.test")
    assert admin_auth.get_current_user(_cookie_request(token))["role"] == "customer_admin"

    with admin_db.get_conn() as conn:
        conn.execute("UPDATE users SET active=0 WHERE id='u1'")
    with pytest.raises(HTTPException) as excinfo:
        admin_auth.get_current_user(_cookie_request(token))
    assert excinfo.value.status_code == 401

    with admin_db.get_conn() as conn:
        conn.execute("DELETE FROM users WHERE id='u1'")
    with pytest.raises(HTTPException) as excinfo:
        admin_auth.get_current_user(_cookie_request(token))
    assert excinfo.value.status_code == 401


def test_a_stale_super_admin_claim_does_not_survive_revalidation(admin_db, admin_auth):
    """A validly *signed* token only proves who is calling -- the users table
    decides whether they are still a super_admin."""
    from fastapi import HTTPException
    _add_admin_user(admin_db, "u1", "user@acme.test", "user", customer_id="acme")
    token = admin_auth.create_token("u1", "super_admin", None, "user@acme.test")
    user = admin_auth.get_current_user(_cookie_request(token))
    assert user["role"] == "user"
    assert user["customer_id"] == "acme"
    with pytest.raises(HTTPException) as excinfo:
        admin_auth.require_super_admin(_cookie_request(token))
    assert excinfo.value.status_code == 403


def test_a_demoted_super_admin_loses_access_on_the_next_request(admin_db, admin_auth):
    from fastapi import HTTPException
    _add_admin_user(admin_db, "root", "admin@arckon.local", "super_admin")
    token = admin_auth.create_token("root", "super_admin", None, "admin@arckon.local")
    assert admin_auth.require_super_admin(_cookie_request(token))["role"] == "super_admin"

    with admin_db.get_conn() as conn:
        conn.execute("UPDATE users SET role='user', customer_id='acme' WHERE id='root'")
    with pytest.raises(HTTPException) as excinfo:
        admin_auth.require_super_admin(_cookie_request(token))
    assert excinfo.value.status_code == 403


def test_a_valid_msp_admin_session_is_unchanged(admin_db, admin_auth):
    """Revalidation must not cost a working session anything: same sub, same
    email, same customer, same role."""
    _add_admin_user(admin_db, "u1", "msp@acme.test", "customer_admin",
                    customer_id="acme")
    token = admin_auth.create_token("u1", "customer_admin", "acme", "msp@acme.test")
    user = admin_auth.get_current_user(_cookie_request(token))
    assert user["sub"] == "u1"
    assert user["email"] == "msp@acme.test"
    assert user["role"] == "customer_admin"
    assert user["customer_id"] == "acme"
    assert user["client_org_id"] is None


def test_an_unsigned_or_absent_cookie_is_still_401(admin_db, admin_auth):
    from fastapi import HTTPException
    for token in ("", "not-a-jwt"):
        with pytest.raises(HTTPException) as excinfo:
            admin_auth.get_current_user(_cookie_request(token))
        assert excinfo.value.status_code == 401


# -- nginx: propagating that identity, and only that identity -----------------
#
# The customer container trusts these headers whenever it is started with
# ARCKON_TRUSTED_PROXY (see server.py::_proxy_session_user), and nginx
# forwards client request headers to the upstream unless they are explicitly
# blanked. So the vhost owes the container two things, and both are tested
# against the checked-in provisioner *and* against the config it actually
# renders -- a header that is only captured, or a spelling that is only
# blanked on some locations, is silently exploitable:
#
#   1. on the auth_request-protected location, every identity header
#      /auth/verify returns is captured and re-set from the captured value;
#   2. on every location that bypasses /auth/verify, all of them are blanked
#      -- both the X-Arckon-* spelling and the X-Sentinel-* one the container
#      actually prefers.

PROVISIONER = REPO / "deploy" / "gcp" / "provision_customer.sh"
VHOST_CUSTOMER = "acme"

# Both spellings of every identity header server.py will trust from the proxy.
IDENTITY_HEADERS = tuple(
    prefix + suffix
    for prefix in ("X-Arckon-", "X-Sentinel-")
    for suffix in ("User-Email", "User-Role", "Customer-ID", "Client-Org-ID")
)


def _auth_verify_emitted_headers():
    """The identity headers /auth/verify hands back, read out of admin/app.py.

    Read from the source rather than hard-coded so that adding a header there
    without wiring it through the vhost fails these tests."""
    src = (ADMIN / "app.py").read_text()
    body = src.split("async def auth_verify(", 1)[1].split("\n@app.", 1)[0]
    headers = re.findall(r'"(X-(?:Arckon|Sentinel)-[\w-]+)":', body)
    assert len(headers) >= 4, "could not read auth_verify's headers: " + repr(headers)
    return headers


def _location_blocks(conf):
    """{location argument: [directive lines]} for a rendered vhost."""
    blocks, current = {}, None
    for raw in conf.splitlines():
        line = raw.strip()
        if line.startswith("location ") and line.endswith("{"):
            current = line[len("location "):-1].strip()
            blocks[current] = []
        elif line == "}":
            current = None
        elif current is not None and line and not line.startswith("#"):
            blocks[current].append(line)
    assert "/" in blocks, "no catch-all location in the rendered vhost"
    return blocks


_SET_HEADER = re.compile(r"^proxy_set_header\s+(\S+)\s+(.*?);$")
_AUTH_SET = re.compile(r"^auth_request_set\s+(\$\w+)\s+\$upstream_http_(\w+);$")


def _proxy_headers(lines):
    matches = (_SET_HEADER.match(line) for line in lines)
    return {m.group(1): m.group(2).strip() for m in matches if m}


def _captured_headers(lines):
    """{nginx variable: auth-response header it was captured from}."""
    out = {}
    for line in lines:
        m = _AUTH_SET.match(line)
        if m:
            out[m.group(1)] = m.group(2).replace("_", "-")
    return out


@pytest.fixture(scope="module")
def rendered_vhost(tmp_path_factory):
    """The vhost the checked-in provisioner actually writes.

    Only docker and chown are stubbed (the script would otherwise start a
    container and chown a host path); the config itself comes from the real
    script, so a heredoc-escaping or interpolation slip fails here rather than
    on the next customer to be provisioned."""
    tmp = tmp_path_factory.mktemp("provision")
    stubs = tmp / "bin"
    stubs.mkdir()
    for name in ("docker", "chown"):
        stub = stubs / name
        stub.write_text("#!/bin/sh\nexit 0\n")
        stub.chmod(0o755)
    conf_dir = tmp / "nginx"
    env = dict(
        os.environ,
        PATH=str(stubs) + os.pathsep + os.environ.get("PATH", ""),
        NGINX_CONF_DIR=str(conf_dir),
        SENTINEL_DATA_ROOT=str(tmp / "data"),
        HOST_LICENSES_DIR=str(tmp / "licenses"),
    )
    proc = subprocess.run(
        ["bash", str(PROVISIONER), VHOST_CUSTOMER, "203.0.113.10", "standard", "",
         "5", "Acme Corp", "7042", "agent-token"],
        env=env, capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return (conf_dir / (VHOST_CUSTOMER + ".conf")).read_text()


def test_the_checked_in_provisioner_is_valid_bash():
    proc = subprocess.run(["bash", "-n", str(PROVISIONER)],
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr


def test_the_checked_in_provisioner_captures_only_headers_the_verifier_sends():
    """The failure this guards against is silent: capturing
    $upstream_http_x_sentinel_user_role when the verifier answers with
    X-Arckon-User-Role leaves the variable -- and the header -- empty, and the
    container then falls back to its least-privileged default."""
    emitted = {h.lower().replace("-", "_") for h in _auth_verify_emitted_headers()}
    captured = re.findall(r"\$upstream_http_(\w+)", PROVISIONER.read_text())
    assert captured, "the provisioner captures no auth-response headers at all"
    for name in captured:
        assert name in emitted, \
            "captures $upstream_http_" + name + ", which /auth/verify never sends"


def test_the_checked_in_provisioner_blanks_both_header_spellings():
    src = PROVISIONER.read_text()
    for header in IDENTITY_HEADERS:
        assert re.search(r"proxy_set_header\s+" + header + r'\s+"";', src), \
            header + " is never blanked, so a client copy survives somewhere"


def test_the_authenticated_location_forwards_every_verified_identity_header(
        rendered_vhost):
    block = _location_blocks(rendered_vhost)["/"]
    assert "auth_request /_auth;" in block
    captured = _captured_headers(block)
    headers = _proxy_headers(block)

    for name in _auth_verify_emitted_headers():
        assert name in headers, name + " never reaches the container"
        value = headers[name]
        assert value not in ('""', ""), name + " is forwarded as an empty value"
        if value.startswith("$"):
            assert captured.get(value) == name.lower(), \
                name + " is set from " + value + ", which is not captured " \
                "from " + name
        else:
            # The only literal allowed: the vhost's own customer (below).
            assert name.endswith("-Customer-ID"), \
                name + " is set to the literal " + value


def test_the_authenticated_location_pins_the_customer_id_to_its_own_vhost(
        rendered_vhost):
    """A super_admin's session carries no customer_id, and an empty header
    would send the container looking for the 'default' tenant's data."""
    headers = _proxy_headers(_location_blocks(rendered_vhost)["/"])
    assert headers["X-Arckon-Customer-ID"] == VHOST_CUSTOMER
    assert headers["X-Sentinel-Customer-ID"] == VHOST_CUSTOMER


def test_the_authenticated_location_uses_no_undefined_variables(rendered_vhost):
    """An identity header set from a variable nobody assigns renders empty --
    which fails open on any consumer that treats "absent" as "unrestricted"."""
    block = _location_blocks(rendered_vhost)["/"]
    defined = set(_captured_headers(block)) | {
        "$host", "$remote_addr", "$proxy_add_x_forwarded_for", "$http_authorization",
        "$http_cookie", "$request_uri", "$server_port",
    }
    for name, value in _proxy_headers(block).items():
        for var in re.findall(r"\$\w+", value):
            assert var in defined, name + " is set from undefined " + var


def test_every_bypass_location_clears_every_identity_header(rendered_vhost):
    """Anything proxied without the auth subrequest must blank all of them --
    including /_auth itself, whose client is the browser too."""
    bypass = {
        name: lines for name, lines in _location_blocks(rendered_vhost).items()
        if any(line.startswith("proxy_pass ") for line in lines)
        and not any(line.startswith("auth_request ") for line in lines)
    }
    assert set(bypass) >= {"= /_auth", "/api/agent/", "/install/"}, sorted(bypass)
    assert any(name.startswith("~") for name in bypass), \
        "the bundle/agent download location is missing"

    for name, lines in bypass.items():
        headers = _proxy_headers(lines)
        for header in IDENTITY_HEADERS:
            assert headers.get(header) == '""', \
                "location " + name + " does not clear " + header


def test_the_rendered_vhost_still_does_the_rest_of_its_job(rendered_vhost):
    """Guard rails for the rewrite above: the identity plumbing must not have
    cost the vhost its upstreams, its auth redirect or its long timeouts."""
    blocks = _location_blocks(rendered_vhost)
    assert "listen 7042;" in rendered_vhost
    assert "error_page 401 403 = @login_redirect;" in blocks["/"]
    assert "proxy_pass http://sentinel-acme:7331;" in blocks["/"]
    assert "proxy_pass http://user-manager:8000/auth/verify;" in blocks["= /_auth"]
    assert "proxy_set_header X-Customer-ID acme;" in blocks["= /_auth"]
    assert "proxy_read_timeout 300;" in blocks["/api/agent/"]
    assert rendered_vhost.count("proxy_read_timeout 300;") == 3
    assert any("return 302 http://203.0.113.10/login?next=" in line
               for line in blocks["@login_redirect"])
