"""Regression tests: Endpoint AI customer-facing surfaces must not expose
raw-JSON operator tooling, and raw JSON inventory endpoints must be
role-gated server-side. (Incident 2026-11-02: 'JSON API' button shipped to
all customer roles; replaced by tenant-scoped CSV export.)"""

import pytest

import server


ALL_ROLES = ('admin', 'viewer', 'client_viewer', 'customer_admin', 'super_admin')
PRIVILEGED = ('customer_admin', 'super_admin')


def _fleet_html(role: str) -> str:
    return server._build_fleet_html([], current_user_role=role)


class TestEndpointAiPageSurfaces:
    @pytest.mark.parametrize('role', ALL_ROLES)
    def test_no_raw_json_api_link_for_any_role(self, role):
        html = _fleet_html(role)
        assert 'JSON API' not in html
        assert 'target="_blank" style="font-size:12px;color:#4F46E5' not in html

    @pytest.mark.parametrize('role', ALL_ROLES)
    def test_csv_export_link_present(self, role):
        html = _fleet_html(role)
        assert '/api/fleet/ai-inventory/csv' in html
        assert 'Export CSV' in html


class _HandlerStub:
    """Minimal stub for exercising handler methods without HTTP."""

    def __init__(self, role, path='/api/fleet/ai-inventory'):
        self._role = role
        self.path = path
        self.json_calls = []

    def _session_user(self):
        return {'role': self._role} if self._role else None

    def _json(self, payload, status=200):
        self.json_calls.append((payload, status))


class TestRawJsonEndpointsRoleGated:
    @pytest.mark.parametrize('role', [r for r in ALL_ROLES if r not in PRIVILEGED] + [None])
    def test_inventory_403_for_unprivileged(self, role):
        h = _HandlerStub(role)
        handler = server._Handler.__new__(server._Handler)
        handler._session_user = h._session_user
        handler._json = h._json
        handler.path = h.path
        handler._api_get_fleet_ai_inventory()
        assert h.json_calls == [({'error': 'forbidden'}, 403)]

    @pytest.mark.parametrize('role', [r for r in ALL_ROLES if r not in PRIVILEGED] + [None])
    def test_summary_403_for_unprivileged(self, role):
        h = _HandlerStub(role)
        handler = server._Handler.__new__(server._Handler)
        handler._session_user = h._session_user
        handler._json = h._json
        handler._api_get_fleet_ai_inventory_summary()
        assert h.json_calls == [({'error': 'forbidden'}, 403)]

    @pytest.mark.parametrize('role', PRIVILEGED)
    def test_inventory_serves_privileged(self, role):
        class _Store:
            def list_endpoint_ai_inventory(self, client_org_id=None, limit=200, offset=0):
                return []

            def count_endpoint_ai_inventory(self, client_org_id=None):
                return 0

        h = _HandlerStub(role)
        handler = server._Handler.__new__(server._Handler)
        handler._session_user = h._session_user
        handler._json = h._json
        handler.path = h.path
        handler._scoped_client_org = lambda: None
        handler._store = lambda: _Store()
        handler._api_get_fleet_ai_inventory()
        assert len(h.json_calls) == 1
        payload, status = h.json_calls[0]
        assert status == 200 and payload['entries'] == []
