"""Endpoint AI governance authorization, validation, and rendering boundaries."""

import html
import io
import json
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import server
from storage import AgentStore
from .test_endpoint_ai_governance_storage import add_tool
from .test_server_security_boundaries import dashboard


ROUTE = '/api/fleet/ai-inventory/governance'
ADMIN_ROLES = ('admin', 'customer_admin', 'super_admin')


@pytest.fixture
def governance(monkeypatch):
    user = {'id': 17, 'email': 'admin@example.test', 'role': 'admin',
            'customer_id': 'customer-a'}
    registry = Mock()
    registry.get_client_org.return_value = {
        'id': 'org-a', 'active': True, 'customer_id': 'customer-a'}
    monkeypatch.setattr(server, '_get_registry', Mock(return_value=registry))
    store = Mock()
    store.set_endpoint_ai_governance.return_value = True
    handler = server._Handler.__new__(server._Handler)
    handler.path = ROUTE + '?client_org=org-a'
    handler._session_user = Mock(return_value=user)
    handler._store = Mock(return_value=store)
    handler._json = Mock()

    def request(body=None, *, raw=None, length=None):
        data = raw if raw is not None else json.dumps(
            body if body is not None else {'id': 7, 'governance_status': 'restricted'}
        ).encode()
        handler.headers = {'Content-Length': str(len(data)) if length is None else length}
        handler.rfile = io.BytesIO(data)
        handler._json.reset_mock()
        handler._api_set_endpoint_ai_governance()
        args = handler._json.call_args.args
        handler._json.assert_called_once()
        return (args[1] if len(args) > 1 else 200), args[0]

    return SimpleNamespace(handler=handler, user=user, registry=registry,
                           store=store, request=request)


@pytest.mark.parametrize('role', [None, '', 'viewer', 'client_viewer', 'user', 'msp_admin'])
def test_role_denial_precedes_scope_body_and_storage(governance, role):
    g = governance
    if role is None:
        g.handler._session_user.return_value = None
    else:
        g.user['role'] = role
    g.handler._scoped_client_org = Mock(side_effect=AssertionError('scope accessed'))
    assert g.request(raw=b'not json') == (403, {'error': 'forbidden'})
    g.handler._scoped_client_org.assert_not_called()
    g.handler._store.assert_not_called()
    assert g.handler.rfile.tell() == 0


@pytest.mark.parametrize('body', [
    [], 'restricted', 1, True,
    {}, {'id': 7}, {'governance_status': 'restricted'},
    {'id': 7, 'governance_status': 'restricted', 'changed_by': 'spoofed'},
    {'id': 7, 'governance_status': 'restricted', 'actor_role': 'super_admin'},
    {'id': 7, 'governance_status': 'restricted', 'client_org_id': 'org-b'},
] + [{'id': value, 'governance_status': 'restricted'}
     for value in (True, False, 0, -1, 1.5, '7', None, [], {})]
  + [{'id': 7, 'governance_status': value}
     for value in ('', 'approved', 'Restricted', True, 1, [], {})])
def test_invalid_payload_never_accesses_storage(governance, body):
    assert governance.request(body)[0] == 400
    governance.handler._store.assert_not_called()


@pytest.mark.parametrize('raw', [b'{', b'null', b'', b'\xff'])
def test_malformed_json_never_accesses_storage(governance, raw):
    assert governance.request(raw=raw)[0] == 400
    governance.handler._store.assert_not_called()


@pytest.mark.parametrize('length', ['0', '-1', '4097', 'invalid'])
def test_invalid_request_size_never_reads_body_or_storage(governance, length):
    assert governance.request(length=length)[0] == 400
    assert governance.handler.rfile.tell() == 0
    governance.handler._store.assert_not_called()


@pytest.mark.parametrize('org', [
    None,
    {'active': False, 'customer_id': 'customer-a'},
    {'active': True, 'customer_id': 'foreign-customer'},
])
def test_missing_inactive_or_foreign_query_scope_is_forbidden(governance, org):
    g = governance
    g.registry.get_client_org.return_value = org
    assert g.request() == (403, {'error': 'invalid client-org scope'})
    g.registry.get_client_org.assert_called_once_with('org-a')
    g.handler._store.assert_not_called()
    assert g.handler.rfile.tell() == 0


def test_scope_resolution_failure_is_forbidden_before_storage(governance):
    g = governance
    g.handler._scoped_client_org = Mock(side_effect=server._TenantScopeError('invalid'))
    assert g.request() == (403, {'error': 'invalid client-org scope'})
    g.handler._store.assert_not_called()


@pytest.mark.parametrize('role', ADMIN_ROLES)
@pytest.mark.parametrize('status', ['sanctioned', 'tolerated', 'shadow', 'restricted', None])
def test_admin_calls_pass_session_actor_status_and_scope(governance, role, status):
    g = governance
    g.user['role'] = role
    assert g.request({'id': 7, 'governance_status': status}) == (200, {'ok': True})
    g.store.set_endpoint_ai_governance.assert_called_once_with(
        7, status, changed_by='admin@example.test', actor_role=role, client_org_id='org-a')


@pytest.mark.parametrize(('fields', 'actor'), [
    ({'email': '', 'id': 23}, '23'),
    ({'email': None, 'id': 'operator-id'}, 'operator-id'),
    ({'impersonated_by': 'owner@example.test'},
     'admin@example.test (impersonated by owner@example.test)'),
])
def test_audit_actor_is_derived_from_session(governance, fields, actor):
    g = governance
    g.user.update(fields)
    assert g.request()[0] == 200
    assert g.store.set_endpoint_ai_governance.call_args.kwargs['changed_by'] == actor


@pytest.mark.parametrize(('query', 'scope'), [('', None), ('?client_org=all', None),
                                                       ('?client_org=__unassigned__', '')])
def test_all_and_unassigned_scopes_are_preserved(governance, query, scope):
    g = governance
    g.handler.path = ROUTE + query
    assert g.request()[0] == 200
    assert g.store.set_endpoint_ai_governance.call_args.kwargs['client_org_id'] == scope
    g.registry.get_client_org.assert_not_called()


def test_session_scope_cannot_be_overridden_by_query(governance):
    g = governance
    g.user['client_org_id'] = 'org-a'
    g.handler.path = ROUTE + '?client_org=foreign-org'
    assert g.request()[0] == 200
    assert g.store.set_endpoint_ai_governance.call_args.kwargs['client_org_id'] == 'org-a'
    assert all(call.args == ('org-a',) for call in g.registry.get_client_org.call_args_list)


@pytest.mark.parametrize('target', ['missing', 'out-of-scope'])
def test_missing_and_out_of_scope_rows_return_same_404(governance, tmp_path, target):
    g = governance
    store = AgentStore(tmp_path / 'agents.db')
    row = add_tool(store, org='org-b')
    g.handler._store.return_value = store
    row_id = row['id'] if target == 'out-of-scope' else row['id'] + 1000
    assert g.request({'id': row_id, 'governance_status': 'restricted'}) == (
        404, {'error': 'Tool not found'})
    assert store.list_endpoint_ai_governance_audit() == []
    assert store.list_endpoint_ai_inventory()[0]['governance_override'] is None


def test_null_reset_removes_override_and_audits_session_actor(governance, tmp_path):
    g = governance
    store = AgentStore(tmp_path / 'agents.db')
    row = add_tool(store)
    g.handler._store.return_value = store
    for status in ('restricted', None):
        assert g.request({'id': row['id'], 'governance_status': status}) == (200, {'ok': True})
        updated = store.list_endpoint_ai_inventory()[0]
        assert updated['governance_override'] == status
        assert updated['governance_status'] == (status or 'shadow')
    audit = store.list_endpoint_ai_governance_audit('org-a')
    assert len(audit) == 2
    assert all(entry['changed_by'] == g.user['email'] for entry in audit)


@pytest.fixture
def fleet_page(monkeypatch, tmp_path):
    monkeypatch.setattr(server, 'ROOT', tmp_path)
    store = Mock()
    store.get_all_latest_reports.return_value = []
    monkeypatch.setattr(server, '_get_store', Mock(return_value=store))

    def render(role):
        return server._build_fleet_html(
            [], store=store, current_user_role=role,
            ai_inventory=[{'id': 7, 'tool_name': 'Claude Code',
                           'governance_status': 'restricted',
                           'governance_override': 'restricted'}])

    return render


@pytest.mark.parametrize('role', [*ADMIN_ROLES, '', 'viewer', 'client_viewer', 'user', 'msp_admin'])
def test_renderer_controls_are_only_for_admin_roles(fleet_page, role):
    page = fleet_page(role)
    allowed = role in ADMIN_ROLES
    assert ('aria-label="Governance policy"' in page) == allowed
    assert ('onclick="saveEndpointGovernance(this,7)"' in page) == allowed
    assert 'Organization policy' in page
    if allowed:
        assert '<option value="restricted" selected>' in page
        assert '<option value="">Use Agent Default</option>' in page


@pytest.mark.parametrize('can_manage', [False, True])
def test_tool_name_is_escaped_in_governance_rows(can_manage):
    name = '<img src=x onerror="alert(1)"> & \'tool\''
    rows = server._build_endpoint_ai_rows(
        [{'id': 7, 'tool_name': name}], 100, can_manage_governance=can_manage)
    assert name not in rows
    assert html.escape(name) in rows
    assert '<img' not in rows


def test_governance_javascript_retains_scope_and_sends_null_reset(fleet_page):
    page = fleet_page('admin')
    script = page.split('async function saveEndpointGovernance(', 1)[1].split(
        'function navTo(', 1)[0]
    assert "new URL('/api/fleet/ai-inventory/governance', window.location.origin)" in script
    assert "new URLSearchParams(window.location.search).get('client_org')" in script
    assert "url.searchParams.set('client_org', org)" in script
    assert 'fetch(url,' in script
    assert "method: 'POST'" in script
    assert 'JSON.stringify({id: id, governance_status: select.value || null})' in script


def test_post_route_requires_browser_auth_and_trusted_provenance(dashboard, monkeypatch):
    dispatch = Mock()
    monkeypatch.setattr(server._Handler, '_api_set_endpoint_ai_governance', dispatch)
    body = {'id': 7, 'governance_status': 'restricted'}
    response = dashboard.request('POST', ROUTE, body, {'Origin': dashboard.origin}, role=None)
    assert response.status == 401
    dispatch.assert_not_called()
    for headers in ({}, {'Origin': 'null'}, {'Origin': 'https://evil.test'},
                    [('Origin', dashboard.origin), ('Origin', 'https://evil.test')],
                    {'Authorization': 'Bearer arbitrary', 'Sec-Fetch-Site': 'same-origin'}):
        response = dashboard.request('POST', ROUTE, body, headers)
        assert response.status == 403
        assert json.loads(response.body) == {'error': 'untrusted_browser_origin'}
        dispatch.assert_not_called()

    # A trusted request must reach this exact handler, not merely fail earlier.
    def reached(handler):
        dispatch()
        handler._json({'ok': True})

    monkeypatch.setattr(server._Handler, '_api_set_endpoint_ai_governance', reached)
    for headers in ({'Origin': dashboard.origin}, {'Referer': dashboard.origin + '/fleet'}):
        response = dashboard.request('POST', ROUTE, body, headers)
        assert response.status == 200
        assert json.loads(response.body) == {'ok': True}
    assert dispatch.call_count == 2
