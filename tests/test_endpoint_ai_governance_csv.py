"""CSV export security, scope, and governance regression coverage."""

import csv
import io
from unittest.mock import Mock

import pytest

import server
from storage import AgentStore
from .test_endpoint_ai_governance_storage import add_tool
from .test_server_security_boundaries import dashboard


ROUTE = '/api/fleet/ai-inventory/csv'
COLUMNS = ['Tool', 'Category', 'Governance', 'Risk Score', 'Risk Band',
           'Running', 'Endpoint', 'Platform', 'Source', 'Install Path',
           'First Seen', 'Last Seen']


@pytest.fixture
def export():
    handler = server._Handler.__new__(server._Handler)
    handler._scoped_client_org = Mock(return_value='org-a')
    store = Mock()
    store.list_endpoint_ai_inventory.return_value = []
    handler._store = Mock(return_value=store)
    handler._json = Mock()
    handler.send_response = Mock()
    handler.send_header = Mock()
    handler.end_headers = Mock()
    handler.wfile = io.BytesIO()
    return handler


def records(handler):
    return list(csv.reader(io.StringIO(handler.wfile.getvalue().decode('utf-8'), newline='')))


def test_csv_route_uses_common_auth_and_scope_guards(dashboard, monkeypatch):
    reached = Mock()

    def dispatch(handler):
        reached()
        handler._json({'ok': True})

    monkeypatch.setattr(server._Handler, '_api_ai_inventory_csv', dispatch)
    response = dashboard.request('GET', ROUTE, role=None)
    assert response.status == 401
    reached.assert_not_called()
    for role in ('admin', 'customer_admin', 'super_admin', 'viewer'):
        assert dashboard.request('GET', ROUTE, role=role).status == 200
    reached.reset_mock()
    # A client_viewer without a valid pinned org must not reach the export.
    assert dashboard.request('GET', ROUTE, role='client_viewer').status == 403
    reached.assert_not_called()
    org = dashboard.registry.create_client_org(dashboard.customer['id'], 'Client A')
    user = dashboard.registry.create_user(
        dashboard.customer['id'], 'scoped@example.test', 'correct-password',
        role='client_viewer', client_org_id=org['id'])
    dashboard.cookies['client_viewer'] = 'sentinel_session=' + dashboard.registry.create_session(
        user['id'], dashboard.customer['id'], user['email'])
    assert dashboard.request('GET', ROUTE, role='client_viewer').status == 200
    reached.assert_called_once()


def test_scoped_snapshot_exports_all_rows_and_only_documented_columns(export):
    rows = [{'tool_name': f'Tool {i}', 'client_org_id': 'private-org',
             'device_id': 'private-device', 'risk_dimensions_json': 'secret'}
            for i in range(1001)]
    store = export._store.return_value
    store.list_endpoint_ai_inventory.return_value = rows
    export._api_ai_inventory_csv()
    store.list_endpoint_ai_inventory.assert_called_once_with(client_org_id='org-a', limit=None)
    result = records(export)
    assert result[0] == COLUMNS
    assert len(result) == 1002
    assert [row[0] for row in result[1:]] == [row['tool_name'] for row in rows]
    assert all(len(row) == len(COLUMNS) for row in result)
    assert b'private' not in export.wfile.getvalue()
    assert b'secret' not in export.wfile.getvalue()
    export.send_response.assert_called_once_with(200)
    headers = dict(c.args for c in export.send_header.call_args_list)
    assert headers['Content-Type'] == 'text/csv; charset=utf-8'
    assert headers['Content-Disposition'].startswith('attachment; filename="endpoint_ai_inventory_')
    assert int(headers['Content-Length']) == len(export.wfile.getvalue())


@pytest.mark.parametrize('value', ['=1+1', ' +SUM(A1)', '\n-1', '  @cmd',
                                  '\tplain', ' \rplain', '\t=1', '\r=1'])
@pytest.mark.parametrize('field,index', [('tool_name', 0), ('tool_category', 1),
    ('governance_status', 2), ('risk_score', 3), ('risk_band', 4), ('hostname', 6),
    ('platform', 7), ('source', 8), ('install_path', 9)])
def test_formula_cells_are_prefixed_without_changing_original_text(export, value, field, index):
    export._store.return_value.list_endpoint_ai_inventory.return_value = [{field: value}]
    export._api_ai_inventory_csv()
    assert records(export)[1][index] == "'" + value


def test_csv_quoting_unicode_numbers_and_dates(export):
    text = 'Tool, "quoted"\nsecond line \u00e9'
    export._store.return_value.list_endpoint_ai_inventory.return_value = [{
        'tool_name': text, 'risk_score': 81, 'running': True,
        'install_path': '/normal/path', 'first_seen': 1704067200}]
    export._api_ai_inventory_csv()
    row = records(export)[1]
    assert row[0] == text
    assert row[3] == '81'
    assert row[5] == 'yes'
    assert row[9:] == ['/normal/path', '2024-01-01 00:00 UTC', '']


def test_effective_governance_exported_from_real_store(export, tmp_path):
    store = AgentStore(tmp_path / 'agents.db')
    row = add_tool(store)
    add_tool(store, device='b1', org='org-b')
    add_tool(store, device='u1', org='', name='Unassigned tool')
    store.upsert_endpoint_ai_inventory('a1', 'a1', [
        {'tool_name': f'Tool {i}', 'governance_status': 'tolerated'}
        for i in range(600)])
    store.set_endpoint_ai_governance(row['id'], 'restricted', changed_by='operator',
                                    actor_role='admin', client_org_id='org-a')
    export._store.return_value = store
    export._api_ai_inventory_csv()
    result = records(export)
    assert len(result) == 602
    exported = {row[0]: row[2] for row in result[1:]}
    assert exported == {'Claude Code': 'restricted',
                        **{f'Tool {i}': 'tolerated' for i in range(600)}}
    assert store.list_endpoint_ai_inventory('org-a')[0]['reported_governance_status'] == 'shadow'


def test_session_scope_wins_over_query_in_real_csv_request(dashboard):
    org = dashboard.registry.create_client_org(dashboard.customer['id'], 'Client A')
    user = dashboard.registry.create_user(
        dashboard.customer['id'], 'scoped@example.test', 'correct-password',
        role='client_viewer', client_org_id=org['id'])
    dashboard.cookies['client_viewer'] = 'sentinel_session=' + dashboard.registry.create_session(
        user['id'], dashboard.customer['id'], user['email'])
    add_tool(dashboard.store, org=org['id'], name='Visible tool')
    add_tool(dashboard.store, device='b1', org='org-b', name='Hidden tool')
    response = dashboard.request('GET', ROUTE + '?client_org=all', role='client_viewer')
    assert response.status == 200
    result = list(csv.reader(io.StringIO(response.body.decode())))
    assert len(result) == 2
    assert result[1][0] == 'Visible tool'
    assert b'Hidden tool' not in response.body


@pytest.mark.parametrize('scope', [None, ''])
def test_all_and_unassigned_scopes_preserved(export, scope):
    export._scoped_client_org.return_value = scope
    export._api_ai_inventory_csv()
    export._store.return_value.list_endpoint_ai_inventory.assert_called_once_with(
        client_org_id=scope, limit=None)


def test_scope_failure_does_not_access_storage_or_disclose_details(export):
    export._scoped_client_org.side_effect = server._TenantScopeError('private scope detail')
    export._api_ai_inventory_csv()
    export._store.assert_not_called()
    export._json.assert_called_once_with({'error': 'invalid client-org scope'}, 403)
    assert not export.wfile.getvalue()


def test_storage_failure_is_confidential_and_not_partial(export):
    export._store.return_value.list_endpoint_ai_inventory.side_effect = RuntimeError('secret database path')
    export._api_ai_inventory_csv()
    export._json.assert_called_once_with({'error': 'internal server error'}, 500)
    export.send_response.assert_not_called()
    assert not export.wfile.getvalue()


@pytest.mark.parametrize('role', ['admin', 'viewer', 'client_viewer', None])
@pytest.mark.parametrize('method', ['_api_get_fleet_ai_inventory', '_api_get_fleet_ai_inventory_summary'])
def test_raw_feeds_deny_unprivileged_roles_before_storage(export, role, method):
    export._session_user = Mock(return_value={'role': role} if role else None)
    getattr(export, method)()
    export._json.assert_called_once_with({'error': 'forbidden'}, 403)
    export._store.assert_not_called()


def test_export_button_replaces_raw_json_link(dashboard):
    response = dashboard.request('GET', '/')
    assert response.status == 200
    assert b'href="/api/fleet/ai-inventory/csv" download' in response.body
    assert b'JSON API' not in response.body
    assert b'href="/api/fleet/ai-inventory"' not in response.body
