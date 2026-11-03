"""Real HTTP governance lifecycle with registry sessions and SQLite storage."""

import csv
import io
import json
from urllib.parse import urlencode

import server
from .test_endpoint_ai_governance_storage import add_tool
from .test_server_security_boundaries import dashboard


def test_governance_http_lifecycle_and_scoped_dashboard(dashboard, monkeypatch):
    store = dashboard.store
    monkeypatch.setattr(server._Handler, '_store', lambda self: store)
    org = dashboard.registry.create_client_org(dashboard.customer['id'], 'Client A')
    other_org = dashboard.registry.create_client_org(dashboard.customer['id'], 'Client B')
    target = add_tool(store, org=org['id'])
    add_tool(store, device='a2', org=org['id'], status='tolerated')
    add_tool(store, device='b1', org=other_org['id'])
    add_tool(store, device='u1', org='')
    query = '?' + urlencode({'client_org': org['id']})
    route = '/api/fleet/ai-inventory/governance' + query
    headers = {'Origin': dashboard.origin}
    before_summary = store.list_endpoint_ai_inventory_summary(org['id'])

    response = dashboard.request('POST', route, {
        'id': target['id'], 'governance_status': 'restricted',
    }, headers, role='admin')
    assert response.status == 200
    assert json.loads(response.body) == {'ok': True}
    rows = store.list_endpoint_ai_inventory(org['id'])
    assert len(rows) == 2
    assert {row['governance_status'] for row in rows} == {'restricted'}
    assert {row['governance_override'] for row in rows} == {'restricted'}
    assert {row['reported_governance_status'] for row in rows} == {'shadow', 'tolerated'}
    summary = store.list_endpoint_ai_inventory_summary(org['id'])
    assert summary['total'] == summary['running'] == 2
    assert summary['by_governance'] == {
        'sanctioned': 0, 'tolerated': 0, 'shadow': 0, 'restricted': 2,
    }
    assert summary['by_risk_band'] == before_summary['by_risk_band']
    audit = store.list_endpoint_ai_governance_audit(org['id'])
    assert len(audit) == 1
    event = audit[0]
    assert event['inventory_id'] == target['id']
    assert event['client_org_id'] == org['id']
    assert event['tool_name'] == 'Claude Code'
    assert event['old_status'] is None
    assert event['new_status'] == 'restricted'
    assert event['changed_by'] == 'admin@example.test'
    assert event['actor_role'] == 'admin'

    updated = add_tool(store, org=org['id'], status='sanctioned')
    assert updated['id'] == target['id']
    assert updated['reported_governance_status'] == 'sanctioned'
    assert updated['governance_status'] == updated['governance_override'] == 'restricted'
    assert store.list_endpoint_ai_inventory_summary(org['id']) == summary
    assert store.list_endpoint_ai_governance_audit(org['id']) == audit
    for scope in (other_org['id'], ''):
        outside = store.list_endpoint_ai_inventory(scope)
        assert len(outside) == 1
        assert outside[0]['governance_status'] == 'shadow'
        assert outside[0]['governance_override'] is None
        assert store.list_endpoint_ai_governance_audit(scope) == []

    response = dashboard.request('GET', '/api/fleet/ai-inventory/csv' + query, role='admin')
    assert response.status == 200
    assert response.headers['Content-Type'] == 'text/csv; charset=utf-8'
    exported = list(csv.DictReader(io.StringIO(response.body.decode('utf-8'))))
    assert len(exported) == 2
    assert {row['Endpoint'] for row in exported} == {'a1', 'a2'}
    assert {row['Tool'] for row in exported} == {'Claude Code'}
    assert {row['Governance'] for row in exported} == {'restricted'}

    before_viewer = store.list_endpoint_ai_inventory(org['id'])
    response = dashboard.request('POST', route, {
        'id': target['id'], 'governance_status': 'sanctioned',
    }, headers, role='viewer')
    assert response.status == 403
    assert json.loads(response.body) == {'error': 'forbidden'}
    assert store.list_endpoint_ai_inventory(org['id']) == before_viewer
    assert all(row['governance_status'] == 'restricted'
               for row in store.list_endpoint_ai_inventory(org['id']))
    assert store.list_endpoint_ai_governance_audit(org['id']) == audit

    response = dashboard.request('GET', '/' + query, role='admin')
    assert response.status == 200
    page = response.body.decode('utf-8')
    assert 'Dashboard temporarily unavailable' not in page
    assert 'aria-label="Governance policy"' in page
    assert f'onclick="saveEndpointGovernance(this,{target["id"]})"' in page
    assert '<option value="restricted" selected>' in page
    assert '<option value="">Use Agent Default</option>' in page
    audit_html = page.split('Recent Governance Changes (latest 50)', 1)[1].split('</details>', 1)[0]
    for value in ('Claude Code', org['id'], 'admin@example.test', 'Agent default', 'restricted'):
        assert value in audit_html

    response = dashboard.request('POST', route, {
        'id': target['id'], 'governance_status': None,
    }, headers, role='admin')
    assert response.status == 200
    assert json.loads(response.body) == {'ok': True}
    rows = {row['device_id']: row for row in store.list_endpoint_ai_inventory(org['id'])}
    assert rows['a1']['governance_status'] == 'sanctioned'
    assert rows['a2']['governance_status'] == 'tolerated'
    assert all(row['governance_override'] is None for row in rows.values())
    summary = store.list_endpoint_ai_inventory_summary(org['id'])
    assert summary['by_governance'] == {
        'sanctioned': 1, 'tolerated': 1, 'shadow': 0, 'restricted': 0,
    }
    audit = store.list_endpoint_ai_governance_audit(org['id'])
    assert len(audit) == 2
    assert audit[0]['old_status'] == 'restricted'
    assert audit[0]['new_status'] is None
    assert audit[0]['changed_by'] == 'admin@example.test'
    assert audit[0]['actor_role'] == 'admin'
    response = dashboard.request('GET', '/api/fleet/ai-inventory/csv' + query, role='admin')
    assert response.status == 200
    exported = list(csv.DictReader(io.StringIO(response.body.decode('utf-8'))))
    assert {row['Endpoint']: row['Governance'] for row in exported} == {
        'a1': 'sanctioned', 'a2': 'tolerated',
    }
