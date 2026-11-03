import sqlite3
import time
from collections import Counter

import pytest

from storage import AgentStore


def add_tool(store, device='a1', org='org-a', name='Claude Code', status='shadow'):
    store.upsert_report(device, device, {}, client_org_id=org)
    store.upsert_endpoint_ai_inventory(device, device, [{
        'tool_name': name, 'governance_status': status, 'running': True,
        'risk_score': 81, 'risk_band': 'CRITICAL',
        'risk_dimensions': {'data_sensitivity': 15},
    }])
    return next(row for row in store.list_endpoint_ai_inventory(limit=500)
                if row['device_id'] == device and row['tool_name'] == name)


@pytest.fixture
def store(tmp_path):
    return AgentStore(tmp_path / 'customer.db')


def test_exact_name_org_and_customer_isolation(store, tmp_path):
    target = add_tool(store)
    add_tool(store, 'a2', status='tolerated')
    add_tool(store, 'b1', 'org-b')
    add_tool(store, 'u1', '')
    for name in ('claude code', 'Claude Code Pro', 'Claude Code ', 'Claude%Code'):
        add_tool(store, name=name)
    other_customer = AgentStore(tmp_path / 'other-customer.db')
    add_tool(other_customer)

    assert store.set_endpoint_ai_governance(
        target['id'], 'sanctioned', 'admin@example.com', 'admin', 'org-a')
    for row in store.list_endpoint_ai_inventory():
        matches = row['client_org_id'] == 'org-a' and row['tool_name'] == 'Claude Code'
        assert row['governance_status'] == ('sanctioned' if matches else 'shadow')
        assert row['governance_override'] == ('sanctioned' if matches else None)
        assert row['reported_governance_status'] == (
            'tolerated' if row['device_id'] == 'a2' else 'shadow')
        assert row['risk_score'] == 81
        assert row['risk_band'] == 'CRITICAL'
        assert row['risk_dimensions_json'] == '{"data_sensitivity": 15}'
    assert other_customer.list_endpoint_ai_inventory()[0]['governance_status'] == 'shadow'
    assert other_customer.list_endpoint_ai_governance_audit() == []


def test_admin_scope_derives_target_org_and_unassigned_normalization(store):
    a = add_tool(store)
    b = add_tool(store, 'b', 'org-b')
    u = add_tool(store, 'u', '')
    add_tool(store, 'u-empty', '')
    store.set_device_client_org('u-empty', '')
    assert store.set_endpoint_ai_governance(b['id'], 'restricted', 'admin')
    assert store.set_endpoint_ai_governance(u['id'], 'tolerated', 'admin', client_org_id='')
    assert store.list_endpoint_ai_inventory('org-a')[0]['id'] == a['id']
    assert store.list_endpoint_ai_inventory('org-a')[0]['governance_override'] is None
    assert store.list_endpoint_ai_inventory('org-b')[0]['governance_status'] == 'restricted'
    unassigned = store.list_endpoint_ai_inventory('')
    assert len(unassigned) == store.count_endpoint_ai_inventory('') == 2
    assert all(row['governance_status'] == 'tolerated' for row in unassigned)
    assert store.list_endpoint_ai_inventory_summary('')['by_governance']['tolerated'] == 2
    assert store.list_endpoint_ai_governance_audit('')[0]['client_org_id'] == ''
    assert store.list_endpoint_ai_governance_audit('org-b')[0]['client_org_id'] == 'org-b'


def test_override_survives_ingestion_reopen_and_applies_to_future_rows(store):
    row = add_tool(store)
    assert store.set_endpoint_ai_governance(row['id'], 'restricted', 'admin')
    updated = add_tool(store, status='sanctioned')
    future = add_tool(store, 'a2', status='tolerated')
    reopened = AgentStore(store._path)
    assert updated['id'] == row['id']
    assert updated['reported_governance_status'] == 'sanctioned'
    assert future['reported_governance_status'] == 'tolerated'
    assert all(r['governance_status'] == 'restricted'
               for r in reopened.list_endpoint_ai_inventory())
    assert reopened.set_endpoint_ai_governance(row['id'], None, 'admin')
    rows = {r['device_id']: r for r in reopened.list_endpoint_ai_inventory()}
    assert rows['a1']['governance_status'] == 'sanctioned'
    assert rows['a2']['governance_status'] == 'tolerated'
    assert all(r['governance_override'] is None for r in rows.values())
    with reopened._conn() as conn:
        assert conn.execute('SELECT COUNT(*) FROM endpoint_ai_governance_overrides').fetchone()[0] == 0


@pytest.mark.parametrize('scope', [None, '', 'org-a', 'org-b', 'missing'])
def test_summary_matches_effective_list_without_risk_or_pagination_changes(store, scope):
    row = add_tool(store)
    add_tool(store, 'a2', status='sanctioned')
    add_tool(store, 'b', 'org-b', status='restricted')
    add_tool(store, 'u', '', status='tolerated')
    before = store.list_endpoint_ai_inventory_summary(scope)
    store.set_endpoint_ai_governance(row['id'], 'tolerated', 'admin')
    rows = store.list_endpoint_ai_inventory(scope)
    summary = store.list_endpoint_ai_inventory_summary(scope)
    counts = Counter(r['governance_status'] for r in rows)
    assert summary['total'] == len(rows) == store.count_endpoint_ai_inventory(scope)
    assert summary['running'] == before['running']
    assert summary['by_risk_band'] == before['by_risk_band']
    assert summary['by_governance'] == {
        status: counts[status] for status in ('sanctioned', 'tolerated', 'shadow', 'restricted')}
    assert len(store.list_endpoint_ai_inventory(scope, limit=1)) == min(1, len(rows))
    assert len(store.list_endpoint_ai_inventory(scope, limit=1, offset=1)) == min(1, max(0, len(rows) - 1))


def test_full_snapshot_preserves_scoping_order_and_integer_pagination(store):
    target = add_tool(store)
    add_tool(store, 'b1', 'org-b')
    add_tool(store, 'u1', '')
    store.upsert_endpoint_ai_inventory('a1', 'a1', [
        {'tool_name': f'Tool {i}', 'governance_status': 'shadow', 'risk_score': i % 3}
        for i in range(600)])
    assert store.set_endpoint_ai_governance(target['id'], 'restricted', 'admin')
    with store._conn() as conn:
        conn.execute('UPDATE endpoint_ai_inventory SET last_seen=id % 2')

    rows = store.list_endpoint_ai_inventory('org-a', limit=None)
    assert len(rows) == 601
    assert all(row['client_org_id'] == 'org-a' for row in rows)
    assert rows == sorted(rows, key=lambda row: (-row['risk_score'], -row['last_seen'], row['id']))
    assert rows[0]['governance_status'] == 'restricted'
    assert rows[0]['reported_governance_status'] == 'shadow'
    assert store.list_endpoint_ai_inventory('org-a', limit=None, offset=500) == rows
    assert store.list_endpoint_ai_inventory('org-a') == rows[:200]
    assert store.list_endpoint_ai_inventory('org-a', limit=1000) == rows[:500]
    assert store.list_endpoint_ai_inventory('org-a', limit=500, offset=500) == rows[500:]
    assert store.list_endpoint_ai_inventory('org-a', limit=0, offset=-1) == rows[:1]
    assert len(store.list_endpoint_ai_inventory(limit=None)) == 603
    assert len(store.list_endpoint_ai_inventory('', limit=None)) == 1
    assert store.list_endpoint_ai_inventory('missing', limit=None) == []


def test_audit_records_policy_transitions_actor_scope_order_and_limit(store):
    a = add_tool(store)
    b = add_tool(store, 'b', 'org-b')
    start = int(time.time())
    for status in ('sanctioned', 'restricted', None):
        assert store.set_endpoint_ai_governance(a['id'], status, 'operator', 'admin', 'org-a')
    assert store.set_endpoint_ai_governance(b['id'], 'tolerated', 'other', 'msp_admin')
    audit = store.list_endpoint_ai_governance_audit('org-a')
    assert [(e['old_status'], e['new_status']) for e in audit] == [
        ('restricted', None), ('sanctioned', 'restricted'), (None, 'sanctioned')]
    for event in audit:
        assert event['inventory_id'] == a['id']
        assert event['client_org_id'] == 'org-a'
        assert event['tool_name'] == 'Claude Code'
        assert event['changed_by'] == 'operator'
        assert event['actor_role'] == 'admin'
        assert start <= event['changed_at'] <= int(time.time())
    assert len(store.list_endpoint_ai_governance_audit()) == 4
    assert store.list_endpoint_ai_governance_audit(limit=1)[0]['client_org_id'] == 'org-b'
    assert store.list_endpoint_ai_governance_audit('org-a', limit=1) == audit[:1]
    assert store.list_endpoint_ai_governance_audit('') == []


@pytest.mark.parametrize('target_org,scope', [
    ('org-a', 'org-b'), ('org-a', ''), ('', 'org-a')])
def test_out_of_scope_and_missing_rows_write_nothing(store, target_org, scope):
    row = add_tool(store, org=target_org)
    store.set_endpoint_ai_governance(row['id'], 'restricted', 'admin')
    before = store.list_endpoint_ai_inventory()
    audit = store.list_endpoint_ai_governance_audit()
    with store._conn() as conn:
        changes = conn.execute('PRAGMA data_version').fetchone()[0]
        for status in ('sanctioned', None):
            assert not store.set_endpoint_ai_governance(row['id'], status, 'intruder', client_org_id=scope)
            assert not store.set_endpoint_ai_governance(999999, status, 'intruder')
        assert conn.execute('PRAGMA data_version').fetchone()[0] == changes
    assert store.list_endpoint_ai_inventory() == before
    assert store.list_endpoint_ai_governance_audit() == audit


@pytest.mark.parametrize('inventory_id', [0, -1, True, 1.0, '1', None, 2**63])
def test_invalid_row_ids_rejected(store, inventory_id):
    add_tool(store)
    with pytest.raises(ValueError):
        store.set_endpoint_ai_governance(inventory_id, 'sanctioned', 'admin')
    assert store.list_endpoint_ai_governance_audit() == []


@pytest.mark.parametrize('status', ['', 'approved', 'SANCTIONED', [], {}, True, 1])
def test_invalid_statuses_rejected(store, status):
    row = add_tool(store)
    with pytest.raises(ValueError):
        store.set_endpoint_ai_governance(row['id'], status, 'admin')
    assert store.list_endpoint_ai_inventory()[0]['governance_override'] is None
    assert store.list_endpoint_ai_governance_audit() == []


@pytest.mark.parametrize('status', ['sanctioned', None])
def test_audit_failure_rolls_back_policy_change(store, status):
    row = add_tool(store)
    store.set_endpoint_ai_governance(row['id'], 'restricted', 'admin')
    audit = store.list_endpoint_ai_governance_audit()
    with store._conn() as conn:
        conn.execute("""CREATE TRIGGER reject_governance_audit
            BEFORE INSERT ON endpoint_ai_governance_audit BEGIN
            SELECT RAISE(ABORT, 'audit failure'); END""")
    with pytest.raises(sqlite3.IntegrityError, match='audit failure'):
        store.set_endpoint_ai_governance(row['id'], status, 'admin')
    assert store.list_endpoint_ai_inventory()[0]['governance_override'] == 'restricted'
    assert store.list_endpoint_ai_governance_audit() == audit


def test_device_reassignment_uses_current_org_without_moving_policy(store):
    row = add_tool(store)
    store.set_endpoint_ai_governance(row['id'], 'sanctioned', 'admin')
    store.set_device_client_org('a1', 'org-b')
    assert store.list_endpoint_ai_inventory()[0]['governance_override'] is None
    assert not store.set_endpoint_ai_governance(row['id'], 'restricted', 'admin', client_org_id='org-a')
    assert store.set_endpoint_ai_governance(row['id'], 'tolerated', 'admin', client_org_id='org-b')
    store.set_device_client_org('a1', 'org-a')
    assert store.list_endpoint_ai_inventory()[0]['governance_status'] == 'sanctioned'
