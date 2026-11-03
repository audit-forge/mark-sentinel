"""The fleet AI summary must never fall through into agent event ingestion."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import server


@pytest.fixture
def summary_endpoint(monkeypatch):
    store = Mock()
    store.list_endpoint_ai_inventory_summary.return_value = {
        'total': 2, 'by_governance': {'shadow': 2}, 'by_risk_band': {'HIGH': 2}}
    agent_store = Mock()
    get_agent_store = Mock(return_value=agent_store)
    monkeypatch.setattr(server, '_get_store', get_agent_store)
    handler = server._Handler.__new__(server._Handler)
    handler._session_user = Mock(return_value={'role': 'customer_admin'})
    handler._scoped_client_org = Mock(return_value='org-a')
    handler._store = Mock(return_value=store)
    handler._json = Mock()
    handler._send = Mock()
    handler.rfile = Mock()
    handler._read_json_body = Mock(return_value={'events': [{'device_id': 'device-a'}]})
    handler._get_agent_customer = Mock(return_value={'id': 'agent-customer'})

    yield SimpleNamespace(handler=handler, store=store)

    handler._read_json_body.assert_not_called()
    assert handler.rfile.mock_calls == []
    handler._get_agent_customer.assert_not_called()
    get_agent_store.assert_not_called()
    assert agent_store.mock_calls == []
    store.ingest_access_events.assert_not_called()
    handler._send.assert_not_called()


@pytest.mark.parametrize('role', ['customer_admin', 'super_admin'])
@pytest.mark.parametrize('scope', ['org-a', None, ''])
def test_summary_success_returns_one_json_response_without_ingestion(summary_endpoint, role, scope):
    h, store = summary_endpoint.handler, summary_endpoint.store
    h._session_user.return_value = {'role': role}
    h._scoped_client_org.return_value = scope

    h._api_get_fleet_ai_inventory_summary()

    h._json.assert_called_once_with(store.list_endpoint_ai_inventory_summary.return_value)
    h._store.assert_called_once_with()
    h._scoped_client_org.assert_called_once_with()
    store.list_endpoint_ai_inventory_summary.assert_called_once_with(client_org_id=scope)
    assert len(store.mock_calls) == 1


@pytest.mark.parametrize('failure', ['store', 'query'])
def test_summary_error_returns_one_json_response_without_ingestion(summary_endpoint, failure):
    h, store = summary_endpoint.handler, summary_endpoint.store
    if failure == 'store':
        h._store.side_effect = RuntimeError('private store details')
    else:
        store.list_endpoint_ai_inventory_summary.side_effect = RuntimeError('private query details')

    h._api_get_fleet_ai_inventory_summary()

    h._json.assert_called_once_with({'error': 'internal server error'}, 500)
    h._store.assert_called_once_with()
    if failure == 'store':
        assert store.mock_calls == []
    else:
        store.list_endpoint_ai_inventory_summary.assert_called_once_with(client_org_id='org-a')


def test_scope_error_fails_closed_without_query_or_ingestion(summary_endpoint):
    h, store = summary_endpoint.handler, summary_endpoint.store
    h._scoped_client_org.side_effect = server._TenantScopeError('invalid scope')

    h._api_get_fleet_ai_inventory_summary()

    h._json.assert_called_once_with({'error': 'internal server error'}, 500)
    h._scoped_client_org.assert_called_once_with()
    assert store.mock_calls == []


@pytest.mark.parametrize('user', [None, {'role': 'viewer'}, {'role': 'admin'}])
def test_unauthorized_summary_returns_one_response_before_scope_or_store(summary_endpoint, user):
    h, store = summary_endpoint.handler, summary_endpoint.store
    h._session_user.return_value = user

    h._api_get_fleet_ai_inventory_summary()

    h._json.assert_called_once_with({'error': 'forbidden'}, 403)
    h._scoped_client_org.assert_not_called()
    h._store.assert_not_called()
    assert store.mock_calls == []
