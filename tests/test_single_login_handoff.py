"""Single-login routing through the real HTTP handler, without bcrypt fixtures."""

import http.client
import json
import threading
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.parse import parse_qs, urlencode, urlparse

import pytest

import server


@pytest.fixture
def dashboard(monkeypatch):
    for name in ('SENTINEL_TRUSTED_PROXY', 'SENTINEL_TRUSTED_PROXY_TOKEN',
                 'SENTINEL_TRUSTED_PROXY_TOKEN_FILE', 'PUBLIC_ADMIN_URL', 'PUBLIC_DASHBOARD_URL'):
        monkeypatch.delenv(name, raising=False)
    registry = Mock()
    registry.has_customers.return_value = True
    registry.get_session.return_value = None
    registry.authenticate_user.return_value = None
    monkeypatch.setattr(server, '_get_registry', lambda: registry)
    monkeypatch.setattr(server, '_login_allowed', lambda ip: True)
    monkeypatch.setattr(server, '_login_failed', lambda ip: None)
    httpd = server.http.server.ThreadingHTTPServer(('127.0.0.1', 0), server._Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    origin = f'http://localhost:{httpd.server_port}'

    def request(method='GET', path='/login', body=None, headers=None):
        conn = http.client.HTTPConnection('127.0.0.1', httpd.server_port, timeout=5)
        conn.request(method, path, body=body, headers=headers or {})
        response = conn.getresponse()
        result = SimpleNamespace(status=response.status, headers=dict(response.getheaders()), body=response.read())
        conn.close()
        return result

    yield SimpleNamespace(request=request, registry=registry, origin=origin)
    httpd.shutdown()
    httpd.server_close()
    thread.join()


def cloud(monkeypatch, dashboard):
    monkeypatch.setenv('SENTINEL_TRUSTED_PROXY_TOKEN', 'proxy-secret')
    dashboard.registry.has_customers.return_value = False


@pytest.fixture(params=['missing', 'empty', 'unreadable'])
def unavailable_proxy_secret(request, monkeypatch, dashboard, tmp_path):
    token_file = tmp_path / 'proxy-token'
    monkeypatch.setenv('SENTINEL_TRUSTED_PROXY_TOKEN_FILE', str(token_file))
    if request.param == 'empty':
        monkeypatch.setattr(server.Path, 'read_text', Mock(return_value=' \n'))
    elif request.param == 'unreadable':
        monkeypatch.setattr(server.Path, 'read_text', Mock(side_effect=OSError('Cannot read proxy secret')))
    assert server._proxy_auth_configured()
    assert server._trusted_proxy_token() == ''


def assert_handoff(response, next_url='https://arckon.riskraven.ai/', admin='https://admin.riskraven.ai', status=302):
    assert response.status == status
    assert response.headers['Content-Length'] == '0'
    location = urlparse(response.headers['Location'])
    assert location.scheme + '://' + location.netloc + location.path == admin + '/login'
    assert parse_qs(location.query) == {'next': [next_url]}
    assert b'<form' not in response.body
    assert 'Set-Cookie' not in response.headers


@pytest.mark.parametrize('headers', [
    {}, {'X-Sentinel-Proxy-Token': 'proxy-secret'},
    {'X-Sentinel-User-Email': 'spoof@example.test'},
    {'X-Sentinel-Proxy-Token': 'wrong', 'X-Sentinel-User-Email': 'spoof@example.test'},
    {'Cookie': 'sentinel_session=stale'},
])
def test_cloud_empty_registry_never_local_login_or_setup(dashboard, monkeypatch, headers):
    cloud(monkeypatch, dashboard)
    assert_handoff(dashboard.request(headers=headers))
    assert dashboard.registry.mock_calls == []


def test_cloud_canonical_handoff_ignores_request_hosts(dashboard, monkeypatch):
    cloud(monkeypatch, dashboard)
    monkeypatch.setenv('PUBLIC_ADMIN_URL', 'https://control.example.test/')
    monkeypatch.setenv('PUBLIC_DASHBOARD_URL', 'https://dashboard.example.test:8443/')
    response = dashboard.request(path='/login?' + urlencode({'next': '/clients?view=mine&sort=name'}), headers={
        'Host': 'evil.test', 'X-Forwarded-Host': 'evil.test', 'X-Forwarded-Proto': 'http'})
    assert_handoff(response, 'https://dashboard.example.test:8443/clients?view=mine&sort=name',
                   'https://control.example.test')
    assert dashboard.registry.mock_calls == []


def test_trusted_identity_skips_registry_and_does_not_expand_privilege(dashboard, monkeypatch):
    cloud(monkeypatch, dashboard)
    headers = {'X-Sentinel-Proxy-Token': 'proxy-secret', 'X-Sentinel-User-Email': 'viewer@example.test',
               'X-Sentinel-Customer-ID': 'tenant', 'X-Sentinel-Client-Org-ID': 'org'}
    response = dashboard.request(path='/login?next=/clients', headers=headers)
    assert response.status == 302
    assert response.headers['Location'] == '/clients'
    assert 'Set-Cookie' not in response.headers
    response = dashboard.request(path='/api/auth/me', headers=headers)
    assert response.status == 200
    user = json.loads(response.body)
    assert user == {'email': 'viewer@example.test', 'role': 'client_viewer', 'customer_id': 'tenant'}
    assert dashboard.registry.mock_calls == []
    dashboard.registry.get_client_org.return_value = {'active': True, 'customer_id': 'tenant'}
    assert dashboard.request(path='/clients', headers=headers).status == 403
    dashboard.registry.get_client_org.assert_called_with('org')


@pytest.mark.parametrize('trusted', [False, True])
def test_cloud_post_never_authenticates_or_creates_local_session(dashboard, monkeypatch, trusted):
    cloud(monkeypatch, dashboard)
    headers = {'Origin': 'https://arckon.riskraven.ai'}
    if trusted:
        headers.update({'X-Sentinel-Proxy-Token': 'proxy-secret', 'X-Sentinel-User-Email': 'viewer@example.test'})
    dashboard.registry.authenticate_user.side_effect = AssertionError('local credentials processed')
    response = dashboard.request('POST', '/login?next=/clients',
                                 'email=local&password=secret&next=//evil.test', headers)
    assert_handoff(response, 'https://arckon.riskraven.ai/clients', status=303)
    assert dashboard.registry.mock_calls == []


def test_repeated_cloud_posts_return_complete_empty_redirects(dashboard, monkeypatch):
    cloud(monkeypatch, dashboard)
    for _ in range(20):
        for path in ('/login', '/setup'):
            response = dashboard.request('POST', path, 'email=local&password=secret',
                                         {'Origin': 'https://arckon.riskraven.ai'})
            assert_handoff(response, status=303)
            assert response.body == b''
    assert dashboard.registry.mock_calls == []


def test_cloud_post_keeps_browser_provenance_gate(dashboard, monkeypatch):
    cloud(monkeypatch, dashboard)
    for headers in ({}, {'Origin': 'https://evil.test'}):
        assert dashboard.request('POST', '/login', 'email=local&password=secret', headers).status == 403
    assert dashboard.registry.mock_calls == []


@pytest.mark.parametrize('name', ['PUBLIC_ADMIN_URL', 'PUBLIC_DASHBOARD_URL'])
@pytest.mark.parametrize('value', ['', 'http://insecure.test', '//evil.test', 'https://user@host.test',
                                    'https://host.test:bad', 'https://host.test/path',
                                    'https://host.test?next=bad', 'https://host.test/#bad',
                                    'https://host.test\\evil', 'https://host.test\n'])
def test_invalid_cloud_urls_fail_closed(dashboard, monkeypatch, name, value):
    cloud(monkeypatch, dashboard)
    monkeypatch.setenv(name, value)
    origin = 'https://arckon.riskraven.ai' if name == 'PUBLIC_ADMIN_URL' else 'https://admin.riskraven.ai'
    for method in ('GET', 'POST'):
        response = dashboard.request(method, headers={'Origin': origin})
        assert response.status == 503
        assert 'Location' not in response.headers
        assert 'Set-Cookie' not in response.headers
        assert b'<form' not in response.body
    assert dashboard.registry.mock_calls == []


def test_cloud_dashboard_and_direct_setup_never_offer_local_setup(dashboard, monkeypatch):
    cloud(monkeypatch, dashboard)
    assert_handoff(dashboard.request(path='/clients'), 'https://arckon.riskraven.ai/clients')
    assert_handoff(dashboard.request(path='/setup'))
    assert_handoff(dashboard.request('POST', '/setup', 'email=local&password=secret'), status=303)
    assert dashboard.registry.mock_calls == []


@pytest.mark.parametrize('has_customers', [False, True])
@pytest.mark.parametrize('path', ['/login', '/setup'])
@pytest.mark.parametrize('method', ['GET', 'POST'])
def test_unavailable_proxy_secret_never_allows_local_auth(
        dashboard, unavailable_proxy_secret, has_customers, path, method):
    dashboard.registry.has_customers.return_value = has_customers
    response = dashboard.request(method, path,
                                 'company=Local&email=local%40example.test&password=secret123&confirm=secret123',
                                 {'Origin': dashboard.origin})
    assert response.status == 503
    assert 'Location' not in response.headers
    assert 'Set-Cookie' not in response.headers
    assert b'<form' not in response.body
    assert dashboard.registry.mock_calls == []


def test_unavailable_proxy_secret_rejects_existing_legacy_session(dashboard, unavailable_proxy_secret):
    dashboard.registry.get_session.return_value = {
        'email': 'local@example.test', 'role': 'admin', 'customer_id': 'tenant'}
    response = dashboard.request(path='/api/auth/me', headers={'Cookie': 'sentinel_session=existing'})
    assert response.status == 401
    assert 'Location' not in response.headers
    assert 'Set-Cookie' not in response.headers
    assert dashboard.registry.mock_calls == []


@pytest.mark.parametrize('value', ['//evil.test', 'https://evil.test', '/%2fevil.test', '/%252fevil.test',
                                    '/\\evil.test', '/%5cevil.test', '/%255cevil.test',
                                    '/%0d%0aLocation:evil', '/%2500bad', '/\x7fbad',
                                    '/login', '/logout?next=/clients', '/setup/', '/%256cogin',
                                    '/LOGIN', '/login;anything', '/clients/../login'])
def test_unsafe_returns_rejected_in_cloud_and_local(dashboard, monkeypatch, value):
    path = '/login?' + urlencode({'next': value})
    response = dashboard.request(path=path)
    assert response.status == 200
    assert b'name="next" value="/"' in response.body
    dashboard.registry.authenticate_user.return_value = {'id': 'user', 'customer_id': 'tenant', 'email': 'a@test'}
    dashboard.registry.create_session.return_value = 'local-token'
    response = dashboard.request('POST', '/login', urlencode({'next': value}), {'Origin': dashboard.origin})
    assert response.headers['Location'] == '/'
    cloud(monkeypatch, dashboard)
    assert_handoff(dashboard.request(path=path))
    response = dashboard.request(path=path, headers={
        'X-Sentinel-Proxy-Token': 'proxy-secret', 'X-Sentinel-User-Email': 'viewer@example.test'})
    assert response.headers['Location'] == '/'


def test_local_form_setup_session_and_credentials_preserved(dashboard):
    response = dashboard.request(path='/login?next=/clients')
    assert response.status == 200
    assert b'<form method="POST" action="/login">' in response.body
    assert b'name="next" value="/clients"' in response.body
    dashboard.registry.has_customers.return_value = False
    response = dashboard.request()
    assert response.status == 302
    assert response.headers['Location'] == '/setup'
    dashboard.registry.get_session.return_value = {'role': 'viewer'}
    response = dashboard.request(path='/login?next=/clients', headers={'Cookie': 'sentinel_session=existing'})
    assert response.headers['Location'] == '/clients'
    dashboard.registry.get_session.assert_called_with('existing')
    dashboard.registry.authenticate_user.return_value = {'id': 'user', 'customer_id': 'tenant', 'email': 'a@test'}
    dashboard.registry.create_session.return_value = 'local-token'
    response = dashboard.request('POST', '/login', 'email=a%40test&password=secret&next=/clients',
                                 {'Origin': dashboard.origin})
    assert response.status == 302
    assert response.headers['Location'] == '/clients'
    assert response.headers['Set-Cookie'] == 'sentinel_session=local-token; Path=/; HttpOnly; SameSite=Strict'
    dashboard.registry.authenticate_user.assert_called_once_with('a@test', 'secret')
    dashboard.registry.create_session.assert_called_once_with('user', 'tenant', 'a@test')


def test_local_invalid_credentials_still_return_to_login(dashboard):
    response = dashboard.request('POST', '/login', 'email=a%40test&password=bad&next=/clients',
                                 {'Origin': dashboard.origin})
    assert response.status == 302
    assert response.headers['Location'] == '/login?next=/clients&error=1'
    dashboard.registry.create_session.assert_not_called()
