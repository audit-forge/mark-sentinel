"""HTTP regression coverage using real registry sessions and admin middleware."""

import http.client
import io
import json
import threading
import urllib.error
from types import SimpleNamespace

import pytest

import server
from storage import AgentStore, CustomerRegistry
from .test_browser_security import admin  # Reuse the isolated real ASGI admin fixture.


@pytest.mark.parametrize('mounted', [False, True])
def test_license_uses_private_data_unless_customer_mount_exists(tmp_path, monkeypatch, mounted):
    import license

    monkeypatch.setattr(server, 'ROOT', tmp_path)
    local = tmp_path / 'data' / 'license.json'
    local.parent.mkdir()
    local.write_text('{}')
    root = tmp_path / 'license.json'
    if mounted:
        root.write_text('{}')
    paths = []
    monkeypatch.setattr(license, 'load_license', paths.append)
    server._load_license()
    assert paths == [root if mounted else local]


@pytest.fixture
def dashboard(monkeypatch, tmp_path):
    for name in ('SENTINEL_TRUSTED_PROXY', 'SENTINEL_TRUSTED_PROXY_TOKEN',
                 'SENTINEL_TRUSTED_PROXY_TOKEN_FILE', 'SENTINEL_AGENT_TOKEN',
                 'SENTINEL_AGENT_TOKEN_FILE', 'PUBLIC_ADMIN_URL', 'PUBLIC_DASHBOARD_URL'):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv('ARCKON_MASTER_KEY', 'ab' * 32)
    monkeypatch.delenv('ARCKON_MASTER_KEY_FILE', raising=False)
    monkeypatch.setattr(server, 'ROOT', tmp_path)
    registry = CustomerRegistry(tmp_path / 'data' / 'customers.db')
    customer = registry.create_customer('Boundary Tenant')
    store = AgentStore(tmp_path / 'data' / 'agents.db')
    monkeypatch.setattr(server, '_get_registry', lambda: registry)
    monkeypatch.setattr(server, '_get_store', lambda *args: store)
    cookies = {}
    for role in ('admin', 'customer_admin', 'super_admin', 'viewer', 'client_viewer'):
        user = registry.create_user(customer['id'], role + '@example.test', 'correct-password', role=role)
        cookies[role] = 'sentinel_session=' + registry.create_session(user['id'], customer['id'], user['email'])
    httpd = server.http.server.ThreadingHTTPServer(('127.0.0.1', 0), server._Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    origin = f'http://localhost:{httpd.server_port}'

    def request(method, path, body=None, headers=(), role='admin'):
        pairs = list(headers.items()) if isinstance(headers, dict) else list(headers)
        if role is not None:
            pairs.append(('Cookie', cookies[role]))
        if isinstance(body, dict):
            body = json.dumps(body).encode()
            pairs.append(('Content-Type', 'application/json'))
        if isinstance(body, str):
            body = body.encode()
        conn = http.client.HTTPConnection('127.0.0.1', httpd.server_port, timeout=10)
        conn.putrequest(method, path)
        for key, value in pairs:
            conn.putheader(key, value)
        conn.putheader('Content-Length', str(len(body or b'')))
        conn.endheaders(body)
        response = conn.getresponse()
        result = SimpleNamespace(status=response.status, headers=dict(response.getheaders()), body=response.read())
        conn.close()
        return result

    yield SimpleNamespace(request=request, origin=origin, root=tmp_path, registry=registry,
                          customer=customer, cookies=cookies, store=store)
    httpd.shutdown()
    httpd.server_close()
    thread.join()


@pytest.mark.parametrize('headers', [
    [], [('Origin', 'null')], [('Origin', 'https://evil.test')],
    [('Origin', 'https://arckon.riskraven.ai.evil.test')],
    [('Origin', 'https://arckon.riskraven.ai/')],
    [('Origin', 'https://arckon.riskraven.ai'), ('Origin', 'https://evil.test')],
    [('Referer', 'https://evil.test@arckon.riskraven.ai/')],
    [('Origin', 'null'), ('Referer', 'https://arckon.riskraven.ai/')],
    [('Authorization', 'Bearer arbitrary'), ('X-Forwarded-Host', 'arckon.riskraven.ai')],
])
def test_dashboard_mutations_reject_untrusted_provenance(dashboard, headers):
    response = dashboard.request('POST', '/api/config', {'target': 'changed'}, headers)
    assert response.status == 403
    assert json.loads(response.body) == {'error': 'untrusted_browser_origin'}
    assert response.headers['Cache-Control'] == 'no-store'
    assert not (dashboard.root / 'agent_config.json').exists()


def test_config_allowlist_and_preserved_credentials(dashboard):
    path = dashboard.root / 'agent_config.json'
    original = dict(profile='default', target='/original', interval=60, extra_subnets=[],
                    server='https://server.test', token='persisted-secret', api_key='private', future_secret='hidden')
    path.write_text(json.dumps(original))
    response = dashboard.request('GET', '/api/config')
    assert response.status == 200
    assert json.loads(response.body) == {k: original[k] for k in ('profile', 'target', 'interval', 'extra_subnets', 'server')}
    assert response.headers['Cache-Control'] == 'no-store'
    assert 'Access-Control-Allow-Origin' not in response.headers
    response = dashboard.request('POST', '/api/config', {'target': '/new', 'token': '', 'api_key': 'overwrite'},
                                 {'Origin': dashboard.origin})
    assert response.status == 200
    assert json.loads(path.read_text()) == {**original, 'target': '/new'}
    assert dashboard.request('POST', '/api/config', {'target': '/referer'},
                             {'Referer': dashboard.origin + '/dashboard'}).status == 200
    assert dashboard.request('POST', '/api/config', {}, {'Origin': dashboard.origin}, role=None).status == 401


def test_local_login_origin_check_preserves_cookie_and_redirect(dashboard):
    body = 'email=admin%40example.test&password=correct-password&next=%2Fclients'
    for headers in ({}, {'Origin': 'https://evil.test'}):
        assert dashboard.request('POST', '/login', body, headers, role=None).status == 403
    response = dashboard.request('POST', '/login', body, {'Origin': dashboard.origin}, role=None)
    assert response.status == 302
    assert response.headers['Location'] == '/clients'
    assert response.headers['Set-Cookie'].startswith('sentinel_session=')
    assert response.headers['Set-Cookie'].endswith('; Path=/; HttpOnly; SameSite=Strict')


def test_configured_origins_do_not_trust_host_or_forwarded_headers(dashboard, monkeypatch):
    monkeypatch.setenv('PUBLIC_ADMIN_URL', 'https://control.example.test')
    monkeypatch.setenv('PUBLIC_DASHBOARD_URL', 'https://dashboard.example.test:8443')
    for origin in ('https://control.example.test', 'https://dashboard.example.test:8443'):
        assert dashboard.request('POST', '/api/config', {}, {'Origin': origin}).status == 200
    for origin in ('https://arckon.riskraven.ai', 'https://dashboard.example.test', dashboard.origin + '1'):
        assert dashboard.request('POST', '/api/config', {},
                                 {'Origin': origin, 'Host': origin.split('://')[1],
                                  'X-Forwarded-Host': origin.split('://')[1]}).status == 403


@pytest.mark.parametrize('role', ['admin', 'customer_admin', 'super_admin', 'viewer', 'client_viewer'])
def test_enrollment_token_roles_and_rendered_commands(dashboard, role):
    response = dashboard.request('GET', '/api/customers/me', role=role)
    if role == 'client_viewer':
        assert response.status == 403
        return
    assert response.status == 200
    payload = json.loads(response.body)
    privileged = role != 'viewer'
    assert ('agent_token' in payload) == privileged
    if privileged:
        assert payload['agent_token'] == dashboard.customer['agent_token']
    page = dashboard.request('GET', '/', role=role)
    assert page.status == 200
    token = dashboard.customer['agent_token'].encode()
    assert (token in page.body) == privileged
    if privileged:
        assert b'--server http://127.0.0.1:' in page.body
        assert b'--token ' + token in page.body
        assert b'--target /' in page.body
        assert b'MDM/Jamf deployment script' in page.body


def test_cloud_enrollment_uses_capability_and_persisted_token(dashboard, monkeypatch):
    token_file = dashboard.root / 'data' / 'rotated-agent-token.txt'
    token_file.write_text('rotated-machine-secret')
    monkeypatch.setenv('SENTINEL_AGENT_TOKEN_FILE', str(token_file))
    # An obsolete marker is not cloud authority.
    monkeypatch.setenv('SENTINEL_TRUSTED_PROXY', '1')
    response = dashboard.request('GET', '/api/customers/me')
    assert json.loads(response.body)['agent_token'] == dashboard.customer['agent_token']
    monkeypatch.delenv('SENTINEL_TRUSTED_PROXY')
    monkeypatch.setenv('SENTINEL_TRUSTED_PROXY_TOKEN', 'proxy-capability')
    headers = {'X-Sentinel-Proxy-Token': 'proxy-capability', 'X-Sentinel-User-Email': 'cloud@example.test',
               'X-Sentinel-User-Role': 'customer_admin', 'X-Sentinel-Customer-ID': 'tenant'}
    response = dashboard.request('GET', '/api/customers/me', headers=headers, role=None)
    assert json.loads(response.body)['agent_token'] == 'rotated-machine-secret'
    page = dashboard.request('GET', '/', headers=headers, role=None)
    assert b'--token rotated-machine-secret' in page.body
    assert b'--server https://127.0.0.1:' in page.body
    assert dashboard.request('GET', '/api/customers/me').status == 401  # No local session revival.
    headers['Origin'] = dashboard.origin
    assert dashboard.request('POST', '/api/config', {}, headers, role=None).status == 403
    headers['Origin'] = 'https://arckon.riskraven.ai'
    assert dashboard.request('POST', '/api/config', {}, headers, role=None).status == 200
    headers['X-Sentinel-User-Role'] = 'viewer'
    assert 'agent_token' not in json.loads(dashboard.request('GET', '/api/customers/me', headers=headers, role=None).body)


def test_dashboard_failure_does_not_disclose_traceback(dashboard, monkeypatch):
    def fail(*args, **kwargs):
        raise RuntimeError('private-path-and-credential')
    monkeypatch.setattr(server, '_build_fleet_html', fail)
    response = dashboard.request('GET', '/')
    assert b'Dashboard temporarily unavailable' in response.body
    assert b'Traceback' not in response.body
    assert b'private-path-and-credential' not in response.body


def test_machine_routes_keep_their_own_authentication(dashboard):
    dashboard.store.upsert_report('agent-one', 'host', {'summary': {'fail': 0, 'warn': 0, 'pass': 1}})
    payload = {'device_id': 'agent-one', 'hostname': 'host', 'results': []}
    for token, status in [('wrong', 401), (dashboard.customer['agent_token'], 200)]:
        response = dashboard.request('POST', '/api/agent/network-assets', payload,
                                     {'Authorization': 'Bearer ' + token, 'Origin': 'https://evil.test'})
        assert response.status == status
    response = dashboard.request('POST', '/api/cloud-assets/events', {},
                                 {'Authorization': 'Bearer wrong', 'Origin': 'https://evil.test'})
    assert response.status == 401
    response = dashboard.request('POST', '/api/cloud-assets/events', {},
                                 {'Authorization': 'Bearer ' + server._cloud_ingest_token(), 'Origin': 'https://evil.test'})
    assert response.status == 200


@pytest.mark.parametrize('provenance', ['Origin', 'Referer'])
def test_admin_post_relays_forward_validated_browser_provenance(dashboard, admin, monkeypatch, provenance):
    app, client, _ = admin
    with app.get_conn() as conn:
        conn.execute("UPDATE customers SET is_reseller=1 WHERE id='tenant'")
        conn.execute("INSERT INTO customers (id, name, created_at, agent_token, port, parent_customer_id) VALUES (?,?,?,?,?,?)",
                     ('resold', 'Resold Tenant', '2026-01-01', 'resold-secret', 81, 'tenant'))
    login = client.post('/login', data={'email': 'customer@example.test', 'password': 'correct-password'},
                        headers={'Origin': 'https://admin.riskraven.ai'})
    assert login.status_code == 303
    token = client.cookies.get('token')
    monkeypatch.setenv('SENTINEL_TRUSTED_PROXY_TOKEN', 'proxy-capability')
    monkeypatch.setenv('SENTINEL_TRUSTED_PROXY', '1')  # Existing user-management relay switch.
    headers = {'X-Sentinel-Proxy-Token': 'proxy-capability', 'X-Sentinel-User-Email': 'customer@example.test',
               'X-Sentinel-User-Role': 'customer_admin', 'X-Sentinel-Customer-ID': 'tenant',
               'Cookie': 'token=' + token, provenance: 'https://arckon.riskraven.ai' + ('/dashboard' if provenance == 'Referer' else '')}
    relayed = []

    def urlopen(req, **kwargs):
        forwarded = dict(req.header_items())
        response = client.request(req.method, req.selector, content=req.data, headers=forwarded)
        relayed.append((req.selector, forwarded, response.status_code))
        if response.status_code >= 400:
            raise urllib.error.HTTPError(req.full_url, response.status_code, 'admin rejection', {}, io.BytesIO(response.content))
        class Response(io.BytesIO):
            status = response.status_code
        return Response(response.content)

    monkeypatch.setattr('urllib.request.urlopen', urlopen)
    response = dashboard.request('POST', '/api/users/add',
                                 {'email': 'new@example.test', 'password': 'new-password', 'role': 'user'}, headers, role=None)
    assert response.status == 200
    response = dashboard.request('POST', '/api/reseller/impersonate', {'customer_id': 'resold'}, headers, role=None)
    assert response.status == 200
    assert json.loads(response.body)['ok'] is True
    assert response.headers['Set-Cookie'].startswith('token=')
    # Exercise the end relay with a registry-backed JWT, independently of
    # the admin service's synthetic impersonation-subject validation.
    headers['Cookie'] = 'token=' + token + '; sentinel_return_token=' + token + '; sentinel_return_url=/reseller'
    response = dashboard.request('POST', '/api/reseller/impersonate/end', {}, headers, role=None)
    assert response.status == 200
    assert json.loads(response.body) == {'ok': True, 'redirect_url': '/reseller'}
    assert [path for path, _, _ in relayed] == ['/api/users/add', '/api/reseller/impersonate', '/api/reseller/impersonate/end']
    for _, forwarded, status in relayed:
        assert forwarded[provenance] == headers[provenance]
        assert status == 200
    with app.get_conn() as conn:
        assert conn.execute("SELECT COUNT(*) FROM audit_log WHERE action='impersonate_start'").fetchone()[0] == 1
    before = len(relayed)
    headers['Origin'] = 'https://evil.test'
    assert dashboard.request('POST', '/api/users/add', {}, headers, role=None).status == 403
    assert len(relayed) == before


def test_siem_routes_use_persisted_data_path(dashboard, monkeypatch):
    from connectors import siem_connector
    expected = dashboard.root / 'data' / 'siem_config.json'
    paths = []
    monkeypatch.setattr(siem_connector, 'load_siem_config_for_ui', lambda path: paths.append(path) or {})
    assert dashboard.request('GET', '/api/siem/config').status == 200
    assert paths == [expected]


def test_siem_save_masks_secrets_and_test_reads_same_data_path(dashboard, monkeypatch):
    from connectors import siem_connector
    expected = dashboard.root / 'data' / 'siem_config.json'
    headers = {'Origin': dashboard.origin}
    payload = {'splunk': {'enabled': True, 'hec_token': 'private-siem-secret'}}
    response = dashboard.request('POST', '/api/siem/config', payload, headers)
    assert response.status == 200
    assert 'private-siem-secret' not in expected.read_text()
    assert not (dashboard.root / 'siem_config.json').exists()
    assert siem_connector.load_siem_config(expected) == payload
    response = dashboard.request('GET', '/api/siem/config')
    assert json.loads(response.body)['splunk']['hec_token'] == '__set__'
    assert dashboard.request('POST', '/api/siem/config', {'splunk': {'hec_token': '__set__'}}, headers).status == 200
    assert siem_connector.load_siem_config(expected) == payload
    seen = []
    monkeypatch.setattr(siem_connector, 'test_connection', lambda name, cfg: (seen.append((name, cfg)) or True, 'tested'))
    assert dashboard.request('POST', '/api/siem/test/splunk', {}, headers).status == 200
    assert seen == [('splunk', payload)]
    assert siem_connector._SIEM_CONFIG_PATH == server.Path(siem_connector.__file__).parent.parent / 'data' / 'siem_config.json'


def test_invalid_master_key_is_fatal_before_license_and_monitors(dashboard, monkeypatch):
    monkeypatch.setenv('ARCKON_MASTER_KEY', 'invalid')
    monkeypatch.setattr('sys.argv', ['server.py', '--no-browser'])
    started = []
    monkeypatch.setattr(server, '_load_license', lambda: started.append('license'))
    monkeypatch.setattr(server.threading.Thread, 'start', lambda self: started.append('thread'))
    with pytest.raises(ValueError):
        server.main()
    assert started == []
