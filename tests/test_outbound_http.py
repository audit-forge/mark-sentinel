"""Transport tests use fake sockets, never public network access."""

import io
import ipaddress
import json
import socket
import ssl
import urllib.error
import urllib.request
from unittest.mock import MagicMock

import pytest

import outbound_http as http


@pytest.fixture(autouse=True)
def clean_policy(monkeypatch):
    monkeypatch.delenv('ARCKON_OUTBOUND_PRIVATE_ORIGINS', raising=False)


def dns(monkeypatch, *addresses):
    answers = []
    for address in addresses:
        family = socket.AF_INET6 if ':' in address else socket.AF_INET
        sockaddr = (address, 443, 0, 0) if family == socket.AF_INET6 else (address, 443)
        answers.append((family, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', sockaddr))
    resolver = MagicMock(return_value=answers)
    monkeypatch.setattr(http.socket, 'getaddrinfo', resolver)
    return resolver


def wire(monkeypatch, response=b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}'):
    sock = MagicMock()
    sock.makefile.side_effect = lambda *a, **kw: io.BytesIO(response)
    factory = MagicMock(return_value=sock)
    monkeypatch.setattr(http.socket, 'socket', factory)
    context = ssl.create_default_context()
    wrap = MagicMock(return_value=sock)
    monkeypatch.setattr(context, 'wrap_socket', wrap)
    monkeypatch.setattr(http.ssl, 'create_default_context', lambda: context)
    return sock, factory, context, wrap


@pytest.mark.parametrize('url', [
    'file:///etc/passwd', 'ftp://example.com/a', 'https://user:secret@example.com/',
    'https://@example.com/', 'https://example.com/#fragment',
    '\nhttps://example.com/', 'https://example.com/\r\nx: y',
    'https://example.com/\x7f', 'https://example.com/ ',
    'https://example.com\\@127.0.0.1/', 'http://example.com:0/',
    'http://example.com:65536/', 'http://example.com:/',
    'http://[::1]evil/', 'http://[fe80::1%25en0]/',
    'http://2130706433/', 'http://127.1/', 'http://0177.0.0.1/',
    'http://0x7f000001/', 'https://example.com./',
])
def test_strict_url_rejected_before_dns(monkeypatch, url):
    resolver = dns(monkeypatch, '8.8.8.8')
    with pytest.raises((http.OutboundHTTPError, ValueError)):
        http.urlopen(url)
    resolver.assert_not_called()


def test_request_retains_controls_before_urllib_normalization(monkeypatch):
    resolver = dns(monkeypatch, '8.8.8.8')
    req = http.Request('\nhttps://example.com/', data=b'secret')
    with pytest.raises(http.OutboundHTTPError):
        http.urlopen(req)
    resolver.assert_not_called()


@pytest.mark.parametrize('address', [
    '127.0.0.1', '10.1.2.3', '172.16.0.1', '192.168.1.1', '::1', 'fd12::1',
    '169.254.169.254', '169.254.170.2', 'fe80::1', '224.0.0.1', 'ff02::1',
    '0.0.0.0', '::', '100.100.100.200', '168.63.129.16', 'fd00:ec2::254',
    '192.0.2.1', '198.18.0.1', '240.0.0.1', '::ffff:127.0.0.1',
    '::ffff:8.8.8.8', '2002:7f00:1::', '64:ff9b::7f00:1',
])
def test_nonpublic_and_metadata_denied(monkeypatch, address):
    dns(monkeypatch, address)
    _, factory, _, _ = wire(monkeypatch)
    with pytest.raises(http.OutboundHTTPError):
        http.urlopen('https://example.com/')
    factory.assert_not_called()


def test_mixed_dns_answers_fail_closed(monkeypatch):
    dns(monkeypatch, '8.8.8.8', '127.0.0.1')
    _, factory, _, _ = wire(monkeypatch)
    with pytest.raises(http.OutboundHTTPError):
        http.urlopen('https://example.com/')
    factory.assert_not_called()


@pytest.mark.parametrize('address', ['8.8.8.8', '2606:4700:4700::1111'])
def test_numeric_pin_preserves_tls_identity_and_host(monkeypatch, address):
    resolver = dns(monkeypatch, address)
    sock, _, context, wrap = wire(monkeypatch)
    req = http.Request('https://api.example.com:8443/v1?x=1', data=b'secret',
                       headers={'Authorization': 'Bearer token', 'Host': 'attacker.test'})
    with http.urlopen(req, timeout=7) as response:
        assert response.read() == b'{}'
    resolver.assert_called_once_with('api.example.com', 8443, type=socket.SOCK_STREAM)
    assert sock.connect.call_args.args[0][0] == address
    sock.settimeout.assert_called_once_with(7)
    wrap.assert_called_once_with(sock, server_hostname='api.example.com')
    assert context.check_hostname
    assert context.verify_mode == ssl.CERT_REQUIRED
    sent = b''.join(call.args[0] for call in sock.sendall.call_args_list)
    assert b'Host: api.example.com:8443\r\n' in sent
    assert b'Authorization: Bearer token\r\n' in sent
    assert b'POST /v1?x=1 HTTP/1.1\r\n' in sent
    assert sent.endswith(b'secret')
    assert req.get_header('Host') == 'attacker.test'


def test_ambient_proxies_disabled(monkeypatch):
    for name in ('http_proxy', 'https_proxy', 'all_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY'):
        monkeypatch.setenv(name, 'http://127.0.0.1:9999')
    dns(monkeypatch, '8.8.8.8')
    sock, _, _, _ = wire(monkeypatch)
    with http.urlopen('http://api.example.com/'):
        pass
    assert sock.connect.call_args.args[0][0] == '8.8.8.8'
    assert b'GET / HTTP/1.1' in sock.sendall.call_args_list[0].args[0]


@pytest.mark.parametrize('status', [301, 302, 303, 307, 308])
def test_no_redirects_or_credential_forwarding(monkeypatch, status):
    resolver = dns(monkeypatch, '8.8.8.8')
    sock, _, _, _ = wire(monkeypatch, (
        f'HTTP/1.1 {status} Redirect\r\nLocation: http://127.0.0.1/secret\r\n'
        'Content-Length: 0\r\n\r\n'
    ).encode())
    with pytest.raises(urllib.error.URLError):
        http.urlopen(http.Request('https://example.com/', headers={'Authorization': 'secret'}))
    assert sock.connect.call_count == 1
    assert resolver.call_count == 1


@pytest.mark.parametrize('url,address', [
    ('https://siem.internal:8088/event', '10.20.0.10'),
    ('http://127.0.0.1:8400/chat', '127.0.0.1'),
    ('http://[::1]:11434/v1/chat/completions', '::1'),
])
def test_explicit_private_origin_approval(monkeypatch, url, address):
    scheme, host, port = http._parse_url(url)
    authority = f'[{host}]' if ':' in host else host
    cidr = f'{address}/{ipaddress.ip_address(address).max_prefixlen}'
    monkeypatch.setenv('ARCKON_OUTBOUND_PRIVATE_ORIGINS', json.dumps({
        f'{scheme}://{authority}:{port}': [cidr],
    }))
    dns(monkeypatch, address)
    sock, _, _, _ = wire(monkeypatch)
    with http.urlopen(url):
        pass
    assert sock.connect.call_args.args[0][0] == address


@pytest.mark.parametrize('url,address', [
    ('https://siem.internal:8089/', '10.20.0.10'),
    ('http://siem.internal:8088/', '10.20.0.10'),
    ('https://other.internal:8088/', '10.20.0.10'),
    ('https://siem.internal.evil:8088/', '10.20.0.10'),
    ('https://siem.internal:8088/', '10.20.0.11'),
    ('https://siem.internal:8088/', '169.254.169.254'),
])
def test_approval_is_exact_origin_and_cidr(monkeypatch, url, address):
    monkeypatch.setenv('ARCKON_OUTBOUND_PRIVATE_ORIGINS', json.dumps({
        'https://siem.internal:8088': ['10.20.0.10/32'],
    }))
    dns(monkeypatch, address)
    with pytest.raises(http.OutboundHTTPError):
        http.urlopen(url)


@pytest.mark.parametrize('policy', [
    'invalid', '[]', '{"https://example.com": "10.0.0.0/8"}',
    '{"https://example.com/path": ["10.0.0.0/8"]}',
    '{"https://example.com": ["0.0.0.0/0"]}',
    '{"https://example.com": ["169.254.0.0/16"]}',
    '{"https://example.com": ["224.0.0.0/4"]}',
])
def test_bad_operator_policy_fails_closed(monkeypatch, policy):
    monkeypatch.setenv('ARCKON_OUTBOUND_PRIVATE_ORIGINS', policy)
    resolver = dns(monkeypatch, '8.8.8.8')
    with pytest.raises(http.OutboundHTTPError):
        http.urlopen('https://example.com/')
    resolver.assert_not_called()


def test_private_metadata_never_approved(monkeypatch):
    monkeypatch.setenv('ARCKON_OUTBOUND_PRIVATE_ORIGINS', json.dumps({
        'https://siem.internal': ['fc00::/7'],
    }))
    dns(monkeypatch, 'fd00:ec2::254')
    with pytest.raises(http.OutboundHTTPError):
        http.urlopen('https://siem.internal/')


@pytest.mark.parametrize('timeout', [None, 0, -1, float('inf'), float('nan')])
def test_finite_timeout_required(timeout):
    with pytest.raises(http.OutboundHTTPError):
        http.urlopen('https://example.com/', timeout=timeout)


def test_dns_failure_and_empty_answers(monkeypatch):
    resolver = dns(monkeypatch)
    with pytest.raises(http.OutboundHTTPError):
        http.urlopen('https://example.com/')
    resolver.side_effect = socket.gaierror('failed')
    with pytest.raises(http.OutboundHTTPError):
        http.urlopen('https://example.com/')


def test_no_global_monkeypatch():
    assert urllib.request.urlopen is not http.urlopen


def test_tenant_config_cannot_approve_private_siem(monkeypatch):
    from connectors.siem_connector import SplunkHECConnector
    dns(monkeypatch, '127.0.0.1')
    _, factory, _, _ = wire(monkeypatch)
    connector = SplunkHECConnector({
        'hec_url': 'https://127.0.0.1:8088', 'hec_token': 'secret',
        'verify_ssl': False, 'private_origins': {'https://127.0.0.1:8088': ['127.0.0.1/32']},
        'ARCKON_OUTBOUND_PRIVATE_ORIGINS': '{"https://127.0.0.1:8088":["127.0.0.1/32"]}',
    })
    status, body = connector._post({'event': 'test'})
    assert status == 0
    assert 'blocked' in body
    factory.assert_not_called()


def test_siem_cannot_disable_tls_verification(monkeypatch):
    from connectors.siem_connector import SplunkHECConnector
    dns(monkeypatch, '8.8.8.8')
    context = ssl.create_default_context()
    sock = MagicMock()
    sock.makefile.return_value = io.BytesIO(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}')
    monkeypatch.setattr(http.socket, 'socket', MagicMock(return_value=sock))
    monkeypatch.setattr(context, 'wrap_socket', MagicMock(return_value=sock))
    monkeypatch.setattr(http.ssl, 'create_default_context', lambda: context)
    connector = SplunkHECConnector({'hec_url': 'https://example.com', 'hec_token': 'secret', 'verify_ssl': False})
    assert connector._post({'event': 'test'})[0] == 200
    assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED


def test_alerts_and_model_probes_reject_private_destinations(monkeypatch):
    import alerts
    from connectors import api_connector, hash_connector
    dns(monkeypatch, '127.0.0.1')
    _, factory, _, _ = wire(monkeypatch)
    assert not alerts._post_webhook('https://example.com/', {'severity': 'HIGH'})
    assert not alerts._post_gchat('https://example.com/', 'test')
    assert not alerts._post_teams('https://example.com/', 'test')
    assert not alerts._post_slack('https://hooks.slack.com/services/a/b/c', 'test', {})
    assert api_connector._chat_request('http://127.0.0.1:11434/v1', '', 'model', 'sys', 'test')[1]
    assert hash_connector._chat_request('http://127.0.0.1:8400', '', 'session', 'test')[1]
    factory.assert_not_called()


def test_psa_including_oauth_rejects_private_destinations(monkeypatch):
    from connectors import psa_connector as psa
    dns(monkeypatch, '127.0.0.1')
    _, factory, _, _ = wire(monkeypatch)
    assert psa._halo_get_token({'tenant': 'https://example.com', 'client_secret': 'secret'}) is None
    assert not psa._http_post('https://example.com/', {}, {'Authorization': 'secret'}, 'Test')[0]
    factory.assert_not_called()


def test_approved_local_integrations_end_to_end(monkeypatch):
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import threading
    import alerts
    from connectors import api_connector, hash_connector, psa_connector
    from connectors.siem_connector import SplunkHECConnector

    received = []
    body = json.dumps({
        'choices': [{'message': {'content': 'safe model response'}}],
        'response': 'safe hash response', 'access_token': 'oauth-token', 'code': 0,
    }).encode()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            received.append((self.path, self.headers, self.rfile.read(int(self.headers['Content-Length']))))
            self.send_response(200)
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    origin = f'http://127.0.0.1:{server.server_port}'
    monkeypatch.setenv('ARCKON_OUTBOUND_PRIVATE_ORIGINS', json.dumps({origin: ['127.0.0.1/32']}))
    try:
        assert api_connector._chat_request(origin + '/v1', 'api-key', 'model', 'sys', 'hello') == ('safe model response', '')
        assert hash_connector._chat_request(origin, 'hash-key', 'session', 'hello') == ('safe hash response', '')
        assert alerts._post_webhook(origin + '/webhook', {'severity': 'HIGH'})
        assert psa_connector._halo_get_token({'tenant': origin, 'client_secret': 'secret'}) == 'oauth-token'
        assert psa_connector._http_post(origin + '/tickets', {}, {'Authorization': 'Bearer oauth-token'}, 'Test')[0]
        assert SplunkHECConnector({'hec_url': origin, 'hec_token': 'siem-key'})._post({'event': 'test'})[0] == 200
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
    assert [entry[0] for entry in received] == [
        '/v1/chat/completions', '/chat', '/webhook', '/auth/token', '/tickets', '/services/collector/event',
    ]
    assert received[0][1]['Authorization'] == 'Bearer api-key'
    assert received[1][1]['Authorization'] == 'Bearer hash-key'
    assert b'client_secret=secret' in received[3][2]


def test_tls_certificate_failure_never_falls_back(monkeypatch):
    resolver = dns(monkeypatch, '8.8.8.8')
    sock, factory, _, wrap = wire(monkeypatch)
    wrap.side_effect = ssl.SSLCertVerificationError('untrusted certificate')
    with pytest.raises(urllib.error.URLError):
        http.urlopen('https://example.com/')
    assert resolver.call_count == 1
    assert factory.call_count == 1
    assert sock.sendall.call_count == 0


def test_pinned_connect_failure_uses_only_other_validated_answers(monkeypatch):
    resolver = dns(monkeypatch, '8.8.8.8', '1.1.1.1')
    sock, _, _, _ = wire(monkeypatch)
    sock.connect.side_effect = [OSError('unreachable'), None]
    with http.urlopen('http://example.com/'):
        pass
    assert [call.args[0][0] for call in sock.connect.call_args_list] == ['8.8.8.8', '1.1.1.1']
    assert resolver.call_count == 1
