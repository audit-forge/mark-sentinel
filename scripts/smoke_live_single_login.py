"""Run inside sentinel-admin; transient test accounts are always removed.

Exercises public TLS ingress and shared-cookie SSO without using customer passwords.
Never prints passwords, bearer credentials, cookies, or response bodies.
"""
import os
import secrets
import sys
import uuid
from datetime import datetime, timezone

import requests

sys.path.insert(0, '/app')
from auth import hash_password
from db import get_conn


def main():
    admin = os.environ['PUBLIC_ADMIN_URL'].rstrip('/')
    dashboard = os.environ['PUBLIC_DASHBOARD_URL'].rstrip('/')
    with get_conn() as conn:
        tenants = [row['id'] for row in conn.execute(
            'SELECT id FROM customers WHERE active=1 AND service_suspended=0 ORDER BY id')]
    for tenant in tenants:
        identity = str(uuid.uuid4())
        email = 'security-smoke-' + identity + '@example.invalid'
        password = secrets.token_urlsafe(36)
        try:
            with get_conn() as conn:
                conn.execute('INSERT INTO users(id,email,password_hash,role,customer_id,created_at,active) '
                             'VALUES(?,?,?,?,?,?,1)', (identity, email, hash_password(password),
                                                      'customer_admin', tenant,
                                                      datetime.now(timezone.utc).isoformat()))
            with requests.Session() as session:
                login = session.post(admin + '/login', data={
                    'email': email, 'password': password, 'next': dashboard + '/?security-smoke=1'},
                    headers={'Origin': admin}, allow_redirects=False, timeout=30)
                assert login.status_code == 303, 'login did not redirect'
                assert login.headers['Location'] == dashboard + '/?security-smoke=1', 'wrong destination'
                cookies = [cookie for cookie in session.cookies if cookie.name == 'token']
                assert len(cookies) == 1 and cookies[0].secure, 'shared secure cookie absent'
                page = session.get(login.headers['Location'], allow_redirects=False, timeout=45)
                print(tenant + ': dashboard status=' + str(page.status_code) +
                      ', redirected=' + str('Location' in page.headers), flush=True)
                assert page.status_code == 200 and 'page-network-assets' in page.text, 'second login or dashboard error'
                for path in ('/api/devices', '/api/customers/me', '/api/config',
                             '/api/protected-paths', '/api/siem/config', '/api/fleet/network-assets/scans'):
                    response = session.get(dashboard + path, allow_redirects=False, timeout=30)
                    assert response.status_code == 200, 'API failed: ' + path
                    payload = response.json()
                    assert response.headers.get('Access-Control-Allow-Origin') != '*', 'wildcard CORS'
                    if path == '/api/config':
                        assert 'token' not in payload and 'api_key' not in payload, 'config credential disclosure'
                    if path == '/api/customers/me':
                        assert payload.get('agent_token'), 'administrator enrollment broken'
                    if path == '/api/protected-paths':
                        assert 'enc:' not in response.text, 'policy decryption failure'
                denied = session.post(dashboard + '/api/config', json={},
                                      headers={'Origin': 'https://untrusted.example.invalid'}, timeout=30)
                assert denied.status_code == 403, 'cross-origin mutation accepted'
                queued = session.post(dashboard + '/api/fleet/network-assets/discover/all',
                                      headers={'Origin': dashboard}, timeout=30)
                assert queued.status_code == 200 and queued.json().get('status') == 'queued', 'passive collection broken'
                logout = session.get(admin + '/logout', allow_redirects=False, timeout=30)
                assert logout.status_code == 303, 'logout failed'
                assert not any(c.name == 'token' for c in session.cookies), 'logout retained cookie'
                response = session.get(dashboard + '/', allow_redirects=False, timeout=30)
                assert response.status_code == 302, 'logout did not end session'
            print(tenant + ': single login, shared cookie, dashboard APIs, enrollment, CSRF, passive queue, logout PASS')
        finally:
            with get_conn() as conn:
                conn.execute('DELETE FROM users WHERE id=?', (identity,))


if __name__ == '__main__':
    main()
