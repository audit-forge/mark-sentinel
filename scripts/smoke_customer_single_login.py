"""Credential-login verification inside sentinel-admin.

Creates and deletes temporary test users only. Uses fresh cookie jars and
generated passwords; does not read customer passwords, call enrollment APIs,
change customer settings, or enqueue agent commands. Not read-only. Privileged
dashboard HTML includes deployment credentials; responses stay in memory and
no credentials, cookies, response bodies, or customer data are printed.
"""
import argparse
from datetime import datetime, timezone
import os
import secrets
import signal
import sys
from urllib.parse import urlsplit
import uuid

import requests

sys.path.insert(0, '/app')
from auth import hash_password
from db import get_conn


def main(expected_tenants):
    admin = os.environ['PUBLIC_ADMIN_URL'].rstrip('/')
    dashboard = os.environ['PUBLIC_DASHBOARD_URL'].rstrip('/')
    for url in (admin, dashboard):
        parsed = urlsplit(url)
        assert parsed.scheme == 'https' and parsed.hostname
        assert not (parsed.username or parsed.password or parsed.query or parsed.fragment)
    with get_conn() as conn:
        tenants = [row['id'] for row in conn.execute(
            'SELECT id FROM customers WHERE active=1 AND service_suspended=0 ORDER BY id')]
    assert tenants and set(tenants) == set(expected_tenants), 'Active tenant coverage differs'
    for tenant in tenants:
        for role in ('admin', 'customer_admin'):
            identity = str(uuid.uuid4())
            email = 'single-login-check-' + identity + '@example.invalid'
            password = secrets.token_urlsafe(32)
            try:
                with get_conn() as conn:
                    conn.execute('INSERT INTO users(id,email,password_hash,role,customer_id,created_at,active) '
                                 'VALUES(?,?,?,?,?,?,1)',
                                 (identity, email, hash_password(password), role, tenant,
                                  datetime.now(timezone.utc).isoformat()))
                with requests.Session() as session:
                    target = dashboard + '/?login-validation=1' if role == 'admin' else '/login'
                    expected = target if role == 'admin' else dashboard
                    result = session.post(admin + '/login', data={
                        'email': email, 'password': password, 'next': target},
                        headers={'Origin': admin}, allow_redirects=False, timeout=30)
                    assert result.status_code == 303, 'Credential login failed'
                    assert result.headers['Location'] == expected, 'Wrong post-login destination'
                    cookies = [cookie for cookie in session.cookies if cookie.name == 'token']
                    assert len(cookies) == 1 and cookies[0].secure, 'Shared secure cookie missing'
                    assert not any(cookie.name == 'sentinel_session' for cookie in session.cookies)
                    page = session.get(expected, allow_redirects=False, timeout=45)
                    assert page.status_code == 200 and 'Location' not in page.headers, 'Second login redirect'
                    assert 'page-endpoint-ai' in page.text, 'Dashboard did not render'
                    me = session.get(dashboard + '/api/auth/me', allow_redirects=False, timeout=20)
                    assert me.status_code == 200 and me.json()['customer_id'] == tenant, 'Wrong tenant handoff'
                    for callback in ('', '?next=/login'):
                        again = session.get(admin + '/login' + callback,
                                            allow_redirects=False, timeout=20)
                        assert again.status_code == 303 and again.headers['Location'] == dashboard, 'Second form at central login'
                    local = session.get(dashboard + '/login', allow_redirects=False, timeout=20)
                    assert local.status_code in (302, 303) and local.headers['Location'] == '/', 'Local second login exposed'
                    response = session.get(dashboard + '/', allow_redirects=False, timeout=45)
                    assert response.status_code == 200, 'Authenticated dashboard access failed'
                    logout = session.get(admin + '/logout?next=/login', allow_redirects=False, timeout=20)
                    assert logout.status_code == 303
                    assert not any(cookie.name == 'token' for cookie in session.cookies), 'Logout retained shared cookie'
                    denied = session.get(dashboard + '/api/auth/me', allow_redirects=False, timeout=20)
                    assert denied.status_code == 401, 'Logout left session usable'
                print(tenant + ' [' + role + ']: one credential POST, dashboard 200, tenant binding, no second form, logout PASS', flush=True)
            finally:
                with get_conn() as conn:
                    conn.execute('DELETE FROM users WHERE id=? AND email=?', (identity, email))
                    assert conn.execute('SELECT 1 FROM users WHERE id=?', (identity,)).fetchone() is None
    print('Exact active-tenant coverage and temporary-user cleanup PASS', flush=True)


if __name__ == '__main__':
    def interrupted(signum, frame):
        raise SystemExit('Verification interrupted; removing current test identity')

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expected-tenants', nargs='+', required=True)
    args = parser.parse_args()
    main(args.expected_tenants)
