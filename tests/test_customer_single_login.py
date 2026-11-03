import pytest

from .test_browser_security import admin, login, ADMIN, DASHBOARD


@pytest.mark.parametrize('target', ['', 'https://untrusted.example/', '/login', '/logout',
                                   '/setup', '/login/?next=/login', '/%6cogin',
                                   '/%256cogin', ADMIN + '/login?next=/login',
                                   DASHBOARD + '/login'])
def test_authenticated_customer_never_gets_a_second_login_form(admin, target):
    _, client, _ = admin
    assert login(client).status_code == 303
    response = client.get('/login', params={'next': target})
    assert response.status_code == 303
    assert response.headers['location'] == DASHBOARD
    assert 'set-cookie' not in response.headers  # no renewal or second login


@pytest.mark.parametrize('target', ['/login', '/logout', '/setup', '/%6cogin',
                                   '/%256cogin', ADMIN + '/login',
                                   DASHBOARD + '/login?next=/login'])
def test_one_credential_post_cannot_land_back_on_an_auth_page(admin, target):
    _, client, _ = admin
    response = login(client, target=target)
    assert response.status_code == 303
    assert response.headers['location'] == DASHBOARD
    assert response.headers['set-cookie'].startswith('token=')
    assert 'sentinel_session' not in response.headers['set-cookie']


def test_existing_customer_session_retains_safe_deep_link(admin):
    _, client, _ = admin
    assert login(client).status_code == 303
    target = DASHBOARD + '/?client_org=client-a#endpoint-ai'
    response = client.get('/login', params={'next': target})
    assert response.status_code == 303
    assert response.headers['location'] == target


def test_expired_customer_really_does_need_one_new_login(admin):
    _, client, _ = admin
    assert login(client).status_code == 303
    client.cookies.clear()
    response = client.get('/login', params={'next': '/login'})
    assert response.status_code == 200
    assert response.template.name == 'login.html'
    assert response.context['next'] == ''


def test_operator_does_not_get_bounced_into_customer_gateway(admin):
    _, client, _ = admin
    assert login(client, user='operator').status_code == 303
    response = client.get('/login', params={'next': DASHBOARD})
    assert response.status_code == 303
    assert response.headers['location'] == '/dashboard'
