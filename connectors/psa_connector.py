"""
M.A.R.K. Sentinel — PSA Connector
Creates service tickets in ConnectWise Manage, Autotask PSA, and HaloPSA
when CRITICAL or HIGH findings are detected.

Config (inside alerts_config.json under key "psa"):
{
  "provider": "connectwise",
  "connectwise": {
    "site": "na.myconnectwise.net",
    "company_id": "MyCompany",
    "public_key": "...",
    "private_key": "...",
    "client_id": "...",
    "service_board": "Service Requests",
    "company_name": "Client Company"
  },
  "autotask": {
    "zone": "webservices2",
    "username": "api@company.com",
    "api_key": "...",
    "account_id": 12345,
    "queue_id": 8,
    "priority_id": 1
  },
  "halopsa": {
    "tenant": "mycompany",
    "client_id": "...",
    "client_secret": "...",
    "ticket_type_id": 1,
    "priority_id": 1
  }
}
"""
import base64
import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

log = logging.getLogger('sentinel.psa')


def create_ticket(psa_cfg: dict, finding: dict, hostname: str) -> tuple[bool, str]:
    """Create a PSA ticket for a finding. Returns (ok, message)."""
    provider = psa_cfg.get('provider', '').lower()
    if provider == 'connectwise':
        return _cw_create_ticket(psa_cfg.get('connectwise', {}), finding, hostname)
    if provider == 'autotask':
        return _at_create_ticket(psa_cfg.get('autotask', {}), finding, hostname)
    if provider == 'halopsa':
        return _halo_create_ticket(psa_cfg.get('halopsa', {}), finding, hostname)
    return False, f'Unknown PSA provider: {provider!r}'


def test_connection(psa_cfg: dict) -> tuple[bool, str]:
    """Test PSA connectivity without creating a ticket. Returns (ok, message)."""
    provider = psa_cfg.get('provider', '').lower()
    if provider == 'connectwise':
        return _cw_test(psa_cfg.get('connectwise', {}))
    if provider == 'autotask':
        return _at_test(psa_cfg.get('autotask', {}))
    if provider == 'halopsa':
        return _halo_test(psa_cfg.get('halopsa', {}))
    return False, f'Unknown PSA provider: {provider!r}'


# ── ConnectWise Manage ────────────────────────────────────────────────────────

def _cw_base_url(cfg: dict) -> str:
    site = cfg.get('site', 'na.myconnectwise.net').rstrip('/')
    return f'https://{site}/v4_6_release/apis/3.0'


def _cw_headers(cfg: dict) -> dict:
    token = base64.b64encode(
        f'{cfg.get("company_id", "")}+{cfg.get("public_key", "")}:{cfg.get("private_key", "")}'.encode()
    ).decode()
    return {
        'Authorization': f'Basic {token}',
        'Content-Type':  'application/json',
        'clientId':      cfg.get('client_id', ''),
    }


def _cw_create_ticket(cfg: dict, finding: dict, hostname: str) -> tuple[bool, str]:
    required = ('company_id', 'public_key', 'private_key', 'client_id', 'service_board', 'company_name')
    if missing := [k for k in required if not cfg.get(k)]:
        return False, f'ConnectWise config missing: {", ".join(missing)}'

    sev      = finding.get('severity', 'HIGH')
    check_id = finding.get('check_id', '')
    title    = finding.get('title', '')
    desc     = finding.get('description', finding.get('remediation', ''))

    summary = f'[Arckon] {sev}: {check_id}' + (f' — {title}' if title else '') + f' on {hostname}'
    body = {
        'summary': summary[:100],
        'initialDescription': (
            f'Arckon AI Security scan detected a {sev} finding on {hostname}.\n\n'
            f'Check ID: {check_id}\nTitle: {title}\n\n'
            + (f'Details:\n{desc}\n\n' if desc else '')
            + 'Log in to Arckon to view full details and remediation steps.'
        ),
        'board':    {'name': cfg['service_board']},
        'company':  {'identifier': cfg['company_name']},
        'priority': {'name': 'Critical' if sev == 'CRITICAL' else 'High'},
        'status':   {'name': 'New'},
    }
    return _http_post(f'{_cw_base_url(cfg)}/service/tickets', body, _cw_headers(cfg), 'ConnectWise')


def _cw_test(cfg: dict) -> tuple[bool, str]:
    if missing := [k for k in ('company_id', 'public_key', 'private_key', 'client_id') if not cfg.get(k)]:
        return False, f'ConnectWise config missing: {", ".join(missing)}'
    try:
        req = urllib.request.Request(f'{_cw_base_url(cfg)}/system/info', headers=_cw_headers(cfg))
        with urllib.request.urlopen(req, timeout=10) as r:
            return (True, 'ConnectWise connection successful') if 200 <= r.status < 300 \
                else (False, f'ConnectWise returned HTTP {r.status}')
    except Exception as e:
        return False, f'ConnectWise connection failed: {e}'


# ── Autotask PSA ──────────────────────────────────────────────────────────────

def _at_base_url(cfg: dict) -> str:
    return f'https://{cfg.get("zone", "webservices2")}.autotask.net/ATServicesRest/V1.0'


def _at_headers(cfg: dict) -> dict:
    return {
        'UserName':     cfg.get('username', ''),
        'Secret':       cfg.get('api_key', ''),
        'Content-Type': 'application/json',
    }


def _at_create_ticket(cfg: dict, finding: dict, hostname: str) -> tuple[bool, str]:
    required = ('username', 'api_key', 'account_id', 'queue_id')
    if missing := [k for k in required if not cfg.get(k)]:
        return False, f'Autotask config missing: {", ".join(missing)}'

    sev      = finding.get('severity', 'HIGH')
    check_id = finding.get('check_id', '')
    title    = finding.get('title', '')
    desc     = finding.get('description', finding.get('remediation', ''))

    ticket_title = f'[Arckon] {sev}: {check_id}' + (f' — {title}' if title else '') + f' on {hostname}'
    body = {
        'title':       ticket_title[:255],
        'description': (
            f'Arckon AI Security scan detected a {sev} finding on {hostname}.\n\n'
            f'Check ID: {check_id}\nTitle: {title}\n\n'
            + (f'Details:\n{desc}\n\n' if desc else '')
            + 'Log in to Arckon to view full details and remediation steps.'
        ),
        'accountID': int(cfg['account_id']),
        'queueID':   int(cfg['queue_id']),
        'priority':  int(cfg.get('priority_id', 1)),
        'status':    1,
        'issuetype': 1,
    }
    return _http_post(f'{_at_base_url(cfg)}/Tickets', body, _at_headers(cfg), 'Autotask')


def _at_test(cfg: dict) -> tuple[bool, str]:
    if missing := [k for k in ('username', 'api_key') if not cfg.get(k)]:
        return False, f'Autotask config missing: {", ".join(missing)}'
    url = f'{_at_base_url(cfg)}/zoneInformation?user={urllib.parse.quote(cfg["username"])}'
    try:
        req = urllib.request.Request(url, headers=_at_headers(cfg))
        with urllib.request.urlopen(req, timeout=10) as r:
            return (True, 'Autotask connection successful') if 200 <= r.status < 300 \
                else (False, f'Autotask returned HTTP {r.status}')
    except Exception as e:
        return False, f'Autotask connection failed: {e}'


# ── HaloPSA ───────────────────────────────────────────────────────────────────

def _halo_base_url(cfg: dict) -> str:
    return f'https://{cfg.get("tenant", "").rstrip("/")}.halopsa.com/api'


def _halo_get_token(cfg: dict) -> Optional[str]:
    url  = f'https://{cfg.get("tenant", "")}.halopsa.com/auth/token'
    data = urllib.parse.urlencode({
        'grant_type':    'client_credentials',
        'client_id':     cfg.get('client_id', ''),
        'client_secret': cfg.get('client_secret', ''),
        'scope':         'all',
    }).encode()
    try:
        req = urllib.request.Request(
            url, data=data,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            method='POST',
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read().decode()).get('access_token')
    except Exception as e:
        log.error('HaloPSA token fetch failed: %s', e)
        return None


def _halo_create_ticket(cfg: dict, finding: dict, hostname: str) -> tuple[bool, str]:
    required = ('tenant', 'client_id', 'client_secret')
    if missing := [k for k in required if not cfg.get(k)]:
        return False, f'HaloPSA config missing: {", ".join(missing)}'

    token = _halo_get_token(cfg)
    if not token:
        return False, 'HaloPSA authentication failed — check client_id and client_secret'

    sev      = finding.get('severity', 'HIGH')
    check_id = finding.get('check_id', '')
    title    = finding.get('title', '')
    desc     = finding.get('description', finding.get('remediation', ''))

    summary = f'[Arckon] {sev}: {check_id}' + (f' — {title}' if title else '') + f' on {hostname}'
    body = [{
        'summary':        summary[:150],
        'details':        (
            f'Arckon AI Security scan detected a {sev} finding on {hostname}.\n\n'
            f'Check ID: {check_id}\nTitle: {title}\n\n'
            + (f'Details:\n{desc}\n\n' if desc else '')
            + 'Log in to Arckon to view full details and remediation steps.'
        ),
        'tickettype_id': int(cfg.get('ticket_type_id', 1)),
        'priority_id':   int(cfg.get('priority_id', 1)),
    }]
    return _http_post(
        f'{_halo_base_url(cfg)}/Tickets', body,
        {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'},
        'HaloPSA',
    )


def _halo_test(cfg: dict) -> tuple[bool, str]:
    required = ('tenant', 'client_id', 'client_secret')
    if missing := [k for k in required if not cfg.get(k)]:
        return False, f'HaloPSA config missing: {", ".join(missing)}'
    token = _halo_get_token(cfg)
    if not token:
        return False, 'HaloPSA authentication failed — check client_id and client_secret'
    try:
        req = urllib.request.Request(
            f'{_halo_base_url(cfg)}/TicketType',
            headers={'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'},
        )
        with urllib.request.urlopen(req, timeout=10) as r:
            return (True, 'HaloPSA connection successful') if 200 <= r.status < 300 \
                else (False, f'HaloPSA returned HTTP {r.status}')
    except Exception as e:
        return False, f'HaloPSA connection failed: {e}'


# ── HTTP helper ───────────────────────────────────────────────────────────────

def _http_post(url: str, body, headers: dict, label: str) -> tuple[bool, str]:
    data = json.dumps(body).encode()
    req  = urllib.request.Request(url, data=data, headers=headers, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            if 200 <= r.status < 300:
                return True, f'{label} ticket created'
            return False, f'{label} returned HTTP {r.status}'
    except urllib.error.HTTPError as e:
        detail = ''
        try:
            detail = e.read().decode(errors='replace')[:200]
        except Exception:
            pass
        log.error('%s ticket creation failed: HTTP %s %s', label, e.code, detail)
        return False, f'{label} HTTP {e.code}: {detail}'
    except Exception as e:
        log.error('%s ticket creation failed: %s', label, e)
        return False, f'{label} error: {e}'
