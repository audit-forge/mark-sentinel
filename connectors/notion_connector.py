"""
RiskRaven Arckon — Notion Connector
Creates a page (in a database or under a parent page) for each CRITICAL
or HIGH finding, using the same canned-response content shared with
chat alerts and PSA tickets (see alerts.py's _build_canned_response).

Mirrors connectors/psa_connector.py's shape exactly: a routing entry
point (create_page/test_connection), provider-specific helpers, and the
same urllib-only HTTP style — no new dependency for a single connector.

Config (inside alerts_config.json under key "notion"):
{
  "token":          "secret_...",          // Notion integration token
  "parent_type":    "page" | "database",   // default: "page"
  "page_id":        "...",                 // required if parent_type == "page"
  "database_id":    "...",                 // required if parent_type == "database"
  "title_property": "Name"                 // database only — the title
                                            // column's name, which varies
                                            // per database (Notion has no
                                            // fixed name for it); default
                                            // "Name" matches a fresh
                                            // database's default column.
}

Setup: create an integration at notion.so/my-integrations, copy its
"Internal Integration Secret" as `token`, then share the target page or
database with that integration (the page/database's ••• menu →
Connections) — a valid token alone is not enough; Notion also requires
the integration to be explicitly invited to whatever it should write to.
That second step is exactly the kind of "your environment, your call"
step this whole feature exists to demonstrate takes minutes, not
engineering effort.
"""
import json
import logging
import re
import urllib.error
import urllib.request

log = logging.getLogger('sentinel.notion')

_API_BASE = 'https://api.notion.com/v1'
_NOTION_VERSION = '2022-06-28'

_LABEL_VALUE_RE = re.compile(r'^\*\*(.+?):\*\*\s*(.*)$')
_WHOLE_BOLD_RE = re.compile(r'^\*\*(.+)\*\*$')
_PREFIX_BOLD_RE = re.compile(r'^\*\*(.+?)\*\*(.*)$')


def _headers(cfg: dict) -> dict:
    return {
        'Authorization':  f'Bearer {cfg.get("token", "")}',
        'Notion-Version': _NOTION_VERSION,
        'Content-Type':   'application/json',
    }


def _rich_text_for_line(line: str) -> list[dict]:
    """Turns one canned-response markdown line into a Notion rich_text
    run list, preserving the label:value bold/plain split
    _build_canned_response() already produces (e.g. "**Category:** X"
    -> bold "Category:" + plain " X"), rather than flattening everything
    to plain text or requiring a full markdown parser for an MVP."""
    m = _LABEL_VALUE_RE.match(line)
    if m:
        label, value = m.group(1), m.group(2)
        runs = [{'type': 'text', 'text': {'content': f'{label}: '}, 'annotations': {'bold': True}}]
        if value:
            runs.append({'type': 'text', 'text': {'content': value}})
        return runs
    m = _WHOLE_BOLD_RE.match(line)
    if m:
        return [{'type': 'text', 'text': {'content': m.group(1)}, 'annotations': {'bold': True}}]
    # The header line ("**summary** on `device`") is bold-prefix + plain
    # suffix, neither a pure label:value nor a fully-bold line — without
    # this case it fell through to the plain catch-all below with the
    # literal ** markers visible instead of rendering as bold.
    m = _PREFIX_BOLD_RE.match(line)
    if m:
        bold, rest = m.group(1), m.group(2)
        runs = [{'type': 'text', 'text': {'content': bold}, 'annotations': {'bold': True}}]
        if rest:
            runs.append({'type': 'text', 'text': {'content': rest}})
        return runs
    return [{'type': 'text', 'text': {'content': line}}]


def _body_to_blocks(body_markdown: str) -> list[dict]:
    blocks = []
    for line in body_markdown.split('\n\n'):
        line = line.strip()
        if not line:
            continue
        blocks.append({
            'object': 'block',
            'type': 'paragraph',
            'paragraph': {'rich_text': _rich_text_for_line(line)},
        })
    return blocks


def create_page(notion_cfg: dict, finding: dict, hostname: str) -> tuple[bool, str]:
    """Create a Notion page for a finding. Returns (ok, message).
    `finding` is the same enriched dict alerts.py builds for PSA tickets
    (check_id/title/severity/description, where description is already
    the canned-response detail_text) — reused here rather than a
    Notion-specific shape, so this connector doesn't drift from what
    chat/PSA already send."""
    parent_type = (notion_cfg.get('parent_type') or 'page').lower()
    token = notion_cfg.get('token', '')
    if not token:
        return False, 'Notion config missing: token'
    if parent_type == 'database':
        if not notion_cfg.get('database_id'):
            return False, 'Notion config missing: database_id'
        parent = {'database_id': notion_cfg['database_id']}
        title_prop = notion_cfg.get('title_property', 'Name')
    elif parent_type == 'page':
        if not notion_cfg.get('page_id'):
            return False, 'Notion config missing: page_id'
        parent = {'page_id': notion_cfg['page_id']}
        title_prop = 'title'
    else:
        return False, f'Unknown Notion parent_type: {parent_type!r} (expected "page" or "database")'

    sev      = finding.get('severity', 'HIGH')
    check_id = finding.get('check_id', '')
    title    = finding.get('title', '')
    body     = finding.get('description', finding.get('remediation', ''))

    page_title = f'[Arckon] {sev}: {check_id}' + (f' — {title}' if title else '') + f' on {hostname}'
    title_block = {'title': [{'type': 'text', 'text': {'content': page_title[:200]}}]}

    payload = {
        'parent': parent,
        'properties': {title_prop: title_block},
        'children': _body_to_blocks(body) if body else [],
    }
    return _http_post(f'{_API_BASE}/pages', payload, _headers(notion_cfg), 'Notion')


def test_connection(notion_cfg: dict) -> tuple[bool, str]:
    """Test Notion connectivity without creating a page. Verifies the
    token itself is valid via GET /v1/users/me — does NOT confirm the
    configured page_id/database_id has been shared with the integration
    (Notion requires that as a separate step; a token can be perfectly
    valid while still being unable to write to an un-shared parent, and
    that failure only surfaces on an actual create_page call)."""
    token = notion_cfg.get('token', '')
    if not token:
        return False, 'Notion config missing: token'
    try:
        req = urllib.request.Request(f'{_API_BASE}/users/me', headers=_headers(notion_cfg))
        with urllib.request.urlopen(req, timeout=10) as r:
            if 200 <= r.status < 300:
                data = json.loads(r.read().decode())
                name = data.get('name') or data.get('bot', {}).get('owner', {}).get('type', 'integration')
                return True, f'Notion connection successful (authenticated as {name})'
            return False, f'Notion returned HTTP {r.status}'
    except urllib.error.HTTPError as e:
        detail = ''
        try:
            detail = e.read().decode(errors='replace')[:200]
        except Exception:
            pass
        return False, f'Notion connection failed: HTTP {e.code} {detail}'
    except Exception as e:
        return False, f'Notion connection failed: {e}'


# ── HTTP helper — mirrors connectors/psa_connector.py's _http_post ───────────

def _http_post(url: str, body, headers: dict, label: str) -> tuple[bool, str]:
    data = json.dumps(body).encode()
    req  = urllib.request.Request(url, data=data, headers=headers, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            if 200 <= r.status < 300:
                return True, f'{label} page created'
            return False, f'{label} returned HTTP {r.status}'
    except urllib.error.HTTPError as e:
        detail = ''
        try:
            detail = e.read().decode(errors='replace')[:200]
        except Exception:
            pass
        log.error('%s page creation failed: HTTP %s %s', label, e.code, detail)
        return False, f'{label} HTTP {e.code}: {detail}'
    except Exception as e:
        log.error('%s page creation failed: %s', label, e)
        return False, f'{label} error: {e}'
