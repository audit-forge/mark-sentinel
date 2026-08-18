#!/usr/bin/env python3
"""
Arckon by RiskRaven — Dashboard Server
Serves the live dashboard and runs on-demand scans via a browser UI.

Usage:
  python3 server.py                   # serves latest results on :7331
  python3 server.py --port 8080       # custom port
  python3 server.py --no-browser      # don't auto-open browser
"""
import sys
if sys.version_info < (3, 11):
    sys.exit(
        "Arckon requires Python 3.11 or later.\n"
        f"Running: Python {sys.version.split()[0]}\n"
        "Install: https://python.org/downloads/"
    )
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

# Auto-install packages that aren't part of stdlib but are required for full
# functionality. Runs with the same Python binary that launched the server so
# app-bundle and venv environments get the right site-packages.
def _ensure_packages():
    import importlib
    import subprocess as _sp
    import os as _os
    import time as _time
    _needed = [('fpdf', 'fpdf2'), ('yaml', 'pyyaml')]
    installed_any = False
    for module, package in _needed:
        try:
            importlib.import_module(module)
        except ImportError:
            print(f'[sentinel] installing {package}…', flush=True)
            r = _sp.run([sys.executable, '-m', 'pip', 'install', package, '-q'],
                        capture_output=True)
            if r.returncode == 0:
                installed_any = True
            else:
                print(f'[sentinel] pip failed: {r.stderr.decode(errors="replace").strip()}', flush=True)
    if installed_any:
        # Newly installed packages aren't visible to the running interpreter —
        # restart immediately so the next launch finds them in site-packages.
        print('[sentinel] packages installed — restarting…', flush=True)
        _time.sleep(0.5)
        if sys.platform == 'win32':
            _sp.Popen([sys.executable] + sys.argv,
                      creationflags=_sp.CREATE_NEW_PROCESS_GROUP)
            _os._exit(0)
        else:
            _os.execv(sys.executable, [sys.executable] + sys.argv)

_ensure_packages()

import http.server
import json
import logging
import os
import hmac
import mimetypes
import subprocess
import threading
import time
import webbrowser
from collections import defaultdict
from datetime import date, datetime, timezone
from pathlib import Path
from urllib.parse import unquote, urlparse

PORT = 7001


def _compiled_cmd(script: Path) -> list:
    """Return command prefix for a script — uses compiled binary if present, else Python."""
    binary = script.with_suffix('')
    if binary.exists() and not binary.is_dir():
        return [str(binary)]
    return [sys.executable, str(script)]
ROOT = Path(__file__).parent
RELEASE_DIR = ROOT / 'releases' / 'current'
_serve_port = PORT   # updated at startup so handlers can reference it

# A baseline is one normal endpoint profile per customer. Container profiles
# remain opt-in commands because they need different discovery semantics.
_BASELINE_PROFILES = frozenset({
    'default', 'fedramp', 'fedramp_20x', 'cmmc', 'financial',
    'professional_services', 'healthcare', 'biotech', 'lifesciences',
    'owasp_agentic', 'eu_ai_act', 'iso42001', 'atlas',
})
_BASELINE_PROFILE_PATH = ROOT / 'data' / 'baseline_profile.json'


def _load_baseline_profile() -> str:
    try:
        profile = json.loads(_BASELINE_PROFILE_PATH.read_text(encoding='utf-8')).get('profile')
        if profile in _BASELINE_PROFILES:
            return profile
    except (OSError, ValueError, AttributeError):
        pass
    return 'default'


def _save_baseline_profile(profile: str) -> None:
    _BASELINE_PROFILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    temp_path = _BASELINE_PROFILE_PATH.with_suffix('.tmp')
    temp_path.write_text(json.dumps({'profile': profile}, indent=2) + '\n', encoding='utf-8')
    temp_path.replace(_BASELINE_PROFILE_PATH)


def _is_container_device(device: dict) -> bool:
    hostname = device.get('hostname', '')
    return hostname.startswith('docker:') or hostname.startswith('k8s:')


def _release_file(request_path: str, platform: str | None = None) -> Path | None:
    """Resolve a release path under the platform-specific directory without traversal.

    If platform is given (linux/macos/windows), files are served from
    releases/<platform>/ instead of the legacy releases/current/.
    """
    prefix = '/releases/current/'
    platform_prefix = '/releases/'
    if request_path.startswith(platform_prefix) and not request_path.startswith(prefix):
        rel = unquote(request_path[len(platform_prefix):]).lstrip('/')
        parts = rel.split('/', 1)
        if len(parts) == 2:
            plat, filename = parts
            if plat in ('linux', 'macos', 'windows') and filename:
                root = (ROOT / 'releases' / plat).resolve()
                candidate = (root / filename).resolve()
                if candidate.is_relative_to(root) and candidate.is_file():
                    return candidate
    if not request_path.startswith(prefix):
        return None
    relative = unquote(request_path[len(prefix):])
    if not relative:
        return None
    root = RELEASE_DIR.resolve()
    candidate = (root / relative).resolve()
    if not candidate.is_relative_to(root) or not candidate.is_file():
        return None
    return candidate

log = logging.getLogger('sentinel.server')

# ── login rate limiting ───────────────────────────────────────────────────────
_login_attempts: dict[str, list[float]] = defaultdict(list)
_LOGIN_WINDOW  = 300   # 5 minutes
_LOGIN_MAX     = 10    # max attempts before lockout
_LOCKOUT_SECS  = 600   # 10 minute lockout

def _login_allowed(ip: str) -> bool:
    now = time.time()
    recent = [t for t in _login_attempts[ip] if now - t < _LOGIN_WINDOW]
    _login_attempts[ip] = recent
    return len(recent) < _LOGIN_MAX

def _login_failed(ip: str) -> None:
    _login_attempts[ip].append(time.time())

# ── scan state ────────────────────────────────────────────────────────────────
_lock   = threading.Lock()
_status = 'idle'       # idle | running | done | error
_log: list[str] = []
# ─────────────────────────────────────────────────────────────────────────────

# ── agent store (lazy init) ───────────────────────────────────────────────────
_store_cache: dict = {}
_store_cache_lock = threading.Lock()
_registry = None
_registry_lock = threading.Lock()


def _get_registry():
    global _registry
    if _registry is None:
        with _registry_lock:
            if _registry is None:
                from storage import CustomerRegistry
                _registry = CustomerRegistry(ROOT / 'data' / 'customers.db')
    return _registry


def _get_store(customer_id: str = 'default'):
    with _store_cache_lock:
        if customer_id not in _store_cache:
            from storage import AgentStore
            db_path = ROOT / 'data' / 'customers' / customer_id / 'agents.db'
            _store_cache[customer_id] = AgentStore(db_path)
    return _store_cache[customer_id]


_device_store_map: dict[str, str] = {}  # device_id → customer_id
_device_store_map_lock = threading.Lock()

def _get_store_for_device(device_id: str):
    """Return the AgentStore that owns device_id, searching all customer dirs if needed."""
    with _device_store_map_lock:
        if device_id in _device_store_map:
            return _get_store(_device_store_map[device_id])

    # Check default first (fast path for single-tenant setups)
    default_store = _get_store('default')
    if default_store.is_known_device(device_id):
        with _device_store_map_lock:
            _device_store_map[device_id] = 'default'
        return default_store

    # Scan all customer directories for the device
    customers_dir = ROOT / 'data' / 'customers'
    if customers_dir.exists():
        for cust_dir in customers_dir.iterdir():
            if not cust_dir.is_dir() or cust_dir.name == 'default':
                continue
            db = cust_dir / 'agents.db'
            if not db.exists():
                continue
            store = _get_store(cust_dir.name)
            if store.is_known_device(device_id):
                with _device_store_map_lock:
                    _device_store_map[device_id] = cust_dir.name
                return store

    # Fall back to default (will create device there on touch)
    return default_store


# ── license (loaded once at startup) ─────────────────────────────────────────
def _load_license() -> None:
    from license import load_license
    load_license(ROOT / 'license.json')

def _has_technical_reports() -> bool:
    """Return True if this license includes Technical reports and remediation. Defaults True."""
    try:
        from license import get_license
        return get_license().has_technical_reports
    except Exception:
        return True

def _is_demo() -> bool:
    """Return True when running in demo mode."""
    try:
        from license import get_license
        return get_license().is_demo
    except Exception:
        return False

def _has_evidence_package() -> bool:
    """Return True when the license allows Evidence Package export. Defaults True."""
    try:
        from license import get_license
        return get_license().has_evidence_package
    except Exception:
        return True


def _has_live_scan() -> bool:
    """Return True when the license allows live adversarial probe scans (Plus only)."""
    try:
        from license import get_license
        return get_license().has_live_scan
    except Exception:
        return True


_LIVE_SCAN_CFG_PATH = ROOT / 'data' / 'live_scan_config.json'

def _load_live_scan_config() -> dict:
    try:
        if _LIVE_SCAN_CFG_PATH.exists():
            return json.loads(_LIVE_SCAN_CFG_PATH.read_text())
    except Exception:
        pass
    return {}

def _save_live_scan_config(cfg: dict) -> None:
    _LIVE_SCAN_CFG_PATH.parent.mkdir(parents=True, exist_ok=True)
    safe = {k: str(v)[:2048] for k, v in cfg.items() if k in ('mode', 'api_key', 'endpoint', 'model')}
    _LIVE_SCAN_CFG_PATH.write_text(json.dumps(safe, indent=2))

def _content_length(headers) -> int:
    """Safely parse Content-Length header; returns 0 on missing or invalid value."""
    try:
        return max(0, int(headers.get('Content-Length', 0)))
    except (ValueError, TypeError):
        return 0


_SPEND_SECRET_ROOT = Path(os.environ.get('SENTINEL_SPEND_SECRET_DIR', '/opt/sentinel-secrets/spend'))


def _spend_customer_dir(customer_id: str) -> Path:
    """Return the per-customer directory used by this customer's AgentStore."""
    return ROOT / 'data' / 'customers' / customer_id


def _spend_config_path(customer_id: str) -> Path:
    return _spend_customer_dir(customer_id) / 'spend_config.json'


def _spend_budget_path(customer_id: str) -> Path:
    return _spend_customer_dir(customer_id) / 'spend_budget.json'


def _spend_fetch_state_path(customer_id: str) -> Path:
    return _spend_customer_dir(customer_id) / 'spend_last_fetch.txt'


def _spend_secret_dir(customer_id: str) -> Path:
    # Hash this path component so no user-controlled string can influence it.
    import hashlib
    return _SPEND_SECRET_ROOT / hashlib.sha256(customer_id.encode()).hexdigest()


def _load_spend_config(customer_id: str) -> dict:
    """Load the redacted AI spend provider configuration from disk.

    The config contains only redacted key entries (key_hash + key_last4 +
    api_key_env / api_key_file). Full keys are never stored in this file. This
    function returns the redacted config as-is; key resolution happens at
    fetch time via connectors.key_store.resolve_key().
    """
    from connectors import key_store
    return key_store.load_config(_spend_config_path(customer_id))


def _fetch_all_spend(config: dict, days: int) -> list[dict]:
    """Fetch spend records from all configured providers, tagging each record
    with the client_org_id of the key that produced it."""
    from datetime import date, timedelta
    from connectors import key_store
    from connectors.openai_cost_connector import OpenAICostConnector
    from connectors.anthropic_cost_connector import AnthropicCostConnector
    from connectors.gemini_cost_connector import GeminiCostConnector
    from connectors.ollama_cost_connector import OllamaCostConnector

    end = date.today()
    start = end - timedelta(days=days - 1)
    all_records: list = []

    mapping = {
        'openai': OpenAICostConnector,
        'anthropic': AnthropicCostConnector,
        'gemini': GeminiCostConnector,
        'ollama': OllamaCostConnector,
    }

    redacted_keys = key_store.config_to_redacted_keys(config)
    for rec in redacted_keys:
        provider = rec.provider
        if provider not in mapping:
            continue
        cls = mapping[provider]
        try:
            if provider == 'ollama':
                connector = cls(base_url='http://localhost:11434')
            else:
                full_key = key_store.resolve_key(rec)
                if not full_key:
                    log.warning('spend fetch: no resolvable key for %s/%s',
                                provider, rec.client_org_id)
                    continue
                connector = cls(api_key=full_key)
                del full_key
            records = connector.fetch_usage(start, end)
            for r in records:
                d = r.to_dict()
                d['client_org_id'] = rec.client_org_id
                d['key_id'] = rec.key_hash[:16]
                d['key_label'] = rec.label
                d['key_last4'] = rec.key_last4
                all_records.append(d)
        except Exception as e:
            log.warning('spend fetch failed for %s/%s: %s',
                        provider, rec.client_org_id, e)

    return all_records


def _agent_token() -> str:
    """Return legacy single-token value. Empty string means no auth configured.
    Prefer SENTINEL_AGENT_TOKEN_FILE over a plain env var — env values are
    visible via docker inspect and /proc (Arckon's own AI-DOCKER-006 check)."""
    if os.environ.get('SENTINEL_AGENT_TOKEN'):
        return os.environ['SENTINEL_AGENT_TOKEN']
    tok_path = os.environ.get('SENTINEL_AGENT_TOKEN_FILE', '')
    if tok_path:
        try:
            p = Path(tok_path)
            if p.is_file():
                return p.read_text().strip()
        except OSError:
            pass
    for tok_file in (ROOT / 'agent_token.txt', ROOT / 'data' / 'agent_token.txt'):
        if tok_file.exists():
            return tok_file.read_text().strip()
    return ''


def _check_agent_token(submitted: str) -> bool:
    """Return True if submitted token is valid (single-token or multi-token store)."""
    if not submitted:
        return False
    import hmac as _hmac
    # Check legacy single token
    single = _agent_token()
    if single and _hmac.compare_digest(submitted, single):
        return True
    # Check multi-token store (tokens.py)
    store_path_env = os.environ.get('SENTINEL_TOKEN_STORE', '')
    store_path = Path(store_path_env) if store_path_env else ROOT / 'output' / 'agent_tokens.json'
    if store_path.exists():
        try:
            import json as _json
            from datetime import date as _date
            data = _json.loads(store_path.read_text())
            for t in data.get('tokens', []):
                tok = t.get('token', '')
                if not tok:
                    continue
                expires = t.get('expires_at')
                if expires and expires < str(_date.today()):
                    continue
                if _hmac.compare_digest(submitted, tok):
                    return True
        except Exception:
            pass
    return False

def _get_session_cookie(headers) -> str:
    for part in headers.get('Cookie', '').split(';'):
        k, _, v = part.strip().partition('=')
        if k.strip() == 'sentinel_session':
            return v.strip()
    return ''


def _get_cookie(headers, name: str) -> str:
    for part in headers.get('Cookie', '').split(';'):
        k, _, v = part.strip().partition('=')
        if k.strip() == name:
            return v.strip()
    return ''

# ── per-device report rate limiting ──────────────────────────────────────────
_report_last_seen: dict[str, float] = {}
_report_lock = threading.Lock()
_REPORT_MIN_INTERVAL = 60  # seconds between accepted reports per device
# ─────────────────────────────────────────────────────────────────────────────


def _latest_out_dir() -> Path | None:
    """Legacy compatibility hook; generated demo reports are never served."""
    return None


def _rebuild_dashboard(out_dir: Path) -> bool:
    try:
        sys.path.insert(0, str(ROOT))
        from output.dashboard import generate
        label_map = {
            'config_scan':           'Config Scan',
            'openai':                'ChatGPT (gpt-4o-2024-11-20)',
            'claude':                'Anthropic (claude-sonnet-4-6)',
            'ollama___qwen2.5-7b':   'Ollama (qwen2.5-7b)',
            'hash-ai':               'Hash-AI',
        }
        reports = []
        for f in sorted(out_dir.glob('*.json')):
            try:
                data = json.loads(f.read_text())
                if '_provider_label' not in data:
                    data['_provider_label'] = label_map.get(f.stem.lower(), f.stem)
                reports.append(data)
            except Exception:
                pass
        if reports:
            generate(reports, out_dir / 'dashboard.html')
            return True
    except Exception as e:
        log.error('dashboard rebuild error: %s', e)
    return False


_SEV_ORDER_REPORT = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
_SEV_COLOR_HTML = {'CRITICAL': '#f85149', 'HIGH': '#d29922', 'MEDIUM': '#58a6ff', 'LOW': '#3fb950', 'INFO': '#6e7681'}
_STATUS_COLOR_HTML = {'FAIL': '#f85149', 'WARN': '#d29922', 'PASS': '#58a6ff', 'SKIP': '#6e7681', 'N/A': '#444c56'}
_STATUS_LABEL_HTML = {'FAIL': 'HIGH RISK', 'WARN': 'MEDIUM RISK', 'PASS': 'PASS', 'SKIP': 'SKIP', 'N/A': 'N/A'}

# ── Shared theme constants injected into every HTML page ──────────────────────
_LIGHT_MODE_CSS = (
    'html.light body{background:#fff;color:#24292f}'
    'html.light h1{color:#0969da}'
    'html.light h2{color:#0969da;border-color:#d0d7de}'
    'html.light h3{color:#57606a}'
    'html.light .meta{color:#57606a}'
    'html.light .toolbar{background:#f6f8fa;border-color:#d0d7de}'
    'html.light .card{background:#f6f8fa;border-color:#d0d7de}'
    'html.light .card-l{color:#57606a}'
    'html.light th{background:#f6f8fa;color:#57606a;border-color:#d0d7de}'
    'html.light td{border-color:#eaeef2}'
    'html.light tr:hover td{background:#f6f8fa}'
    'html.light .block{background:#f6f8fa;border-color:#d0d7de}'
    'html.light .tag{background:#f6f8fa;border-color:#d0d7de;color:#24292f}'
    'html.light .device-block{background:#f6f8fa;border-color:#d0d7de}'
    'html.light .finding{border-color:#d0d7de}'
    'html.light .det{color:#57606a}'
    'html.light .rem{color:#1a7f37}'
    'html.light .no-auth{color:#cf222e}'
    'html.light .unknown{color:#9a6700}'
    'html.light .auth-ok{color:#1a7f37}'
)
_THEME_EARLY_SCRIPT = (
    "<script>if(localStorage.getItem('sentinel_theme')==='light')"
    "document.documentElement.classList.add('light');</script>"
)
_THEME_TOGGLE_JS = (
    "function _applyTheme(l){"
    "document.documentElement.classList.toggle('light',l);"
    "if(document.body){"
    "document.body.classList.toggle('light',l);"
    "document.body.style.background=l?'#fff':'#0d1117';"
    "document.body.style.color=l?'#24292f':'#c9d1d9';}"
    "var b=document.getElementById('theme-toggle');"
    "if(b){b.textContent=l?'⬛ Dark':'☀ Light';"
    "b.style.background=l?'#f6f8fa':'#21262d';"
    "b.style.color=l?'#24292f':'#8b949e';}"
    "var tb=document.querySelector('.toolbar');"
    "if(tb){"
    "tb.style.background=l?'#f6f8fa':'#161b22';"
    "tb.querySelectorAll('button:not(#theme-toggle)').forEach(function(n){"
    "n.style.background=l?'#eef1f4':'#21262d';"
    "n.style.color=l?'#24292f':'#c9d1d9';"
    "n.style.borderColor=l?'#c8ccd0':'#30363d';});"
    "tb.querySelectorAll('span,label').forEach(function(n){"
    "n.style.color=l?'#57606a':null;});}}"
    "function toggleTheme(){"
    "var l=!document.documentElement.classList.contains('light');"
    "localStorage.setItem('sentinel_theme',l?'light':'dark');"
    "_applyTheme(l);}"
    "document.addEventListener('DOMContentLoaded',function(){"
    "_applyTheme(localStorage.getItem('sentinel_theme')==='light');});"
    "window.addEventListener('storage',function(e){"
    "if(e.key==='sentinel_theme')_applyTheme(e.newValue==='light');});"
    "_applyTheme(localStorage.getItem('sentinel_theme')==='light');"
)
_THEME_BTN = (
    '<button id="theme-toggle" onclick="toggleTheme()" '
    'style="margin-left:auto;background:#21262d;border:1px solid #30363d;'
    'color:#8b949e;border-radius:4px;padding:4px 12px;font-size:12px;cursor:pointer">'
    '☀ Light</button>'
)


def _risk_score_html(fail, warn, total) -> int:
    if not total:
        return 0
    return max(0, 100 - round((fail * 3 + warn) / max(total, 1) * 100))


_MCP_REMEDIATION = {
    'fastmcp':            'Add `auth=BearerAuth(token=os.environ["MCP_TOKEN"])` to your FastMCP server constructor.',
    'uvx':                'Pass `--api-key` flag or configure authentication in the MCP server settings file.',
    'modelcontextprotocol': 'Add OAuth 2.1 or API-key middleware to the MCP server before deploying to a shared network.',
    'default':            'Configure an API key or OAuth 2.1 bearer token on this MCP server. Restrict allowed origins to trusted hosts only.',
}

_OWASP_AGENTIC_MAP = {
    'none':    ['A02 Tool/Plugin Hijacking — unauthenticated server allows arbitrary tool invocation',
                'A08 Excessive Agency — AI can call any exposed tool without authorization check',
                'A07 Data Exfiltration — tools like read_file or query_database accessible with no credentials'],
    'unknown': ['A09 Audit Bypass — authentication status unverified, logging compliance uncertain'],
    'required': [],
}

_EU_AI_ACT_MAP = {
    'none':    'Article 12 (Logging) — unauthenticated MCP servers produce no attributable audit trail; '
               'Article 14 (Human Oversight) — no gate between AI agent and tool execution.',
    'unknown': 'Article 12 (Logging) — authentication status unverified; audit trail completeness cannot be confirmed.',
    'required': 'Compliant with Article 12 and Article 14 access controls.',
}


def _live_scan_settings_html() -> str:
    return ''


def _build_mcp_report_html(servers: list, tier: str) -> str:
    from datetime import datetime, timezone
    import html as _html

    def esc(s):
        return _html.escape(str(s or ''))

    def ts(epoch):
        if not epoch:
            return 'never'
        try:
            return datetime.fromtimestamp(int(epoch), tz=timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
        except Exception:
            return str(epoch)

    now          = datetime.now(tz=timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    tier_label   = {'executive': 'Executive Summary', 'ciso': 'CISO Report', 'technical': 'Technical Findings'}.get(tier, 'MCP Report')
    no_auth      = [s for s in servers if s.get('auth_status') == 'none']
    unknown_auth = [s for s in servers if s.get('auth_status') == 'unknown']
    auth_ok      = [s for s in servers if s.get('auth_status') == 'required']
    [s for s in servers if s.get('source') == 'network']
    [s for s in servers if s.get('source') == 'process']
    all_tools    = sorted({t for s in servers for t in (s.get('tools') or [])})

    risk_level  = 'CRITICAL' if no_auth else 'MEDIUM' if unknown_auth else 'LOW'
    risk_color  = '#f85149' if risk_level == 'CRITICAL' else '#d29922' if risk_level == 'MEDIUM' else '#3fb950'

    btn_style = ('display:inline-block;padding:6px 14px;border-radius:6px;font-size:12px;'
                 'font-weight:600;cursor:pointer;border:1px solid #30363d;background:#21262d;color:#c9d1d9')
    active_btn = 'color:#58a6ff;border-color:#1f6feb'

    parts = [f'''<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>Arckon — MCP & Agent Governance {esc(tier_label)}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#0d1117;color:#c9d1d9;font-family:system-ui,sans-serif;padding:32px;max-width:1100px;margin:0 auto}}
h1{{color:#58a6ff;font-size:22px;margin-bottom:4px}}
h2{{color:#58a6ff;font-size:15px;margin:28px 0 10px;border-bottom:1px solid #21262d;padding-bottom:6px}}
h3{{color:#8b949e;font-size:13px;margin:16px 0 6px}}
.meta{{color:#6e7681;font-size:12px;margin-bottom:28px}}
.cards{{display:flex;gap:16px;flex-wrap:wrap;margin:16px 0 24px}}
.card{{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:16px 24px;min-width:120px}}
.card-n{{font-size:28px;font-weight:700}}
.card-l{{font-size:11px;color:#6e7681;margin-top:4px;text-transform:uppercase}}
table{{width:100%;border-collapse:collapse;font-size:13px;margin-bottom:16px}}
th{{background:#161b22;color:#6e7681;font-size:11px;text-transform:uppercase;padding:8px 10px;text-align:left;border-bottom:1px solid #21262d}}
td{{padding:7px 10px;border-bottom:1px solid #161b22;vertical-align:top}}
tr:hover td{{background:#161b22}}
.no-auth{{color:#f85149}}.unknown{{color:#d29922}}.auth-ok{{color:#3fb950}}
.block{{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:20px;margin-bottom:20px}}
.tag{{display:inline-block;background:#0d1117;border:1px solid #30363d;border-radius:3px;padding:1px 8px;font-size:11px;font-family:monospace;color:#c9d1d9;margin:2px}}
.rem{{color:#3fb950;font-size:12px;margin-top:6px}}
.risk-banner{{border-radius:6px;padding:12px 18px;margin-bottom:24px;font-weight:600}}
.toolbar{{position:sticky;top:0;z-index:100;background:#161b22;border-bottom:1px solid #21262d;
          margin:-32px -32px 28px;padding:10px 32px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}}
@media print{{.toolbar{{display:none}}body{{background:#fff;color:#000;padding:16px}}h1,h2,h3,.card-l{{color:#000}}}}
{_LIGHT_MODE_CSS}
</style>
<script>
function switchTier(t){{location.href='/api/fleet/mcp/report?tier='+t;}}
{_THEME_TOGGLE_JS}
</script>
{_THEME_EARLY_SCRIPT}
</head><body>
<div class="toolbar">
  <span style="font-size:13px;font-weight:600;color:#c9d1d9;margin-right:6px">Arckon</span>
  <button onclick="switchTier('executive')" style="{btn_style}{';' + active_btn if tier=='executive' else ''}">Executive</button>
  <button onclick="switchTier('ciso')"      style="{btn_style}{';' + active_btn if tier=='ciso'      else ''}">CISO</button>
  <button onclick="switchTier('technical')" style="{btn_style}{';' + active_btn if tier=='technical' else ''}">Technical</button>
  <button onclick="window.print()" style="{btn_style}">&#128438; Print</button>
  {_THEME_BTN}
</div>
<h1>Arckon &mdash; MCP &amp; Agent Governance &mdash; {esc(tier_label)}</h1>
<div class="meta">Generated {esc(now)} &nbsp;&bull;&nbsp; {len(servers)} MCP server(s) discovered &nbsp;&bull;&nbsp; Confidential</div>''']

    # Risk banner
    if no_auth:
        parts.append(f'<div class="risk-banner" style="background:#2d0f0f;border:1px solid #f85149;color:#f85149">'
                     f'&#9888;&nbsp; HIGH RISK — {len(no_auth)} unauthenticated MCP server{"s" if len(no_auth)>1 else ""} detected. '
                     f'Any AI agent on the network can invoke exposed tools with no credentials.</div>')
    elif unknown_auth:
        parts.append(f'<div class="risk-banner" style="background:#2a1f0a;border:1px solid #d29922;color:#d29922">'
                     f'&#9888;&nbsp; REVIEW REQUIRED — {len(unknown_auth)} MCP server{"s" if len(unknown_auth)>1 else ""} with unverified authentication.</div>')
    else:
        parts.append('<div class="risk-banner" style="background:#0f2a1a;border:1px solid #3fb950;color:#3fb950">'
                     '&#10003;&nbsp; All MCP servers require authentication.</div>')

    # Summary cards
    parts.append(f'''<div class="cards">
  <div class="card"><div class="card-n" style="color:{risk_color}">{esc(risk_level)}</div><div class="card-l">Risk Level</div></div>
  <div class="card"><div class="card-n" style="color:#58a6ff">{len(servers)}</div><div class="card-l">MCP Servers</div></div>
  <div class="card"><div class="card-n no-auth">{len(no_auth)}</div><div class="card-l">Unauthenticated</div></div>
  <div class="card"><div class="card-n unknown">{len(unknown_auth)}</div><div class="card-l">Auth Unknown</div></div>
  <div class="card"><div class="card-n auth-ok">{len(auth_ok)}</div><div class="card-l">Auth OK</div></div>
  <div class="card"><div class="card-n" style="color:#c9d1d9">{len(all_tools)}</div><div class="card-l">Unique Tools</div></div>
</div>''')

    # ── EXECUTIVE ──────────────────────────────────────────────────────────────
    if tier == 'executive':
        if not servers:
            parts.append('<div class="block"><p>No MCP servers have been discovered on the network. Run a scan from the Sentinel dashboard to populate this report.</p></div>')
        else:
            business_risk = (
                'Your organization has AI agent infrastructure running with <strong>no access controls</strong>. '
                'This means any AI system — or any person with network access — can invoke tools such as '
                + ', '.join(f'<code>{esc(t)}</code>' for t in all_tools[:4])
                + (' and others' if len(all_tools) > 4 else '')
                + ' without any login, token, or approval. This is equivalent to leaving internal APIs '
                'publicly accessible with no password.'
            ) if no_auth else (
                'AI agent infrastructure is present on the network. Authentication controls are in place '
                'or under review. Continued monitoring is recommended as the number of AI agents deployed '
                'is expected to grow significantly in 2026.'
            )

            parts.append(f'<h2>Business Risk</h2><div class="block"><p style="font-size:14px;line-height:1.7">{business_risk}</p></div>')

            if no_auth:
                parts.append('<h2>What Needs to Happen</h2><div class="block"><ol style="padding-left:20px;line-height:2">')
                parts.append('<li>Require authentication (API key or OAuth token) on all MCP servers immediately</li>')
                parts.append('<li>Audit the tools each server exposes — remove any tools that AI agents should not have access to</li>')
                parts.append('<li>Establish a register of approved MCP servers and the teams responsible for them</li>')
                parts.append('<li>Set up logging so every tool call an AI agent makes is recorded with a timestamp and identity</li>')
                parts.append('</ol></div>')

            parts.append('<h2>Regulatory Exposure</h2><div class="block"><p style="font-size:13px;line-height:1.7">')
            if no_auth:
                parts.append('Unauthenticated MCP servers create direct exposure under <strong>EU AI Act Article 12 and 14</strong> '
                             '(logging and human oversight obligations, effective August 2026) and <strong>OWASP Agentic AI A02 and A08</strong> '
                             '(tool hijacking and excessive agency). Organizations in regulated industries should treat this as a priority remediation item.')
            else:
                parts.append('Current MCP server posture is consistent with EU AI Act Article 12 and 14 access control requirements. '
                             'Continue monitoring as additional MCP servers may be deployed by business units without IT knowledge.')
            parts.append('</p></div>')

        parts.append('</body></html>')
        return ''.join(parts)

    # ── CISO ───────────────────────────────────────────────────────────────────
    if not servers:
        parts.append('<div class="block"><p>No MCP servers discovered. Run a scan from the dashboard.</p></div>')
        parts.append('</body></html>')
        return ''.join(parts)

    parts.append('<h2>MCP Server Inventory</h2>')
    parts.append('<table><thead><tr>'
                 '<th>Host / Location</th><th>Server Name</th><th>Auth</th>'
                 '<th>Tools Exposed</th><th>Source</th><th>Reporter</th><th>Last Seen</th>'
                 '</tr></thead><tbody>')
    for s in servers:
        auth   = s.get('auth_status', 'unknown')
        ac     = 'no-auth' if auth == 'none' else 'unknown' if auth == 'unknown' else 'auth-ok'
        al     = 'NO AUTH ⚠' if auth == 'none' else 'Unknown' if auth == 'unknown' else 'Auth OK ✓'
        loc    = f"{esc(s.get('host',''))}:{s.get('port',0)}" if s.get('source') == 'network' else 'Local process'
        name   = esc(s.get('server_name') or '—')
        tools  = s.get('tools') or []
        src    = 'Network' if s.get('source') == 'network' else 'Process'
        parts.append(f'<tr><td><strong>{loc}</strong></td><td style="color:#58a6ff">{name}</td>'
                     f'<td class="{ac}"><strong>{al}</strong></td>'
                     f'<td>{len(tools)} tool{"s" if len(tools) != 1 else ""}'
                     f'{": " + ", ".join(esc(t) for t in tools[:3]) + ("…" if len(tools)>3 else "") if tools else ""}</td>'
                     f'<td style="color:#6e7681">{src}</td>'
                     f'<td style="color:#6e7681">{esc(s.get("reporter_hostname",""))}</td>'
                     f'<td style="color:#6e7681;font-size:12px">{esc(ts(s.get("last_seen")))}</td></tr>')
    parts.append('</tbody></table>')

    if no_auth:
        parts.append('<h2>OWASP Agentic AI Risk Mapping</h2><div class="block">')
        parts.append('<p style="font-size:12px;color:#6e7681;margin-bottom:12px">Unauthenticated MCP servers expose the following OWASP Agentic Top 10 (2026) risks:</p>')
        for risk in _OWASP_AGENTIC_MAP.get('none', []):
            parts.append(f'<div style="padding:6px 0;border-bottom:1px solid #21262d;font-size:13px">'
                         f'<span style="color:#f85149;font-weight:700">&#9888;</span> {esc(risk)}</div>')
        parts.append('</div>')

    parts.append('<h2>EU AI Act Exposure</h2><div class="block">')
    for s in servers:
        auth = s.get('auth_status', 'unknown')
        msg  = _EU_AI_ACT_MAP.get(auth, _EU_AI_ACT_MAP['unknown'])
        loc  = f"{s.get('host','')}:{s.get('port',0)}" if s.get('source') == 'network' else 'Local process'
        color = '#f85149' if auth == 'none' else '#d29922' if auth == 'unknown' else '#3fb950'
        parts.append(f'<div style="padding:8px 0;border-bottom:1px solid #21262d;font-size:13px">'
                     f'<strong style="color:{color}">{esc(loc)}</strong> — {esc(msg)}</div>')
    parts.append('</div>')

    if tier == 'ciso':
        parts.append('</body></html>')
        return ''.join(parts)

    # ── TECHNICAL ──────────────────────────────────────────────────────────────
    parts.append('<h2>Per-Server Technical Detail</h2>')
    for s in servers:
        auth         = s.get('auth_status', 'unknown')
        auth_color   = '#f85149' if auth == 'none' else '#d29922' if auth == 'unknown' else '#3fb950'
        auth_label   = 'NO AUTHENTICATION — HIGH RISK' if auth == 'none' else 'Authentication unverified' if auth == 'unknown' else 'Authentication required — OK'
        loc          = f"{s.get('host','')}:{s.get('port',0)}" if s.get('source') == 'network' else 'Local process'
        tools        = s.get('tools') or []
        server_name  = s.get('server_name') or 'Unknown'
        process_info = s.get('process_info', '')

        # Pick remediation hint from process_info
        fix = _MCP_REMEDIATION['default']
        for key, hint in _MCP_REMEDIATION.items():
            if key != 'default' and key in (process_info or '').lower():
                fix = hint
                break

        parts.append('<div class="block">')
        parts.append(f'<h3>&#128279; {esc(loc)} &mdash; {esc(server_name)}</h3>')
        parts.append('<table style="margin-bottom:12px"><tbody>')
        parts.append(f'<tr><td style="color:#6e7681;width:160px">Auth Status</td><td><strong style="color:{auth_color}">{esc(auth_label)}</strong></td></tr>')
        parts.append(f'<tr><td style="color:#6e7681">Source</td><td>{"Network probe" if s.get("source")=="network" else "Process scan"}</td></tr>')
        parts.append(f'<tr><td style="color:#6e7681">Reporter</td><td>{esc(s.get("reporter_hostname",""))}</td></tr>')
        parts.append(f'<tr><td style="color:#6e7681">First seen</td><td>{esc(ts(s.get("first_seen")))}</td></tr>')
        parts.append(f'<tr><td style="color:#6e7681">Last seen</td><td>{esc(ts(s.get("last_seen")))}</td></tr>')
        if process_info:
            parts.append(f'<tr><td style="color:#6e7681">Process</td><td style="font-family:monospace;font-size:12px">{esc(process_info[:120])}</td></tr>')
        parts.append('</tbody></table>')

        if tools:
            parts.append('<p style="font-size:12px;color:#6e7681;margin-bottom:6px">Tools this server exposes to AI agents:</p>')
            parts.append('<div style="margin-bottom:12px">' + ''.join(f'<span class="tag">{esc(t)}</span>' for t in tools) + '</div>')
            high_risk_tools = [t for t in tools if any(kw in t.lower() for kw in ('exec', 'code', 'shell', 'run', 'write', 'delete', 'email', 'send', 'database', 'db', 'sql'))]
            if high_risk_tools and auth == 'none':
                parts.append('<div style="background:#2d0f0f;border:1px solid #f85149;border-radius:4px;padding:8px 12px;font-size:12px;margin-bottom:10px;color:#f85149">'
                             '&#9888; High-risk tools accessible with no auth: '
                             + ''.join(f'<code style="background:#0d1117;padding:1px 6px;border-radius:3px;margin:0 3px">{esc(t)}</code>' for t in high_risk_tools)
                             + '</div>')
        else:
            parts.append('<p style="font-size:12px;color:#484f58;margin-bottom:12px">Tool list could not be enumerated during scan.</p>')

        owasp_risks = _OWASP_AGENTIC_MAP.get(auth, [])
        if owasp_risks:
            parts.append('<p style="font-size:12px;color:#6e7681;margin-bottom:4px">OWASP Agentic AI risks:</p>')
            for risk in owasp_risks:
                parts.append(f'<div style="font-size:12px;color:#d29922;padding:2px 0">&#9654; {esc(risk)}</div>')
            parts.append('<br>')

        if auth != 'required':
            parts.append(f'<div class="rem"><strong>Remediation:</strong> {esc(fix)}</div>')
            parts.append(f'<div style="font-size:12px;color:#6e7681;margin-top:4px">'
                         f'EU AI Act: {esc(_EU_AI_ACT_MAP.get(auth,""))}</div>')

        parts.append('</div>')

    parts.append('</body></html>')
    return ''.join(parts)


def _build_fleet_report_html(devices: list, tier: str, profile: str = '', profiles: list | None = None, status_filter: str = '', sev_filter: str = '', demo: bool = False) -> str:
    from datetime import datetime, timezone
    import html as _html

    def esc(s):
        return _html.escape(str(s or ''))

    def ts(epoch):
        if not epoch:
            return 'never'
        try:
            return datetime.fromtimestamp(int(epoch), tz=timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
        except Exception:
            return str(epoch)

    _status_label = {'fail': 'High Risk Items', 'warn': 'Medium Risk Items', 'pass': 'Info Items'}.get(status_filter, '')
    _sev_label    = {'ch': 'Critical / High Severity', 'med': 'Medium Severity', 'li': 'Low / Info'}.get(sev_filter, '')
    _tier_base    = {'executive': 'Executive Summary', 'ciso': 'CISO Report', 'technical': 'Technical Findings'}.get(tier, 'Fleet Report')
    _active_label = _sev_label or _status_label
    tier_label    = f'{_tier_base} — {_active_label}' if _active_label else _tier_base
    total_fail = sum(d.get('fail_count', 0) or 0 for d in devices)
    total_warn = sum(d.get('warn_count', 0) or 0 for d in devices)
    total_pass = sum(d.get('pass_count', 0) or 0 for d in devices)
    total_checks = total_fail + total_warn + total_pass
    fleet_score = _risk_score_html(total_fail, total_warn, total_checks)
    score_color = '#3fb950' if fleet_score >= 80 else '#d29922' if fleet_score >= 60 else '#f85149'
    now = datetime.now(tz=timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    active_profiles = profiles or ([profile] if profile else [])

    _rpt_profiles = [('default', 'Base Scan'), ('fedramp', 'FedRAMP'), ('fedramp_20x', 'FedRAMP 20x'), ('cmmc', 'CMMC 2.0'),
                     ('financial', 'Financial'), ('biotech', 'Biotech'), ('healthcare', 'Healthcare'),
                     ('professional_services', 'Professional Services'),
                     ('owasp_agentic', 'OWASP Agentic'), ('eu_ai_act', 'EU AI Act'),
                     ('iso42001', 'ISO 42001'), ('atlas', 'MITRE ATLAS'),
                     ('kubernetes', 'Kubernetes'), ('docker', 'Docker')]
    _toolbar_cbs = ' '.join(
        f'<label style="font-size:12px;color:#c9d1d9;white-space:nowrap;cursor:pointer">'
        f'<input type="checkbox" class="rpt-cb" value="{v}"{" checked" if v in active_profiles else ""}> {lbl}</label>'
        for v, lbl in _rpt_profiles
    )
    _pdf_profile_param = ('&profile=' + ','.join(active_profiles)) if active_profiles else ''
    _pdf_fname_suffix  = ('_' + '_'.join(active_profiles)) if active_profiles else ''
    _profile_label     = ', '.join(p.upper() for p in active_profiles) if active_profiles else ''

    btn_style = 'display:inline-block;padding:6px 14px;border-radius:6px;font-size:12px;font-weight:600;text-decoration:none;cursor:pointer;border:1px solid #30363d;background:#21262d;color:#c9d1d9'

    # Pre-compute severity counts across all devices for stat cards
    _all_pre = []
    for _d in devices:
        _rep = _d.get('_report') or {}
        for _r in _rep.get('findings', _rep.get('results', [])):
            if _r.get('status') != 'SKIP':
                _all_pre.append(_r)
    _cnt_ch  = sum(1 for f in _all_pre if f.get('severity') in ('CRITICAL', 'HIGH'))
    _cnt_med = sum(1 for f in _all_pre if f.get('severity') == 'MEDIUM')
    _cnt_li  = sum(1 for f in _all_pre if f.get('severity') in ('LOW', 'INFO'))

    parts = [f'''<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>Arckon — Fleet {esc(tier_label)}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#0d1117;color:#c9d1d9;font-family:system-ui,sans-serif;padding:32px;max-width:1100px;margin:0 auto}}
h1{{color:#58a6ff;font-size:22px;margin-bottom:4px}}
h2{{color:#58a6ff;font-size:15px;margin:28px 0 10px;border-bottom:1px solid #21262d;padding-bottom:6px}}
h3{{color:#8b949e;font-size:13px;margin:16px 0 6px}}
.meta{{color:#6e7681;font-size:12px;margin-bottom:28px}}
.score{{font-size:36px;font-weight:700;color:{score_color}}}
.cards{{display:flex;gap:16px;flex-wrap:wrap;margin:16px 0 24px}}
.card{{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:16px 24px;min-width:120px}}
.card-n{{font-size:28px;font-weight:700}}
.card-l{{font-size:11px;color:#6e7681;margin-top:4px;text-transform:uppercase}}
table{{width:100%;border-collapse:collapse;font-size:13px;margin-bottom:16px}}
th{{background:#161b22;color:#6e7681;font-size:11px;text-transform:uppercase;padding:8px 10px;text-align:left;border-bottom:1px solid #21262d}}
td{{padding:7px 10px;border-bottom:1px solid #161b22}}
tr:hover td{{background:#161b22}}
.fail{{color:#f85149}}.warn{{color:#d29922}}.pass{{color:#58a6ff}}.skip{{color:#6e7681}}
.crit{{color:#f85149}}.high{{color:#d29922}}.med{{color:#58a6ff}}.low{{color:#3fb950}}
.device-block{{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:20px;margin-bottom:20px}}
.finding{{padding:6px 0;border-bottom:1px solid #21262d;font-size:13px}}
.finding:last-child{{border-bottom:none}}
.rem{{color:#3fb950;font-size:12px;margin-top:3px;font-style:italic}}
.det{{color:#8b949e;font-size:12px;margin-top:3px}}
.toolbar{{position:sticky;top:0;z-index:100;background:#161b22;border-bottom:1px solid #21262d;
          margin:-32px -32px 28px;padding:10px 32px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}}
@media print{{.toolbar{{display:none}}body{{background:#fff;color:#000;padding:16px}}h1,h2,h3,.card-l{{color:#000}}.card{{border:1px solid #ccc}}.fail{{color:#c00}}.pass{{color:#090}}.warn{{color:#850}}}}
{_LIGHT_MODE_CSS}
</style>
<script>
{_THEME_TOGGLE_JS}
var _sf='{status_filter}';
function applyProfiles(){{
  var checked=[...document.querySelectorAll('.rpt-cb:checked')].map(function(c){{return c.value;}});
  var p=checked.length?'&profile='+checked.join(','):'';
  var sf=_sf?'&status='+_sf:'';
  location.href='/api/fleet/report?tier={tier}&fmt=html'+p+sf;
}}
function switchTier(t){{
  var checked=[...document.querySelectorAll('.rpt-cb:checked')].map(function(c){{return c.value;}});
  var p=checked.length?'&profile='+checked.join(','):'';
  var sf=_sf?'&status='+_sf:'';
  location.href='/api/fleet/report?tier='+t+'&fmt=html'+p+sf;
}}
</script>
{_THEME_EARLY_SCRIPT}
</head><body>
<div class="toolbar">
  <span style="font-size:13px;font-weight:600;color:#c9d1d9;margin-right:6px">Arckon</span>
  <button onclick="switchTier('executive')" style="{btn_style}{';color:#58a6ff;border-color:#1f6feb' if tier=='executive' else ''}">Executive</button>
  <button onclick="switchTier('ciso')"      style="{btn_style}{';color:#58a6ff;border-color:#1f6feb' if tier=='ciso' else ''}">CISO</button>
  <button onclick="switchTier('technical')" style="{btn_style}{';color:#58a6ff;border-color:#1f6feb' if tier=='technical' else ''}">Technical</button>
  <span style="font-size:11px;color:#8b949e;white-space:nowrap;margin-left:6px">Profiles:</span>
  {_toolbar_cbs}
  <button onclick="applyProfiles()" style="{btn_style};color:#58a6ff;border-color:#1f6feb">Apply</button>
  <a href="/api/fleet/report?tier={tier}&fmt=pdf{_pdf_profile_param}{'&status=' + status_filter if status_filter else ''}" download="sentinel_fleet_{tier}{_pdf_fname_suffix}.pdf" style="{btn_style};color:#3fb950;border-color:#238636">&#8659; Download PDF</a>
  <button onclick="window.print()" style="{btn_style}">&#128438; Print</button>
  {'<a href="/api/fleet/report?tier=' + tier + '&fmt=html' + _pdf_profile_param + '" style="' + btn_style + ';color:#f85149;border-color:#30363d">&#10005; Clear filter</a>' if status_filter else ''}
  {_THEME_BTN}
</div>
{'<div style="background:#1c2128;border:1px solid #30363d;border-radius:6px;padding:10px 18px;margin-bottom:20px;display:flex;align-items:center;justify-content:space-between"><span style="font-size:13px;font-weight:600;color:' + ('#f85149' if status_filter=='fail' else '#d29922' if status_filter=='warn' else '#58a6ff') + '">Showing: ' + esc(_status_label) + ' only — across all devices</span></div>' if status_filter else ''}
{'<div style="background:#3d2000;border:1px solid #bb6800;border-radius:6px;padding:10px 18px;margin-bottom:18px;display:flex;align-items:center;gap:12px"><span style="font-size:15px">⚠️</span><div><span style="font-size:13px;font-weight:700;color:#f0a500">DEMO REPORT — For evaluation purposes only. Not for distribution.</span><span style="font-size:12px;color:#8b949e;margin-left:12px">Contact <a href="mailto:sales@markai.io" style="color:#58a6ff">sales@markai.io</a> to purchase a license.</span></div></div>' if demo else ''}
<h1>Arckon &mdash; Fleet {esc(tier_label)}</h1>
<div class="meta">Generated {esc(now)} &nbsp;&bull;&nbsp; {len(devices)} device(s){(' &nbsp;&bull;&nbsp; Profiles: <strong>' + esc(_profile_label) + '</strong>') if _profile_label else ''} &nbsp;&bull;&nbsp; {'DEMO — Not for distribution' if demo else 'Confidential'}</div>
<div class="cards">
  <div class="card"><div class="card-n score">{fleet_score}%</div><div class="card-l">Fleet Score</div></div>
  <div class="card"><div class="card-n fail">{_cnt_ch}</div><div class="card-l">Critical / High</div></div>
  <div class="card"><div class="card-n warn">{_cnt_med}</div><div class="card-l">Medium</div></div>
  <div class="card"><div class="card-n pass">{_cnt_li}</div><div class="card-l">Low / Info</div></div>
  <div class="card"><div class="card-n" style="color:#58a6ff">{len(devices)}</div><div class="card-l">Devices</div></div>
</div>''']

    # Device summary table
    parts.append('<h2>Device Status</h2><table><thead><tr><th>Hostname</th><th>Platform</th><th>High</th><th>Medium</th><th>Info</th><th>Score</th><th>Last Seen</th></tr></thead><tbody>')
    for d in devices:
        f = d.get('fail_count', 0) or 0
        w = d.get('warn_count', 0) or 0
        p = d.get('pass_count', 0) or 0
        sc = _risk_score_html(f, w, f + w + p)
        sc_color = '#3fb950' if sc >= 80 else '#d29922' if sc >= 60 else '#f85149'
        parts.append(f'<tr><td><strong>{esc(d.get("hostname") or d.get("device_id") or "?")}</strong></td>'
                     f'<td style="color:#6e7681">{esc(d.get("platform",""))}</td>'
                     f'<td class="fail">{f}</td><td class="warn">{w}</td><td class="pass">{p}</td>'
                     f'<td style="color:{sc_color};font-weight:700">{sc}%</td>'
                     f'<td style="color:#6e7681;font-size:12px">{esc(ts(d.get("last_seen")))}</td></tr>')
    parts.append('</tbody></table>')

    # Findings across fleet — filtered by status_filter when set
    all_findings = []
    for d in devices:
        rep = d.get('_report') or {}
        for r in rep.get('findings', rep.get('results', [])):
            r2 = dict(r); r2['_hostname'] = d.get('hostname') or d.get('device_id') or '?'
            all_findings.append(r2)

    if status_filter:
        _target_status = {'fail': 'FAIL', 'warn': 'WARN', 'pass': 'PASS'}.get(status_filter, '')
        all_findings = [f for f in all_findings if f.get('status', '').upper() == _target_status]

    # Sort: FAIL first, then WARN, then PASS; within that by severity
    _ST_RANK = {'FAIL': 0, 'WARN': 1, 'PASS': 2, 'SKIP': 3}
    def _srt(lst):
        return sorted(lst, key=lambda x: (
            _ST_RANK.get(x.get('status', 'SKIP'), 99),
            _SEV_ORDER_REPORT.index(x.get('severity', 'INFO')) if x.get('severity') in _SEV_ORDER_REPORT else 99
        ))

    _af = all_findings  # may be pre-filtered by status_filter
    _bkt_ch  = _srt([f for f in _af if f.get('severity') in ('CRITICAL', 'HIGH') and f.get('status') != 'SKIP'])
    _bkt_med = _srt([f for f in _af if f.get('severity') == 'MEDIUM'             and f.get('status') != 'SKIP'])
    _bkt_li  = _srt([f for f in _af if f.get('severity') in ('LOW', 'INFO')      and f.get('status') != 'SKIP'])

    def _sev_table(label, findings, limit=None):
        rows = [f'<h2>{label} ({len(findings)})</h2>']
        if not findings:
            rows.append('<p style="color:#3fb950;padding:12px 0">No findings in this category across the fleet.</p>')
            return ''.join(rows)
        rows.append('<table><thead><tr><th>Status</th><th>Severity</th><th>Device</th><th>Check</th><th>Finding</th></tr></thead><tbody>')
        show = findings[:limit] if limit else findings
        for f in show:
            st  = f.get('status', '')
            sev = f.get('severity', 'INFO')
            sc  = _STATUS_COLOR_HTML.get(st, '#c9d1d9')
            sv  = _SEV_COLOR_HTML.get(sev, '#6e7681')
            rows.append(
                f'<tr><td style="color:{sc};font-weight:700;white-space:nowrap">{esc(_STATUS_LABEL_HTML.get(st, st))}</td>'
                f'<td style="color:{sv};font-weight:600">{esc(sev)}</td>'
                f'<td style="color:#8b949e">{esc(f.get("_hostname",""))}</td>'
                f'<td style="color:#8b949e;font-size:12px">{esc(f.get("check_id",""))}</td>'
                f'<td>{esc(f.get("title",""))}</td></tr>'
            )
        rows.append('</tbody></table>')
        if limit and len(findings) > limit:
            rows.append(f'<p style="color:#6e7681;font-size:12px;margin-top:4px">Showing top {limit} of {len(findings)}. View Technical report for full list.</p>')
        return ''.join(rows)

    exec_limit = 15
    if sev_filter == 'ch':
        parts.append(_sev_table('Critical &amp; High Severity', _bkt_ch))
    elif sev_filter == 'med':
        parts.append(_sev_table('Medium Severity', _bkt_med))
    elif sev_filter == 'li':
        parts.append(_sev_table('Low / Info', _bkt_li))
    else:
        parts.append(_sev_table('Critical &amp; High Severity', _bkt_ch, exec_limit if tier == 'executive' else None))
        if tier != 'executive':
            parts.append(_sev_table('Medium Severity', _bkt_med))
            parts.append(_sev_table('Low / Info', _bkt_li))

    if tier == 'executive':
        posture = ('Strong — healthy AI security posture.' if fleet_score >= 90
                   else 'Moderate — several issues require attention.' if fleet_score >= 70
                   else 'Elevated risk — critical findings need remediation within 30 days.' if fleet_score >= 50
                   else 'High risk — immediate action required on critical findings.')
        parts.append(f'<h2>Executive Recommendation</h2>'
                     f'<div class="device-block"><p style="font-size:14px"><strong>Overall posture:</strong> {esc(posture)}</p>'
                     f'<p style="color:#6e7681;font-size:12px;margin-top:12px">For full technical details request the CISO or Technical report.</p></div>')
        parts.append('</body></html>')
        return ''.join(parts)

    # Per-device breakdown for ciso/technical
    parts.append('<h2>Per-Device Breakdown</h2>')
    for d in devices:
        report = d.get('_report') or {}
        results = report.get('findings', report.get('results', []))
        f = d.get('fail_count', 0) or 0
        w = d.get('warn_count', 0) or 0
        p = d.get('pass_count', 0) or 0
        sc = _risk_score_html(f, w, f + w + p)
        sc_color = '#3fb950' if sc >= 80 else '#d29922' if sc >= 60 else '#f85149'
        parts.append(f'<div class="device-block"><h3>{esc(d.get("hostname") or d.get("device_id") or "?")} '
                     f'<span style="color:{sc_color}">{sc}%</span> &nbsp;'
                     f'<span style="color:#6e7681;font-size:11px">{esc(d.get("platform",""))} &bull; '
                     f'{esc(ts(d.get("last_seen")))}</span></h3>')
        if status_filter:
            _target_st = {'fail': 'FAIL', 'warn': 'WARN', 'pass': 'PASS'}.get(status_filter, '')
            show = [r for r in results if r.get('status', '').upper() == _target_st]
        else:
            show = [r for r in results if r.get('status') in ('FAIL', 'WARN')]
        show.sort(key=lambda x: _SEV_ORDER_REPORT.index(x.get('severity', 'INFO')) if x.get('severity') in _SEV_ORDER_REPORT else 99)
        if not show:
            parts.append('<p style="color:#3fb950;font-size:13px;padding:8px 0">No failures on this device.</p>')
        for r in show:
            st = r.get('status', '')
            sev = r.get('severity', 'INFO')
            sc2 = _STATUS_COLOR_HTML.get(st, '#c9d1d9')
            sv2 = _SEV_COLOR_HTML.get(sev, '#6e7681')
            sev_span = f'<span style="color:{sv2}">[{esc(sev)}]</span> ' if st in ('FAIL', 'WARN') else ''
            parts.append(f'<div class="finding">'
                         f'<span style="color:{sc2};font-weight:700">[{esc(_STATUS_LABEL_HTML.get(st, st))}]</span> '
                         f'{sev_span}'
                         f'<strong>{esc(r.get("title",""))}</strong>')
            if tier == 'technical' and r.get('details'):
                parts.append(f'<div class="det">{esc(r["details"][:300])}</div>')
            if tier == 'technical' and r.get('remediation'):
                parts.append(f'<div class="rem">Fix: {esc(r["remediation"][:250])}</div>')
            parts.append('</div>')
        parts.append('</div>')

    parts.append('</body></html>')
    return ''.join(parts)


def _run_scan(mode: str, target: str, profile: str, providers: list[str], live_cfg: dict | None = None):
    global _status, _log
    with _lock:
        _status = 'running'
        _log = []

    def emit(line: str):
        with _lock:
            _log.append(line)

    try:
        if mode == 'demo':
            cmd = _compiled_cmd(ROOT / 'scripts' / 'demo.py') + ['--target', target]
            if profile and profile != 'default':
                cmd += ['--profile', profile]
        else:
            provider = providers[0] if providers else 'config'
            db_path = str(ROOT / 'data' / 'agents.db')
            cmd = _compiled_cmd(ROOT / 'audit.py') + [
                   '--target', target,
                   '--mode', provider, '--profile', profile, '--output', 'json',
                   '--store-db', db_path]
            if live_cfg and provider not in ('config', 'demo'):
                api_key  = live_cfg.get('api_key', '')
                endpoint = live_cfg.get('endpoint', '')
                mdl      = live_cfg.get('model', '')
                if api_key:
                    if provider == 'anthropic':
                        cmd += ['--anthropic-api-key', api_key]
                    elif provider == 'gemini':
                        cmd += ['--gemini-api-key', api_key]
                    else:
                        cmd += ['--api-key', api_key]
                if endpoint and provider == 'api':
                    cmd += ['--endpoint', endpoint]
                elif not endpoint and provider == 'api':
                    cmd += ['--endpoint', 'https://api.openai.com/v1']
                if mdl:
                    cmd += ['--model', mdl]

        emit(f'$ {" ".join(cmd)}')
        emit('')
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, encoding='utf-8', cwd=str(ROOT),
        )
        for line in proc.stdout:
            emit(line.rstrip())
        proc.wait()

        if proc.returncode == 0:
            out_dir = _latest_out_dir()
            if out_dir:
                emit('')
                emit('Regenerating dashboard…')
                if _rebuild_dashboard(out_dir):
                    emit('Dashboard ready — click Reload Dashboard.')

        with _lock:
            _status = 'done' if proc.returncode == 0 else 'error'

    except Exception as e:
        emit(f'Error: {e}')
        with _lock:
            _status = 'error'


class _TenantScopeError(Exception):
    """A session's client-org scope could not be resolved safely.

    Raised instead of returning None (which means "no filter — show the whole
    MSP fleet") so that a client_viewer with a missing, unknown, deactivated
    or cross-customer client_org_id fails closed rather than being handed
    every tenant's devices."""


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_): pass

    def handle_error(self, *_):
        import traceback as _tb
        log.error('HTTP handler thread error: %s', _tb.format_exc())

    # ── auth helpers ──────────────────────────────────────────────────────────

    def _proxy_session_user(self) -> dict | None:
        proxy_token = os.environ.get('SENTINEL_TRUSTED_PROXY_TOKEN', '')
        supplied_token = self.headers.get('X-Sentinel-Proxy-Token', '')
        # A marker alone is not proof that nginx authenticated this request:
        # callers could reach the backend directly if ingress is misconfigured.
        if not proxy_token or not hmac.compare_digest(supplied_token, proxy_token):
            return None
        email = (self.headers.get('X-Sentinel-User-Email')
                 or self.headers.get('X-Arckon-User-Email', '')).strip()
        if not email:
            return None
        customer_id = (self.headers.get('X-Sentinel-Customer-ID')
                       or self.headers.get('X-Arckon-Customer-ID', '')).strip() or 'default'
        org = (self.headers.get('X-Sentinel-Client-Org-ID')
               or self.headers.get('X-Arckon-Client-Org-ID', '')).strip()
        return {
            'email':       email,
            # No role header means the proxy didn't vouch for one. Default to
            # the least-privileged role, never 'admin' — a misconfigured or
            # partially-updated vhost must not hand out MSP-wide access.
            'role':        (self.headers.get('X-Sentinel-User-Role')
                            or self.headers.get('X-Arckon-User-Role', '')).strip() or 'client_viewer',
            'customer_id': customer_id,
            'client_org_id': org or None,
            'is_reseller': self.headers.get('X-Sentinel-Is-Reseller', '').strip() == '1',
            'is_msp':      self.headers.get('X-Sentinel-Is-MSP', '').strip() == '1',
            'impersonated_by': self.headers.get('X-Sentinel-Impersonated-By', '').strip() or None,
        }

    def _session_user(self) -> dict | None:
        proxy = self._proxy_session_user()
        if proxy:
            return proxy
        # Behind the trusted proxy, the admin-domain JWT is the only dashboard
        # session authority. Do not revive a stale host-only legacy session after logout.
        if os.environ.get('SENTINEL_TRUSTED_PROXY_TOKEN'):
            return None
        token = _get_session_cookie(self.headers)
        return _get_registry().get_session(token) if token else None

    def _resolve_session_org(self, user: dict | None) -> str | None:
        """Validate the client org this session is pinned to.

        Returns None only for sessions that legitimately span the whole
        customer — MSP/reseller admins, super-admin impersonation, agent and
        setup requests — which is what lets those roles keep their existing
        fleet-wide view. Anything else raises _TenantScopeError:

          * a client_viewer carrying no client_org_id at all (an unscoped
            portal login is a cross-tenant read waiting to happen),
          * any session whose client_org_id doesn't resolve to an active
            client org belonging to that session's own customer (covers a
            deleted/deactivated org, a typo, and a spoofed header that got
            past the proxy).
        """
        if not user:
            return None
        raw = (user.get('client_org_id') or '').strip()
        if not raw:
            if user.get('role') == 'client_viewer':
                raise _TenantScopeError(
                    f"client_viewer {user.get('email', '?')!r} has no client_org_id"
                )
            return None
        try:
            org = _get_registry().get_client_org(raw)
        except Exception as e:
            # A registry that can't answer is not a licence to show everything.
            raise _TenantScopeError(f'client org lookup failed for {raw!r}: {e}') from e
        if not org or not org.get('active'):
            raise _TenantScopeError(f'client_org_id {raw!r} is not an active client org')
        if org.get('customer_id') != user.get('customer_id'):
            raise _TenantScopeError(
                f"client_org_id {raw!r} belongs to customer "
                f"{org.get('customer_id')!r}, not {user.get('customer_id')!r}"
            )
        return raw

    def _scoped_client_org(self) -> str | None:
        """Return the effective client_org_id filter for this request.

        A client_viewer's own client_org_id always wins — the ?client_org=
        query param is ignored for that role so a scoped user can never
        widen their own view by hand-editing the URL. An MSP admin (no
        client_org_id on their session) may pass ?client_org=<id> to drill
        into one client's fleet view from the /clients rollup; omit it (or
        pass 'all') to see every device across every client, same as before
        this feature existed.

        Raises _TenantScopeError for a scoped session whose org doesn't
        validate — callers must not translate that into an unfiltered query."""
        user = self._session_user()
        own_org = self._resolve_session_org(user)
        if own_org is not None:
            return own_org
        from urllib.parse import parse_qs, urlparse as _up
        qs = parse_qs(_up(self.path).query)
        requested = (qs.get('client_org', [''])[0]).strip()
        if requested == '__unassigned__':
            return ''
        return requested if requested and requested != 'all' else None

    # Paths a client_viewer session may reach — everything else 403s.
    # Each entry here must have matching client_org_id filtering in its
    # handler (grep for self._scoped_client_org() to verify before adding
    # a new path). The rollup dashboard (/clients) is deliberately NOT
    # here — that view spans every client org for the MSP and must stay
    # admin-only.
    _CLIENT_VIEWER_ALLOWED_EXACT = frozenset({'/', '/api/status', '/api/devices', '/api/maintenance-notice',
                                              '/api/fleet/network-assets', '/api/spend/summary',
                                              '/api/spend/by-model', '/api/spend/by-provider',
                                              '/api/spend/daily'})
    _CLIENT_VIEWER_ALLOWED_PREFIX = ('/api/fleet/report',)

    def _client_viewer_gate(self, path: str) -> bool:
        """Return True if this request may proceed. Always True for non-
        client_viewer sessions (MSP admins, agent/proxy auth, etc.).

        Raises _TenantScopeError if the session claims a client org that
        doesn't validate — checked for every role, not just client_viewer,
        so a bad org pin can never fall through to an unscoped query."""
        user = self._session_user()
        self._resolve_session_org(user)
        if not user or user.get('role') != 'client_viewer':
            return True
        if path in self._CLIENT_VIEWER_ALLOWED_EXACT:
            return True
        return any(path.startswith(p) for p in self._CLIENT_VIEWER_ALLOWED_PREFIX)

    def _store(self):
        user = self._session_user()
        return _get_store(user['customer_id'] if user else 'default')

    def _spend_customer_id(self) -> str:
        """Authenticated customer boundary for all spend config and secrets."""
        user = self._session_user()
        if not user or not user.get('customer_id'):
            raise _TenantScopeError('spend access requires an authenticated customer')
        return user['customer_id']

    def _check_dashboard_auth(self) -> bool:
        return self._session_user() is not None

    def _require_dashboard_auth(self) -> bool:
        if self._check_dashboard_auth():
            return True
        path = urlparse(self.path).path
        if self.command == 'POST' or path.startswith('/api/'):
            self._json({'error': 'unauthorized'}, 401)
        else:
            from urllib.parse import quote
            if not _get_registry().has_customers():
                self.send_response(302)
                self.send_header('Location', '/setup')
                self.end_headers()
            else:
                self.send_response(302)
                self.send_header('Location', f'/login?next={quote(path)}')
                self.end_headers()
        return False

    def _get_agent_customer(self) -> dict | None:
        submitted = self.headers.get('Authorization', '')
        if submitted.startswith('Bearer '):
            submitted = submitted[len('Bearer '):]
        if not submitted:
            return None
        cust = _get_registry().get_by_agent_token(submitted)
        if cust:
            return cust
        if _check_agent_token(submitted):
            return {'id': 'default', 'name': 'Default'}
        return None

    def _get_dashboard_customer(self) -> dict | None:
        """Return the customer record for the authenticated dashboard user, or None."""
        user = self._session_user()
        if not user:
            return None
        cust_id = user.get('customer_id')
        if not cust_id:
            return None
        return _get_registry().get_by_id(cust_id)

    def _check_agent_bearer(self) -> bool:
        if not _agent_token() and not (ROOT / 'output' / 'agent_tokens.json').exists():
            if not _get_registry().has_customers():
                return True
        return self._get_agent_customer() is not None

    # ── routing ───────────────────────────────────────────────────────────────

    def do_GET(self):
        print(f'[SENTINEL] GET {self.path}', flush=True)
        try:
            self._do_GET_inner()
            print(f'[SENTINEL] GET {self.path} done', flush=True)
        except BaseException as _e:
            import traceback as _tb
            print(f'[SENTINEL] GET {self.path} EXCEPTION: {_e}\n{_tb.format_exc()}', flush=True)
            log.error('Unhandled GET error for %s: %s', self.path, _e, exc_info=True)
            try:
                body = ('Internal server error:\n' + _tb.format_exc()).encode('utf-8', errors='replace')
                self.send_response(500)
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.send_header('Content-Length', len(body))
                self.end_headers()
                self.wfile.write(body)
            except Exception:
                pass

    def _do_GET_inner(self):
        path = urlparse(self.path).path

        # Auth-exempt: health probe, login, and first-run setup
        if path == '/health':
            self._api_health()
            return
        if path == '/login':
            self._serve_login()
            return
        if path == '/logout':
            self._handle_logout()
            return
        if path == '/setup':
            self._serve_setup()
            return
        if path == '/api/auth/me':
            self._api_auth_me()
            return

        # Agent-token-gated, pre-published signed release files only.
        if path.startswith('/releases/'):
            # Releases must never inherit the first-run authentication bypass.
            if self._get_agent_customer() is None:
                self._send(401, b'Unauthorized', 'text/plain')
                return
            self._serve_release_file(path)
            return

        # Agent-token-gated: command polling (has its own internal check too)
        if path.startswith('/api/agent/commands/'):
            self._api_agent_commands(path[len('/api/agent/commands/'):])
            return

        # All remaining GET endpoints require dashboard auth
        if not self._require_dashboard_auth():
            return

        # client_viewer is a read-only role scoped to one client org (the
        # portal login an MSP hands its customer) — deny-by-default rather
        # than trying to retrofit org-scoping into every one of this file's
        # data-fetching routes individually. Only a small, explicitly
        # reviewed allowlist is reachable; everything else 403s. This is
        # deliberately more restrictive than "everything scoped" for now —
        # extend the allowlist (with matching org-scoping in the handler)
        # rather than removing this gate.
        try:
            if not self._client_viewer_gate(path):
                self._send(403, b'Forbidden: this account is read-only and scoped to one client.', 'text/plain')
                return
        except _TenantScopeError as e:
            log.warning('denying GET %s — unresolvable client-org scope: %s', path, e)
            self._send(403, b'Forbidden: this account is not scoped to a valid client.', 'text/plain')
            return

        static = {
            '/':               self._serve_fleet,
            '/clients':        self._serve_clients,
            '/api/clients':    self._api_clients_list,
            '/reseller':       self._serve_reseller,
            '/api/reseller/customers': self._api_reseller_customers,
            '/dashboard':      self._serve_dashboard,
            '/dashboard.html': self._serve_dashboard,
            '/api/status':     self._api_status,
            '/api/maintenance-notice': self._api_maintenance_notice,
            '/api/events':     self._api_events,
            '/api/devices':    self._api_devices,
            '/api/discover':   self._api_discover,
            '/fleet':          lambda: self._redirect('/'),
            '/academy':        self._serve_academy,
            '/probe':          self._serve_probe_tester if _has_live_scan() else lambda: self._send(403, b'Live scanning requires a Pro license. Contact sales@markai.io to upgrade.', 'text/plain'),
            '/command':        lambda: self._redirect('/'),
            '/api/config':           self._api_get_config,
            '/api/baseline-profile': self._api_get_baseline_profile,
            '/api/alerts/config':    self._api_get_alert_config,
            '/api/alerts/events':    self._api_get_alert_events,
            '/api/alerts/active-issues': self._api_get_active_issues,
            '/api/alerts/unreviewed-count': self._api_unreviewed_alert_count,
            '/api/siem/config':      self._api_get_siem_config,
            '/api/live-scan-config': self._api_get_live_scan_config,
            '/api/fleet/live-stats': self._api_fleet_live_stats,
            '/api/fleet/k8s-status': self._api_fleet_k8s_status,
            '/api/fleet/shadow':  self._api_fleet_shadow,
            '/api/fleet/network-assets': self._api_fleet_network_assets,
            '/api/fleet/mcp':        self._api_fleet_mcp,
            '/api/fleet/mcp/report': self._api_fleet_mcp_report,
            '/api/fleet/eu-ai-act-report': self._api_eu_ai_act_report,
            '/api/fleet/aibom':            self._api_fleet_aibom,
            '/api/fleet/aibom.json':       self._api_fleet_aibom_json,
            '/api/fleet/aibom.csv':        self._api_fleet_aibom_csv,
            '/api/fleet/aibom.pdf':        self._api_fleet_aibom_pdf,
            '/api/branding':               self._api_get_branding,
            '/api/psa/config':             self._api_get_psa_config,
            '/api/wiki/config':            self._api_get_wiki_config,
            '/api/spend/summary':          self._api_spend_summary,
            '/api/spend/by-model':         self._api_spend_by_model,
            '/api/spend/by-provider':      self._api_spend_by_provider,
            '/api/spend/daily':            self._api_spend_daily,
            '/api/spend/by-client-org':    self._api_spend_by_client_org,
            '/api/spend/by-api-key':       self._api_spend_by_api_key,
            '/api/spend/keys':             self._api_spend_keys_list,
            '/download/shortcut': self._serve_shortcut,
        }
        if path in static:
            static[path]()
        elif path.startswith('/fleet/device/') and path.endswith('/timeseries.json'):
            did = path[len('/fleet/device/'): -len('/timeseries.json')]
            self._api_device_timeseries(did)
        elif path.startswith('/fleet/device/') and path.endswith('/dashboard'):
            did = path[len('/fleet/device/'): -len('/dashboard')]
            self._serve_device_dashboard(did)
        elif path.startswith('/fleet/device/') and path.endswith('/report.pdf'):
            did = path[len('/fleet/device/'): -len('/report.pdf')]
            self._serve_device_pdf(did)
        elif path.startswith('/api/devices/'):
            self._api_device_report(path[len('/api/devices/'):])
        elif path == '/api/fleet/report' or path.startswith('/api/fleet/report?'):
            self._api_fleet_report()
        elif path == '/api/fleet/evidence-export' or path.startswith('/api/fleet/evidence-export?'):
            self._api_evidence_export()
        elif path == '/api/fleet/risk-register':
            self._api_risk_register()
        elif path == '/api/fleet/risk-register/csv':
            self._api_risk_register_csv()
        elif path == '/api/fleet/risk-register/overrides':
            self._api_rr_overrides_list()
        elif path == '/api/fleet/shadow/csv':
            self._api_shadow_csv()
        elif path == '/api/fleet/inventory':
            self._api_inventory()
        elif path.startswith('/api/fleet/inventory/history/'):
            self._api_inventory_history(path[len('/api/fleet/inventory/history/'):])
        elif path == '/api/schedules':
            self._api_schedules_list()
        elif path == '/api/users':
            self._api_users_list()
        elif path == '/api/customers/me':
            self._api_customers_me()
        elif path == '/api/verify' or path.startswith('/api/verify?'):
            self._api_verify_signature()
        else:
            self._not_found()

    def do_POST(self):
        try:
            self._do_POST_inner()
        except Exception as _e:
            log.error('Unhandled POST error for %s: %s', self.path, _e, exc_info=True)
            try:
                import traceback as _tb
                body = ('Internal server error:\n' + _tb.format_exc()).encode('utf-8', errors='replace')
                self.send_response(500)
                self.send_header('Content-Type', 'text/plain; charset=utf-8')
                self.send_header('Content-Length', len(body))
                self.end_headers()
                self.wfile.write(body)
            except Exception:
                pass

    def _do_POST_inner(self):
        path = urlparse(self.path).path

        # Login / setup — no auth needed
        if path == '/login':
            self._handle_login_post()
            return
        if path == '/setup':
            self._handle_setup_post()
            return

        # Agent endpoints — use agent-token auth, not dashboard session
        if path == '/api/agent/report':
            self._api_agent_report()
            return
        if path == '/api/agent/discovery':
            if not self._check_agent_bearer():
                self._send(401, b'Unauthorized', 'text/plain')
                return
            self._api_agent_discovery()
            return
        if path == '/api/agent/mcp':
            if not self._check_agent_bearer():
                self._send(401, b'Unauthorized', 'text/plain')
                return
            self._api_agent_mcp()
            return
        if path == '/api/agent/network-assets':
            if not self._check_agent_bearer():
                self._send(401, b'Unauthorized', 'text/plain')
                return
            self._api_agent_network_assets()
            return

        # All other POST endpoints require dashboard auth
        if not self._require_dashboard_auth():
            return

        try:
            self._resolve_session_org(self._session_user())
        except _TenantScopeError as exc:
            log.warning('denying POST %s due to invalid client-org scope: %s', path, exc)
            self._send(403, b'Forbidden: this account is not scoped to a valid client.', 'text/plain')
            return

        # client_viewer is read-only by definition — no POST route is ever
        # appropriate for that role.
        user = self._session_user()
        if user and user.get('role') == 'client_viewer':
            self._send(403, b'Forbidden: this account is read-only.', 'text/plain')
            return
        # An admin session pinned to a client org that no longer validates is
        # denied here too — same fail-closed rule as GET.
        try:
            self._resolve_session_org(user)
        except _TenantScopeError as e:
            log.warning('denying POST %s — unresolvable client-org scope: %s', path, e)
            self._send(403, b'Forbidden: this account is not scoped to a valid client.', 'text/plain')
            return

        if path == '/api/scan':
            self._api_scan()
        elif path == '/api/live-scan-config':
            self._api_set_live_scan_config()
        elif path == '/api/config':
            self._api_set_config()
        elif path == '/api/baseline-profile':
            self._api_set_baseline_profile()
        elif path == '/api/alerts/config':
            self._api_set_alert_config()
        elif path == '/api/alerts/test':
            self._api_test_alert()
        elif path == '/api/branding':
            self._api_set_branding()
        elif path == '/api/alerts/psa/test':
            self._api_test_psa()
        elif path == '/api/psa/config':
            self._api_set_psa_config()
        elif path.startswith('/api/psa/test-ticket/'):
            self._api_test_psa_ticket(path[len('/api/psa/test-ticket/'):].strip('/'))
        elif path.startswith('/api/psa/test/'):
            self._api_test_psa_provider(path[len('/api/psa/test/'):].strip('/'))
        elif path == '/api/wiki/config':
            self._api_set_wiki_config()
        elif path.startswith('/api/wiki/test-page/'):
            self._api_test_wiki_page(path[len('/api/wiki/test-page/'):].strip('/'))
        elif path.startswith('/api/wiki/test/'):
            self._api_test_wiki_provider(path[len('/api/wiki/test/'):].strip('/'))
        elif path == '/api/alerts/events/review-all':
            self._api_review_all_alerts()
        elif path.startswith('/api/alerts/events/') and path.endswith('/review'):
            _eid = path[len('/api/alerts/events/'):-len('/review')]
            self._api_review_alert(_eid)
        elif path == '/api/siem/config':
            self._api_set_siem_config()
        elif path.startswith('/api/siem/test/'):
            self._api_test_siem(path[len('/api/siem/test/'):].strip('/'))
        elif path == '/api/system/update':
            self._api_system_update()
        elif path == '/api/system/restart-agent':
            self._api_system_restart_agent()
        elif path == '/api/system/restart-server':
            self._api_system_restart_server()
        elif path == '/api/fleet/scan/all':
            self._api_fleet_scan_all()
        elif path.startswith('/api/fleet/scan/'):
            self._api_fleet_scan(path[len('/api/fleet/scan/'):])
        elif path == '/api/fleet/update/all':
            self._api_fleet_update_all()
        elif path == '/api/fleet/push-token':
            self._api_fleet_push_token()
        elif path.startswith('/api/fleet/update/'):
            self._api_fleet_update(path[len('/api/fleet/update/'):])
        elif path.startswith('/api/fleet/remove/'):
            self._api_fleet_remove(path[len('/api/fleet/remove/'):])
        elif path == '/api/admin/license':
            self._api_admin_license()
        elif path == '/api/probe-scan':
            self._api_probe_scan()
        elif path == '/probe':
            if not _has_live_scan():
                self._send(403, b'Live scanning requires a Pro license. Contact sales@markai.io to upgrade.', 'text/plain')
                return
            self._probe_run()
        elif path == '/api/fleet/discover/all':
            self._api_fleet_discover_all()
        elif path.startswith('/api/fleet/discover/'):
            self._api_fleet_discover(path[len('/api/fleet/discover/'):])
        elif path == '/api/fleet/network-assets/discover/all':
            self._api_fleet_network_assets_discover_all()
        elif path.startswith('/api/fleet/network-assets/discover/'):
            self._api_fleet_network_assets_discover(path[len('/api/fleet/network-assets/discover/'):])
        elif path.startswith('/api/fleet/shadow/dismiss/'):
            self._api_fleet_shadow_dismiss(path[len('/api/fleet/shadow/dismiss/'):])
        elif path.startswith('/api/fleet/inventory/approve/'):
            self._api_inventory_set_status(path[len('/api/fleet/inventory/approve/'):], 'approved')
        elif path.startswith('/api/fleet/inventory/review/'):
            self._api_inventory_set_status(path[len('/api/fleet/inventory/review/'):], 'under_review')
        elif path.startswith('/api/fleet/inventory/unapprove/'):
            self._api_inventory_set_status(path[len('/api/fleet/inventory/unapprove/'):], 'unapproved')
        elif path.startswith('/api/fleet/inventory/false-positive/'):
            self._api_inventory_false_positive(path[len('/api/fleet/inventory/false-positive/'):])
        elif path == '/api/fleet/inventory/approve-service':
            self._api_approve_service_globally()
        elif path == '/api/schedules':
            self._api_schedules_create()
        elif path.startswith('/api/schedules/') and path.endswith('/toggle'):
            self._api_schedule_toggle(path[len('/api/schedules/'):-len('/toggle')])
        elif path.startswith('/api/schedules/') and path.endswith('/delete'):
            self._api_schedule_delete(path[len('/api/schedules/'):-len('/delete')])
        elif path == '/api/fleet/mcp/discover/all':
            self._api_fleet_mcp_discover_all()
        elif path.startswith('/api/fleet/mcp/dismiss/'):
            self._api_fleet_mcp_dismiss(path[len('/api/fleet/mcp/dismiss/'):])
        elif path == '/api/users/add':
            self._api_users_add()
        elif path.startswith('/api/users/deactivate/'):
            self._api_users_deactivate(path[len('/api/users/deactivate/'):])
        elif path.startswith('/api/users/password/'):
            self._api_users_password(path[len('/api/users/password/'):])
        elif path == '/api/clients/assign-devices':
            self._api_devices_assign_client_org()
        elif path == '/api/reseller/impersonate':
            self._api_reseller_impersonate()
        elif path == '/api/reseller/impersonate/end':
            self._api_reseller_impersonate_end()
        elif path == '/api/clients/add':
            self._api_clients_add()
        elif path.startswith('/api/clients/rename/'):
            self._api_clients_rename(path[len('/api/clients/rename/'):])
        elif path.startswith('/api/clients/deactivate/'):
            self._api_clients_deactivate(path[len('/api/clients/deactivate/'):])
        elif path.startswith('/api/clients/report-config/'):
            self._api_clients_report_config(path[len('/api/clients/report-config/'):])
        elif path.startswith('/api/clients/send-report/'):
            self._api_clients_send_report(path[len('/api/clients/send-report/'):])
        elif path == '/api/fleet/risk-register/override':
            self._api_rr_override_set()
        elif path.startswith('/api/fleet/risk-register/override/') and path.endswith('/delete'):
            check_id = path[len('/api/fleet/risk-register/override/'):-len('/delete')]
            self._api_rr_override_delete(check_id)
        elif path == '/api/spend/fetch':
            self._api_spend_fetch()
        elif path == '/api/spend/budget':
            self._api_spend_set_budget()
        elif path == '/api/spend/keys':
            self._api_spend_keys_add()
        elif path == '/api/spend/keys/remove':
            self._api_spend_keys_remove()
        else:
            self._not_found()

    def do_OPTIONS(self):
        self._send(200, b'', 'text/plain')

    # ── login / logout / setup ────────────────────────────────────────────────

    _LOGIN_CSS = (
        'body{font-family:system-ui;background:#0d1117;color:#8b949e;'
        'display:flex;align-items:center;justify-content:center;height:100vh;margin:0}'
        '.box{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:40px 36px;width:340px}'
        'h2{color:#e6edf3;font-size:18px;margin:0 0 6px}'
        '.sub{font-size:12px;color:#6B7280;margin:0 0 24px}'
        'label{display:block;font-size:12px;color:#8b949e;margin-bottom:4px}'
        'input{width:100%;box-sizing:border-box;background:#0d1117;border:1px solid #30363d;'
        'border-radius:6px;color:#e6edf3;padding:10px 12px;font-size:14px;margin-bottom:14px}'
        'button{width:100%;background:#238636;color:#fff;border:none;border-radius:6px;'
        'padding:10px;font-size:14px;cursor:pointer;font-weight:600}'
        'button:hover{background:#2ea043}'
        '.err{color:#f85149;font-size:13px;margin:0 0 14px}'
        '.brand{color:#58a6ff;font-size:12px;text-align:center;margin-top:20px}'
    )

    def _serve_login(self):
        import html as _html
        from urllib.parse import parse_qs
        if not _get_registry().has_customers():
            self.send_response(302)
            self.send_header('Location', '/setup')
            self.end_headers()
            return
        # In trusted-proxy mode the user is already authenticated by nginx —
        # skip the login form and go straight to the dashboard.
        if self._proxy_session_user():
            self.send_response(302)
            self.send_header('Location', '/')
            self.end_headers()
            return
        qs = parse_qs(urlparse(self.path).query)
        next_url = qs.get('next', ['/'])[0]
        if not next_url.startswith('/') or '//' in next_url:
            next_url = '/'
        safe_next = _html.escape(next_url, quote=True)
        err_html = '<p class="err">Incorrect email or password.</p>' if qs.get('error') else ''
        body = (
            f'<!doctype html><html><head><meta charset="utf-8">'
            f'<title>Arckon — Sign in</title>'
            f'<style>{self._LOGIN_CSS}</style>'
            f'</head><body><div class="box">'
            f'<h2>Arckon by RiskRaven</h2>'
            f'<p class="sub">Sign in to your account</p>'
            f'{err_html}'
            f'<form method="POST" action="/login">'
            f'<input type="hidden" name="next" value="{safe_next}">'
            f'<label>Email</label>'
            f'<input type="email" name="email" placeholder="you@company.com" autofocus autocomplete="username">'
            f'<label>Password</label>'
            f'<input type="password" name="password" placeholder="••••••••" autocomplete="current-password">'
            f'<button type="submit">Sign in</button>'
            f'</form>'
            f'<div class="brand">Powered by RiskRaven</div>'
            f'</div></body></html>'
        ).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def _handle_login_post(self):
        from urllib.parse import parse_qs, quote
        length = _content_length(self.headers)
        if length > 4096:
            self._send(400, b'Bad request', 'text/plain')
            return
        client_ip = self.client_address[0]
        if not _login_allowed(client_ip):
            self.send_response(302)
            self.send_header('Location', '/login?error=ratelimit')
            self.end_headers()
            return
        params = parse_qs(self.rfile.read(length).decode(errors='ignore'))
        email = params.get('email', [''])[0].strip()
        password = params.get('password', [''])[0]
        next_url = params.get('next', ['/'])[0]
        if not next_url.startswith('/') or '//' in next_url:
            next_url = '/'
        reg = _get_registry()
        user = reg.authenticate_user(email, password)
        if user:
            token = reg.create_session(user['id'], user['customer_id'], user['email'])
            self.send_response(302)
            self.send_header('Set-Cookie',
                f'sentinel_session={token}; Path=/; HttpOnly; SameSite=Strict')
            self.send_header('Location', next_url)
            self.end_headers()
        else:
            _login_failed(client_ip)
            self.send_response(302)
            self.send_header('Location', f'/login?next={quote(next_url)}&error=1')
            self.end_headers()

    def _handle_logout(self):
        token = _get_session_cookie(self.headers)
        if token:
            _get_registry().delete_session(token)
        self.send_response(302)
        self.send_header('Set-Cookie',
            'sentinel_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0')
        if os.environ.get('SENTINEL_TRUSTED_PROXY_TOKEN'):
            # Cloud mode: the shared dashboard JWT belongs to the admin app.
            # Send logout there so it clears the .riskraven.ai cookie.
            logout_url = os.environ.get('SENTINEL_ADMIN_LOGOUT_URL', '')
            self.send_header('Location', logout_url if logout_url.startswith('https://') else '/login')
        else:
            self.send_header('Location', '/login')
        self.end_headers()

    def _serve_setup(self):
        from urllib.parse import parse_qs
        if _get_registry().has_customers():
            self.send_response(302)
            self.send_header('Location', '/login')
            self.end_headers()
            return
        qs = parse_qs(urlparse(self.path).query)
        err_map = {
            'exists':   'An account with that email already exists.',
            'mismatch': 'Passwords do not match.',
            'short':    'Password must be at least 8 characters.',
            'invalid':  'Please enter a valid email address.',
            'company':  'Please enter your company name.',
        }
        err_key = qs.get('error', [''])[0]
        err_html = f'<p class="err">{err_map.get(err_key, "")}</p>' if err_key else ''
        body = (
            f'<!doctype html><html><head><meta charset="utf-8">'
            f'<title>Arckon — Setup</title>'
            f'<style>{self._LOGIN_CSS}</style>'
            f'</head><body><div class="box">'
            f'<h2>Arckon by RiskRaven</h2>'
            f'<p class="sub">Create your organization and admin account</p>'
            f'{err_html}'
            f'<form method="POST" action="/setup">'
            f'<label>Company name</label>'
            f'<input type="text" name="company" placeholder="Acme Corp" autofocus autocomplete="organization">'
            f'<label>Admin email</label>'
            f'<input type="email" name="email" placeholder="you@company.com" autocomplete="username">'
            f'<label>Password</label>'
            f'<input type="password" name="password" placeholder="Min 8 characters" autocomplete="new-password">'
            f'<label>Confirm password</label>'
            f'<input type="password" name="confirm" placeholder="Re-enter password" autocomplete="new-password">'
            f'<button type="submit">Create &amp; sign in</button>'
            f'</form>'
            f'<div class="brand">Powered by RiskRaven</div>'
            f'</div></body></html>'
        ).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def _handle_setup_post(self):
        from urllib.parse import parse_qs
        reg = _get_registry()
        if reg.has_customers():
            self.send_response(302)
            self.send_header('Location', '/login')
            self.end_headers()
            return
        length = _content_length(self.headers)
        if length > 8192:
            self._send(400, b'Bad request', 'text/plain')
            return
        params = parse_qs(self.rfile.read(length).decode(errors='ignore'))
        company = params.get('company', [''])[0].strip()
        email = params.get('email', [''])[0].strip().lower()
        password = params.get('password', [''])[0]
        confirm = params.get('confirm', [''])[0]
        if not company:
            self.send_response(302); self.send_header('Location', '/setup?error=company'); self.end_headers(); return
        if '@' not in email or '.' not in email.split('@')[-1]:
            self.send_response(302); self.send_header('Location', '/setup?error=invalid'); self.end_headers(); return
        if len(password) < 8:
            self.send_response(302); self.send_header('Location', '/setup?error=short'); self.end_headers(); return
        if password != confirm:
            self.send_response(302); self.send_header('Location', '/setup?error=mismatch'); self.end_headers(); return
        try:
            customer = reg.create_customer(company)
            user = reg.create_user(customer['id'], email, password, role='admin')
            token = reg.create_session(user['id'], customer['id'], user['email'])
            self.send_response(302)
            self.send_header('Set-Cookie',
                f'sentinel_session={token}; Path=/; HttpOnly; SameSite=Strict')
            self.send_header('Location', '/')
            self.end_headers()
        except Exception:
            self.send_response(302)
            self.send_header('Location', '/setup?error=exists')
            self.end_headers()

    def _api_auth_me(self):
        user = self._session_user()
        if user:
            self._json({'email': user['email'], 'role': user['role'],
                        'customer_id': user['customer_id']})
        else:
            self._json({'email': None, 'role': None, 'customer_id': None}, 401)

    def _admin_panel_url(self) -> str:
        return os.environ.get('SENTINEL_ADMIN_URL', 'http://sentinel-admin:8000')

    def _proxy_to_admin(self, path: str, method: str = 'GET', body: bytes = b'') -> None:
        import urllib.request
        import urllib.error
        url = self._admin_panel_url() + path
        cookie = self.headers.get('Cookie', '')
        req = urllib.request.Request(url, data=body or None, method=method,
                                     headers={'Cookie': cookie, 'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = resp.read()
                self._send(resp.status, data, 'application/json')
        except urllib.error.HTTPError as e:
            self._send(e.code, e.read(), 'application/json')
        except Exception as ex:
            self._json({'error': str(ex)}, 502)

    def _api_users_list(self):
        me = self._session_user()
        if not me:
            self._json({'error': 'unauthorized'}, 401)
            return
        if os.environ.get('SENTINEL_TRUSTED_PROXY'):
            self._proxy_to_admin('/api/users')
            return
        users = _get_registry().list_users(me['customer_id'])
        self._json({'users': [{'id': u['id'], 'email': u['email'], 'role': u['role'],
                                'client_org_id': u.get('client_org_id'),
                                'active': u['active'], 'created_at': u['created_at']}
                               for u in users], 'current_user': me['email']})

    def _api_users_add(self):
        me = self._session_user()
        if not me or me.get('role') not in ('admin', 'customer_admin', 'super_admin'):
            self._json({'error': 'forbidden'}, 403)
            return
        cl = int(self.headers.get('Content-Length', 0))
        raw = self.rfile.read(cl) if cl else b'{}'
        if os.environ.get('SENTINEL_TRUSTED_PROXY'):
            self._proxy_to_admin('/api/users/add', 'POST', raw)
            return
        try:
            body = json.loads(raw)
            email    = str(body.get('email', '')).strip().lower()
            password = str(body.get('password', ''))
            role     = str(body.get('role', 'admin'))
            if role not in ('admin', 'viewer', 'client_viewer'):
                role = 'admin'
            if '@' not in email or len(password) < 8:
                self._json({'error': 'invalid'}, 400)
                return

            client_org_id = None
            if role == 'client_viewer':
                client_org_id = str(body.get('client_org_id', '')).strip()
                if not client_org_id:
                    self._json({'error': 'client_org_id is required for the client_viewer role'}, 400)
                    return
                # Confirm the org actually belongs to this customer — without
                # this check a malicious/buggy request could scope a viewer
                # to another MSP's client org and read their devices.
                org = _get_registry().get_client_org(client_org_id)
                if not org or org.get('customer_id') != me['customer_id']:
                    self._json({'error': 'client_org_id not found for this customer'}, 404)
                    return

            user = _get_registry().create_user(me['customer_id'], email, password, role, client_org_id)
            self._json({'ok': True, 'user': user})
        except Exception as e:
            self._json({'error': str(e)}, 500)

    def _api_users_deactivate(self, user_id_str: str):
        me = self._session_user()
        if not me or me.get('role') not in ('admin', 'customer_admin', 'super_admin'):
            self._json({'error': 'forbidden'}, 403)
            return
        user_id = user_id_str.strip('/')
        if os.environ.get('SENTINEL_TRUSTED_PROXY'):
            self._proxy_to_admin(f'/api/users/remove/{user_id}', 'POST')
            return
        try:
            ok = _get_registry().deactivate_user(user_id, me['customer_id'])
            self._json({'ok': ok})
        except Exception as e:
            self._json({'error': str(e)}, 500)

    def _api_users_password(self, user_id_str: str):
        me = self._session_user()
        if not me or me.get('role') not in ('admin', 'customer_admin', 'super_admin'):
            self._json({'error': 'forbidden'}, 403)
            return
        user_id = user_id_str.strip('/')
        cl = int(self.headers.get('Content-Length', 0))
        raw = self.rfile.read(cl) if cl else b'{}'
        if os.environ.get('SENTINEL_TRUSTED_PROXY'):
            self._proxy_to_admin(f'/api/users/password/{user_id}', 'POST', raw)
            return
        try:
            body = json.loads(raw)
            new_password = str(body.get('new_password', ''))
            if len(new_password) < 8:
                self._json({'error': 'password too short'}, 400)
                return
            ok = _get_registry().change_user_password(user_id, me['customer_id'], new_password)
            self._json({'ok': ok} if ok else {'error': 'user not found'}, 200 if ok else 404)
        except Exception as e:
            self._json({'error': str(e)}, 500)

    def _api_reseller_customers(self):
        """GET /api/reseller/customers — proxies to the admin service so a
        reseller MSP's own customer_admin sees their resold customers inside
        their own dashboard, without a separate admin-panel login."""
        me = self._session_user()
        if not me or me.get('role') not in ('admin', 'customer_admin', 'super_admin'):
            self._json({'error': 'forbidden'}, 403)
            return
        self._proxy_to_admin('/api/reseller/customers')

    def _api_reseller_impersonate(self):
        """POST /api/reseller/impersonate — start a support session in a
        resold customer's dashboard without re-authenticating.

        The browser's real ingress is nginx on the shared IP, on a different
        port per customer but the SAME host — cookies aren't port-scoped, so
        a token cookie set here (via this response) is sent by the browser
        to any resold customer's port on the same host. We stash the
        reseller's own token in a second cookie first so "return to my
        account" can restore it without a fresh login."""
        me = self._session_user()
        if not me or me.get('role') not in ('admin', 'customer_admin', 'super_admin'):
            self._json({'error': 'forbidden'}, 403)
            return
        cl = int(self.headers.get('Content-Length', 0))
        raw = self.rfile.read(cl) if cl else b'{}'
        import urllib.request, urllib.error
        url = self._admin_panel_url() + '/api/reseller/impersonate'
        cookie = self.headers.get('Cookie', '')
        req = urllib.request.Request(url, data=raw, method='POST',
                                     headers={'Cookie': cookie, 'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            self._send(e.code, e.read(), 'application/json')
            return
        except Exception as e:
            self._json({'error': str(e)}, 502)
            return

        original_token = _get_cookie(self.headers, 'token')
        body = json.dumps({'ok': True, 'dashboard_url': data.get('dashboard_url', '')}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        if original_token:
            self.send_header('Set-Cookie',
                f'sentinel_return_token={original_token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=1800')
            self.send_header('Set-Cookie',
                f'sentinel_return_url={data.get("return_url", "")}; Path=/; HttpOnly; SameSite=Lax; Max-Age=1800')
        self.send_header('Set-Cookie',
            f'token={data.get("token", "")}; Path=/; HttpOnly; SameSite=Lax; Max-Age=1800')
        self.end_headers()
        self.wfile.write(body)

    def _api_reseller_impersonate_end(self):
        """POST /api/reseller/impersonate/end — log the end of the support
        session (while the impersonation token is still active), then
        restore the reseller's own token from the stashed cookie."""
        return_token = _get_cookie(self.headers, 'sentinel_return_token')
        return_url = _get_cookie(self.headers, 'sentinel_return_url')
        import urllib.request, urllib.error
        try:
            url = self._admin_panel_url() + '/api/reseller/impersonate/end'
            cookie = self.headers.get('Cookie', '')
            req = urllib.request.Request(url, data=b'{}', method='POST',
                                         headers={'Cookie': cookie, 'Content-Type': 'application/json'})
            with urllib.request.urlopen(req, timeout=5):
                pass
        except Exception:
            pass  # best-effort audit log; don't block the return on it

        body = json.dumps({'ok': bool(return_token), 'redirect_url': return_url}).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        if return_token:
            self.send_header('Set-Cookie', f'token={return_token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=28800')
        self.send_header('Set-Cookie', 'sentinel_return_token=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0')
        self.send_header('Set-Cookie', 'sentinel_return_url=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0')
        self.end_headers()
        self.wfile.write(body)

    def _serve_reseller(self):
        """GET /reseller — MSP-admin-only page listing customers resold under
        this account. Not in the client_viewer allowlist, so a scoped
        session never reaches this method at all."""
        me = self._session_user()
        if not me or me.get('role') not in ('admin', 'customer_admin', 'super_admin'):
            self._send(403, b'Forbidden', 'text/plain')
            return
        body = """<!DOCTYPE html><html><head><meta charset="utf-8">
<title>MSP View — Arckon</title>
<style>
body{font:14px -apple-system,sans-serif;background:#0d1117;color:#c9d1d9;margin:0;padding:32px}
h1{font-size:20px;font-weight:600;margin:0 0 20px}
a.back{color:#58a6ff;text-decoration:none;font-size:13px}
table{width:100%;border-collapse:collapse;margin-top:16px;background:#161b22;border-radius:8px;overflow:hidden}
th{text-align:left;padding:10px 14px;background:#21262d;color:#8b949e;font-weight:500;font-size:12px;text-transform:uppercase}
td{padding:10px 14px;border-top:1px solid #21262d}
.badge-green{color:#16A34A}
.badge-red{color:#DC2626}
#msg{padding:32px;text-align:center;color:#8b949e}
</style></head><body>
<a class="back" id="backlink" href="/">&larr; Back to dashboard</a>
<script>if (window.self !== window.top) { var _bl = document.getElementById('backlink'); if (_bl) _bl.style.display = 'none'; }</script>
<h1>MSP View</h1>
<div id="msg">Loading…</div>
<table id="tbl" style="display:none">
<tr><th>Name</th><th>Status</th><th>Plan</th><th>Seats used</th><th>License expiry</th><th></th></tr>
</table>
<div id="enter-status" style="margin-top:12px;font-size:13px;color:#8b949e"></div>
<script>
async function load(){
  const msg = document.getElementById('msg');
  const tbl = document.getElementById('tbl');
  try {
    const r = await fetch('/api/reseller/customers');
    const data = await r.json();
    if (!r.ok) {
      msg.textContent = data.error === 'this account is not flagged as a reseller MSP'
        ? 'This account is not set up as a reseller MSP. Contact Arckon to enable reselling on your account.'
        : (data.error || 'Failed to load resold customers.');
      return;
    }
    const customers = data.customers || [];
    if (!customers.length) {
      msg.textContent = 'No resold customers yet.';
      return;
    }
    msg.style.display = 'none';
    tbl.style.display = '';
    customers.forEach(c => {
      const tr = document.createElement('tr');
      const status = c.active ? '<span class="badge-green">Active</span>' : '<span class="badge-red">Archived</span>';
      const seats = c.current_agents + ' / ' + c.max_seats;
      const expiry = c.license_expires_at ? c.license_expires_at.slice(0,10) : '—';
      const enterBtn = c.active
        ? '<button onclick="enterCustomer(\\'' + c.id + '\\', this)" style="background:#238636;color:#fff;border:none;padding:5px 12px;border-radius:4px;cursor:pointer;font-size:12px">Enter dashboard</button>'
        : '—';
      tr.innerHTML = '<td>' + c.name + '</td><td>' + status + '</td><td>' + (c.tier || '—') + '</td>' +
        '<td>' + seats + '</td><td>' + expiry + '</td><td>' + enterBtn + '</td>';
      tbl.appendChild(tr);
    });
  } catch(e) {
    msg.textContent = 'Network error loading resold customers.';
  }
}

async function enterCustomer(customerId, btn){
  const statusEl = document.getElementById('enter-status');
  btn.disabled = true;
  statusEl.textContent = 'Starting support session…';
  try {
    const r = await fetch('/api/reseller/impersonate', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({customer_id: customerId})
    });
    const data = await r.json();
    if (data.ok && data.dashboard_url) {
      window.location = data.dashboard_url;
    } else {
      statusEl.textContent = data.error || 'Failed to start support session.';
      btn.disabled = false;
    }
  } catch(e) {
    statusEl.textContent = 'Network error.';
    btn.disabled = false;
  }
}
load();
</script>
</body></html>"""
        self._send(200, body.encode('utf-8'), 'text/html; charset=utf-8')

    # ── client org management (MSP admin only — never reachable by client_viewer,
    # see _CLIENT_VIEWER_ALLOWED_EXACT/_PREFIX) ───────────────────────────────

    def _api_clients_list(self):
        me = self._session_user()
        if not me or me.get('role') not in ('admin', 'customer_admin', 'super_admin'):
            self._json({'error': 'forbidden'}, 403)
            return
        try:
            reg = _get_registry()
            orgs = reg.list_client_orgs(me['customer_id'])
            rollup = self._store().rollup_by_client_org()
            out = []
            for o in orgs:
                stats = rollup.get(o['id'], {
                    'device_count': 0, 'critical': 0, 'warning': 0, 'ok': 0,
                    'no_data': 0, 'last_scan_at': 0, 'worst_severity': 'no_data',
                })
                out.append({**o, **stats})
            unassigned = rollup.get(None)
            if unassigned:
                out.append({'id': None, 'name': 'Unassigned', 'enroll_token': None, **unassigned})
            self._json({'client_orgs': out})
        except Exception as e:
            self._json({'error': str(e)}, 500)

    def _api_devices_assign_client_org(self):
        """POST /api/clients/assign-devices — bulk move devices between client
        orgs (or back to unassigned) without touching agent_config.json on
        each machine. This is the scale-friendly alternative to per-device
        re-enrollment for fleets too large to hand-edit one at a time."""
        me = self._session_user()
        if not me or me.get('role') not in ('admin', 'customer_admin', 'super_admin'):
            self._json({'error': 'forbidden'}, 403)
            return
        cl = int(self.headers.get('Content-Length', 0))
        raw = self.rfile.read(cl) if cl else b'{}'
        try:
            body = json.loads(raw)
            device_ids = body.get('device_ids', [])
            client_org_id = str(body.get('client_org_id', '')).strip()
            if not isinstance(device_ids, list) or not device_ids:
                self._json({'error': 'device_ids is required'}, 400)
                return
            if client_org_id:
                org = _get_registry().get_client_org(client_org_id)
                if not org or org.get('customer_id') != me['customer_id']:
                    self._json({'error': 'client_org_id not found for this customer'}, 404)
                    return
            store = self._store()
            moved = 0
            for device_id in device_ids:
                if store.set_device_client_org(str(device_id), client_org_id or None):
                    moved += 1
            self._json({'ok': True, 'moved': moved})
        except Exception as e:
            self._json({'error': str(e)}, 500)

    def _api_clients_add(self):
        me = self._session_user()
        if not me or me.get('role') not in ('admin', 'customer_admin', 'super_admin'):
            self._json({'error': 'forbidden'}, 403)
            return
        cl = int(self.headers.get('Content-Length', 0))
        raw = self.rfile.read(cl) if cl else b'{}'
        try:
            body = json.loads(raw)
            name = str(body.get('name', '')).strip()
            if not name:
                self._json({'error': 'name is required'}, 400)
                return
            org = _get_registry().create_client_org(me['customer_id'], name)
            self._json({'ok': True, 'client_org': org})
        except Exception as e:
            self._json({'error': str(e)}, 500)

    def _api_clients_rename(self, org_id_str: str):
        me = self._session_user()
        if not me or me.get('role') not in ('admin', 'customer_admin', 'super_admin'):
            self._json({'error': 'forbidden'}, 403)
            return
        org_id = org_id_str.strip('/')
        cl = int(self.headers.get('Content-Length', 0))
        raw = self.rfile.read(cl) if cl else b'{}'
        try:
            body = json.loads(raw)
            name = str(body.get('name', '')).strip()
            if not name:
                self._json({'error': 'name is required'}, 400)
                return
            ok = _get_registry().rename_client_org(org_id, me['customer_id'], name)
            self._json({'ok': ok} if ok else {'error': 'client org not found'}, 200 if ok else 404)
        except Exception as e:
            self._json({'error': str(e)}, 500)

    def _api_clients_deactivate(self, org_id_str: str):
        me = self._session_user()
        if not me or me.get('role') not in ('admin', 'customer_admin', 'super_admin'):
            self._json({'error': 'forbidden'}, 403)
            return
        org_id = org_id_str.strip('/')
        try:
            ok = _get_registry().deactivate_client_org(org_id, me['customer_id'])
            self._json({'ok': ok} if ok else {'error': 'client org not found'}, 200 if ok else 404)
        except Exception as e:
            self._json({'error': str(e)}, 500)

    def _api_clients_report_config(self, org_id_str: str):
        """POST /api/clients/report-config/<org_id> — set the monthly
        white-label PDF delivery email + cadence for one client org."""
        me = self._session_user()
        if not me or me.get('role') not in ('admin', 'customer_admin', 'super_admin'):
            self._json({'error': 'forbidden'}, 403)
            return
        org_id = org_id_str.strip('/')
        cl = int(self.headers.get('Content-Length', 0))
        raw = self.rfile.read(cl) if cl else b'{}'
        try:
            body = json.loads(raw)
            report_email = str(body.get('report_email', '')).strip()
            report_cadence = str(body.get('report_cadence', 'off')).strip()
            if report_cadence == 'monthly' and '@' not in report_email:
                self._json({'error': 'a valid report_email is required to enable monthly reports'}, 400)
                return
            ok = _get_registry().set_client_org_report_config(
                org_id, me['customer_id'], report_email, report_cadence)
            self._json({'ok': ok} if ok else {'error': 'client org not found'}, 200 if ok else 404)
        except Exception as e:
            self._json({'error': str(e)}, 500)

    def _api_clients_send_report(self, org_id_str: str):
        """POST /api/clients/send-report/<org_id> — send the report right
        now, using report_email if set, otherwise a one-off address in the
        request body. Same send_client_org_report() code path the daily
        scheduler uses, so a successful manual test is a real guarantee."""
        me = self._session_user()
        if not me or me.get('role') not in ('admin', 'customer_admin', 'super_admin'):
            self._json({'error': 'forbidden'}, 403)
            return
        org_id = org_id_str.strip('/')
        cl = int(self.headers.get('Content-Length', 0))
        raw = self.rfile.read(cl) if cl else b'{}'
        try:
            body = json.loads(raw) if raw.strip() else {}
        except json.JSONDecodeError:
            body = {}
        org = _get_registry().get_client_org(org_id)
        if not org or org.get('customer_id') != me['customer_id']:
            self._json({'error': 'client org not found'}, 404)
            return
        to_addr = str(body.get('report_email', '')).strip() or org.get('report_email', '')
        if '@' not in to_addr:
            self._json({'ok': False, 'error': 'no report_email set for this client — provide one or save it first'}, 400)
            return
        ok, msg = send_client_org_report(me['customer_id'], org_id, org['name'], to_addr)
        self._json({'ok': ok, 'message': msg})

    def _api_customers_me(self):
        me = self._session_user()
        if not me:
            self._json({'error': 'unauthorized'}, 401)
            return
        if os.environ.get('SENTINEL_TRUSTED_PROXY'):
            # Cloud mode: each container is one customer.
            # Agent token is the env var set at provision time.
            agent_token = os.environ.get('SENTINEL_AGENT_TOKEN', '')
            if not agent_token:
                tok_file = ROOT / 'data' / 'agent_token.txt'
                if tok_file.exists():
                    agent_token = tok_file.read_text().strip()
            # Company name: first (only) customer in registry, else env var
            name = os.environ.get('SENTINEL_CUSTOMER_NAME', '')
            if not name:
                try:
                    custs = _get_registry().list_customers()
                    name = custs[0]['name'] if custs else ''
                except Exception:
                    pass
            self._json({'id': 'default', 'name': name, 'agent_token': agent_token})
            return
        cust = _get_registry().get_by_id(me['customer_id'])
        if not cust:
            self._json({'error': 'customer not found'}, 404)
            return
        self._json({
            'id':          cust['id'],
            'name':        cust['name'],
            'agent_token': cust['agent_token'],
        })

    # ── endpoints ─────────────────────────────────────────────────────────────

    def _serve_dashboard(self):
        self._serve_fleet()

    def _api_status(self):
        with _lock:
            self._json({'status': _status, 'lines': len(_log)})

    def _api_maintenance_notice(self):
        """GET /api/maintenance-notice — relays sentinel-admin's
        /api/maintenance/active so browsers can poll it without needing
        direct network access to the internal admin service (which isn't
        exposed to the public internet). Fails soft: a network blip here
        should never break the dashboard, just means no banner shows."""
        try:
            import urllib.request
            req = urllib.request.Request('http://sentinel-admin:8000/api/maintenance/active')
            with urllib.request.urlopen(req, timeout=3) as resp:
                data = json.loads(resp.read().decode())
            self._json(data)
        except Exception as e:
            log.debug('maintenance notice relay failed: %s', e)
            self._json({'notice': None})

    def _api_health(self):
        """Basic health endpoint for monitoring. Returns 200 + JSON when the dashboard server is reachable.
        Includes server time and which dashboard (demo_*) folder is being served, if any.
        """
        try:
            out_dir = _latest_out_dir()
            if out_dir and (out_dir / 'dashboard.html').exists():
                dash = {
                    'name': out_dir.name,
                    'dashboard': str(out_dir / 'dashboard.html'),
                }
            else:
                dash = None
        except Exception:
            dash = None
        self._json({
            'status': 'ok',
            'server': 'sentinel-dashboard',
            'time': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'dashboard': dash,
        })

    def _serve_release_file(self, path: str):
        file_path = _release_file(path)
        if file_path is None:
            self._not_found()
            return
        content_type = mimetypes.guess_type(file_path.name)[0] or 'application/octet-stream'
        self._send(200, file_path.read_bytes(), content_type)

    def _serve_device_dashboard(self, device_id: str):
        """GET /fleet/device/<id>/dashboard — full single-device dashboard with all views."""
        if not device_id:
            self._not_found()
            return
        try:
            report = self._store().get_latest_report(device_id)
        except Exception as e:
            log.error('get_latest_report error for %s: %s', device_id, e)
            self._send(500, f'Store error: {e}'.encode(), 'text/plain')
            return
        if report is None:
            try:
                device = self._store().get_device(device_id)
            except Exception:
                device = None
            if device is None:
                self._send(404, b'Device not found', 'text/plain')
            else:
                hostname = device.get('hostname', device_id)
                html = (
                    b'<!doctype html><html><head>'
                    b'<meta charset="utf-8">'
                    b'<style>body{font-family:system-ui;background:#0d1117;color:#8b949e;'
                    b'display:flex;align-items:center;justify-content:center;height:100vh;margin:0}'
                    b'div{text-align:center}.title{font-size:18px;color:#e6edf3;margin-bottom:8px}'
                    b'.sub{font-size:13px}</style></head><body><div>'
                    b'<div class="title">No scan report yet for ' + __import__('html').escape(hostname).encode() + b'</div>'
                    b'<div class="sub">The agent has registered but has not completed a scan.<br>'
                    b'Reports arrive automatically after each scan cycle.</div>'
                    b'</div></body></html>'
                )
                self._send(200, html, 'text/html; charset=utf-8')
            return
        try:
            sys.path.insert(0, str(ROOT))
            from output.dashboard import generate
            import tempfile
            import os as _os
            with tempfile.NamedTemporaryFile(suffix='.html', delete=False) as tf:
                tmp_path = tf.name
            try:
                generate([report], tmp_path,
                         meta={'scan_date': report.get('scan_date', ''),
                               'target':    report.get('target', device_id)})
                html = Path(tmp_path).read_bytes()
            finally:
                try:
                    _os.unlink(tmp_path)
                except OSError:
                    pass
            self._send(200, html, 'text/html; charset=utf-8')
        except Exception as e:
            log.error('dashboard generation error for %s: %s', device_id, e)
            self._send(500, f'Dashboard generation failed: {e}'.encode(), 'text/plain')

    def _serve_device_pdf(self, device_id: str):
        """GET /fleet/device/<id>/report.pdf — download single-device audit report as PDF."""
        if not device_id:
            self._not_found()
            return
        try:
            report = self._store().get_latest_report(device_id)
        except Exception as e:
            log.error('get_latest_report error for %s: %s', device_id, e)
            self._send(500, f'Store error: {e}'.encode(), 'text/plain')
            return
        if report is None:
            self._send(404, b'No report found for this device', 'text/plain')
            return
        try:
            sys.path.insert(0, str(ROOT))
            from output.pdf_report import format_pdf
            results_raw = report.get('results', [])
            profile = {'name': report.get('profile', 'AI-STIG')}
            target = report.get('target', device_id)
            mode = report.get('mode', 'config')

            class _R:
                def __init__(self, d):
                    self.check_id  = d.get('check_id', '')
                    self.title     = d.get('title', '')
                    self.status    = d.get('status', '')
                    self.severity  = d.get('severity', '')
                    self.details   = d.get('details', '')
                    self.remediation = d.get('remediation', '')

            results = [_R(r) for r in results_raw]
            pdf_bytes = format_pdf(results, profile, target, mode)
            hostname = report.get('target', device_id).replace('/', '_').replace(' ', '_')
            filename = f'sentinel_{hostname}.pdf'
            self.send_response(200)
            self.send_header('Content-Type', 'application/pdf')
            self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
            self.send_header('Content-Length', str(len(pdf_bytes)))
            self.end_headers()
            self.wfile.write(pdf_bytes)
        except Exception as e:
            log.error('device pdf generation error for %s: %s', device_id, e)
            self._send(500, f'PDF generation failed: {e}'.encode(), 'text/plain')

    def _api_events(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/event-stream')
        self.send_header('Cache-Control', 'no-cache')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        sent = 0
        try:
            while True:
                with _lock:
                    snap_log    = list(_log)
                    snap_status = _status
                while sent < len(snap_log):
                    msg = json.dumps({'t': 'log', 'line': snap_log[sent]})
                    self.wfile.write(f'data: {msg}\n\n'.encode())
                    self.wfile.flush()
                    sent += 1
                if snap_status in ('done', 'error') and sent >= len(snap_log):
                    msg = json.dumps({'t': 'done', 'status': snap_status})
                    self.wfile.write(f'data: {msg}\n\n'.encode())
                    self.wfile.flush()
                    break
                time.sleep(0.15)
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass

    def _api_scan(self):
        global _status
        with _lock:
            if _status == 'running':
                self._json({'error': 'scan already running'}, 409)
                return
            _status = 'running'
        length = _content_length(self.headers)
        if length > 65_536:
            self._send(413, b'Payload too large', 'text/plain')
            return
        body = json.loads(self.rfile.read(length)) if length else {}
        raw_target = body.get('target', '.')
        safe_target = os.path.realpath(raw_target)
        if not safe_target.startswith(os.path.realpath(str(ROOT))):
            safe_target = str(ROOT)
        mode = body.get('mode', 'config')
        if mode not in ('config', 'api', 'local', 'gemini', 'vertex', 'anthropic', 'hash'):
            mode = 'config'
        profile = body.get('profile', 'default')
        if not profile.replace('-', '').replace('_', '').isalnum():
            profile = 'default'
        live_cfg = None
        if mode != 'config':
            if not _has_live_scan():
                self._json({'error': 'Live scan requires a Plus license'}, 403)
                return
            live_cfg = _load_live_scan_config()
        threading.Thread(
            target=_run_scan,
            args=(mode, safe_target, profile, body.get('providers', []), live_cfg),
            daemon=True,
        ).start()
        self._json({'status': 'started'})

    # ── agent API ─────────────────────────────────────────────────────────────

    def _api_agent_report(self):
        if not self._check_agent_bearer():
            self._send(401, b'Unauthorized', 'text/plain')
            return

        length = _content_length(self.headers)
        if not length:
            self._send(400, b'Empty body', 'text/plain')
            return
        if length > 1_048_576:
            self._send(413, b'Payload too large', 'text/plain')
            return
        try:
            body = json.loads(self.rfile.read(length))
        except json.JSONDecodeError:
            self._send(400, b'Invalid JSON', 'text/plain')
            return

        device_id = body.get('device_id', '')
        hostname  = body.get('hostname', 'unknown')
        report    = body.get('report')
        if not device_id or not report:
            self._send(400, b'Missing device_id or report', 'text/plain')
            return

        now = time.time()
        with _report_lock:
            last = _report_last_seen.get(device_id, 0.0)
            if now - last < _REPORT_MIN_INTERVAL:
                self._send(429, b'Too many reports - wait 60s between submissions', 'text/plain')
                return
            _report_last_seen[device_id] = now

        # Prefer the customer's own store (resolved from bearer token) for new devices.
        # _get_store_for_device falls back to 'default' for unknown devices, which causes
        # reports to land in the wrong store when the agent uses a customer-specific token.
        _agent_cust = self._get_agent_customer()
        _cust_id = _agent_cust.get('id') if _agent_cust else None
        if _cust_id and _cust_id != 'default':
            store = _get_store(_cust_id)
            if not store.is_known_device(device_id):
                # Device not in customer store yet — check all stores first
                store = _get_store_for_device(device_id)
                # If still in wrong store, migrate to customer store
                if store is not _get_store(_cust_id):
                    store = _get_store(_cust_id)
        else:
            store = _get_store_for_device(device_id)
        is_new = not store.is_known_device(device_id)

        # Duplicate hostname detection — warn when a new device_id uses an existing hostname
        duplicate_warning = None
        if is_new and not (hostname.startswith('docker:') or hostname.startswith('k8s:')):
            try:
                existing = [d for d in store.find_devices_by_hostname(hostname)
                            if d['device_id'] != device_id]
                if existing:
                    ids = [d['device_id'] for d in existing]
                    log.warning(
                        'DUPLICATE HOSTNAME: new device %s (%s) shares hostname "%s" '
                        'with existing device(s) %s — possible agent reinstall or ID change',
                        device_id, body.get('platform', ''), hostname, ids,
                    )
                    duplicate_warning = {
                        'message': f'Hostname "{hostname}" already registered under different device ID(s): {ids}',
                        'existing_ids': ids,
                    }
            except Exception as _de:
                log.error('duplicate check error: %s', _de)

        # License seat check — only runs when this is a previously unseen device
        license_status = 'ok'
        try:
            from license import check_overage
            if is_new:
                current_count = store.device_count() + 1  # +1 for the device being registered
                license_status = check_overage(device_id, hostname, current_count, store)
        except Exception as _le:
            log.error('license check error: %s', _le)

        # Resolve the optional client-org enrollment token (embedded in the
        # agent's config for MSP sub-clients) to a client_org_id. Empty
        # string on any failure/absence — upsert_report() treats that as
        # "don't touch the existing assignment", never as "clear it".
        client_org_id = ''
        client_org_token = body.get('client_org_token', '').strip()
        if client_org_token:
            org = _get_registry().get_client_org_by_token(client_org_token)
            if org and org.get('customer_id') == _cust_id:
                client_org_id = org['id']
            else:
                log.warning(
                    'agent %s sent client_org_token that did not resolve for customer %s',
                    device_id, _cust_id,
                )

        try:
            store.upsert_report(
                device_id=device_id,
                hostname=hostname,
                report=report,
                platform=body.get('platform', ''),
                agent_version=body.get('agent_version', ''),
                ip_address=self.client_address[0],
                client_org_id=client_org_id,
            )
        except Exception as e:
            log.error('agent store error: %s', e)
            self._send(500, b'Storage error', 'text/plain')
            return

        # New devices inherit the customer baseline before their first
        # scheduled scan. Existing devices are updated when an admin changes
        # the baseline, preserving one-time scan overrides.
        if is_new:
            try:
                profile = _load_baseline_profile()
                store.enqueue_command(device_id, f'set_config:{json.dumps({"profile": profile})}')
            except Exception as _be:
                log.error('baseline profile dispatch error: %s', _be)

        try:
            from alerts import load_alert_config, fire_alerts
            alert_cfg = load_alert_config(ROOT / 'data' / 'alerts_config.json') or {}
            # Per-client PSA override: if this device belongs to a client org
            # that has its own PSA config, route its tickets there instead of
            # the customer-wide default. Only the 'psa' key is swapped —
            # Slack/email/webhook alert channels stay on the customer-wide
            # config, since those aren't yet client-org-scoped.
            if client_org_id:
                override = _get_registry().get_client_org_psa_override(client_org_id)
                if override is not None:
                    alert_cfg = {**alert_cfg, 'psa': override}
            if alert_cfg:
                threading.Thread(
                    target=fire_alerts,
                    args=(report, device_id, hostname, alert_cfg, store),
                    daemon=True,
                ).start()
        except Exception as _ae:
            log.error('alerts error: %s', _ae)

        try:
            from connectors.siem_connector import load_siem_config, send_report as siem_send
            _siem_cfg = load_siem_config(ROOT / 'siem_config.json')
            if _siem_cfg:
                _cid = store._customer_id if hasattr(store, '_customer_id') else 'default'
                threading.Thread(
                    target=siem_send,
                    args=(report,),
                    kwargs=dict(device_id=device_id, hostname=hostname,
                                customer_id=_cid, cfg=_siem_cfg),
                    daemon=True,
                ).start()
        except Exception as _se:
            log.error('siem dispatch error: %s', _se)

        resp = {'status': 'accepted', 'device_id': device_id, 'license_status': license_status}
        if duplicate_warning:
            resp['warning'] = duplicate_warning
        # If this agent is still using the old rollover token, deliver the new one
        # in the response body so the agent self-updates without any manual intervention.
        try:
            cust_cfg = store.get_customer_config() if hasattr(store, 'get_customer_config') else {}
            if cust_cfg and cust_cfg.get('using_old_token') and cust_cfg.get('new_token'):
                resp['token_update'] = {'token': cust_cfg['new_token']}
                log.info('Token rollover delivery: sent new token to device %s (%s)',
                         device_id, hostname)
        except Exception:
            pass  # Token rollover is optional; don't fail the whole report
        self._json(resp)

    def _api_agent_commands(self, device_id: str):
        """GET /api/agent/commands/<device_id> — agent polls for pending commands."""
        if not device_id:
            self._json({'command': None})
            return
        if not self._check_agent_bearer():
            self._send(401, b'Unauthorized', 'text/plain')
            return
        # Route to the customer store derived from the agent's token, not the default store.
        _agent_cust = self._get_agent_customer()
        _cust_id = _agent_cust.get('id') if _agent_cust else None
        if _cust_id and _cust_id != 'default':
            store = _get_store(_cust_id)
        else:
            store = _get_store_for_device(device_id)
        store.touch_device(device_id)
        command = store.claim_command(device_id)
        self._json({'command': command})

    def _api_fleet_scan(self, device_id: str):
        """POST /api/fleet/scan/<device_id> — enqueue one or more profile scans for a device.
        Body (optional): {"profiles": ["fedramp", "cmmc"]}
        If profiles is absent or empty, falls back to scan_now (uses agent's saved profile).
        """
        if not device_id:
            self._json({'error': 'missing device_id'}, 400)
            return
        store = self._store()
        if store.get_device(device_id) is None:
            self._json({'error': 'device not found'}, 404)
            return

        body = {}
        try:
            length = _content_length(self.headers)
            if length:
                body = json.loads(self.rfile.read(length))
        except Exception:
            pass

        profiles = [p.strip() for p in (body.get('profiles') or []) if p.strip()]
        _VALID = {'default', 'fedramp', 'fedramp_20x', 'cmmc', 'financial', 'professional_services',
                  'healthcare', 'biotech', 'lifesciences', 'owasp_agentic', 'eu_ai_act',
                  'iso42001', 'atlas', 'kubernetes', 'docker'}
        profiles = [p for p in profiles if p in _VALID]

        cmd_store = _get_store_for_device(device_id)
        if profiles:
            cmd_ids = [cmd_store.enqueue_command(device_id, f'scan_profile:{p}') for p in profiles]
            self._json({'status': 'queued', 'device_id': device_id,
                        'profiles': profiles, 'command_ids': cmd_ids})
        else:
            cmd_id = cmd_store.enqueue_command(device_id, 'scan_now')
            self._json({'status': 'queued', 'device_id': device_id, 'command_id': cmd_id})

    def _api_fleet_scan_all(self):
        """POST /api/fleet/scan/all — enqueue scans for every device with optional stagger.
        Body: {"profiles": ["fedramp"], "stagger": "normal"}
        stagger: "instant" (all at once), "normal" (25/30s), "slow" (10/60s)
        """
        body = {}
        try:
            length = _content_length(self.headers)
            if length:
                body = json.loads(self.rfile.read(length))
        except Exception:
            pass

        _VALID = {'default', 'fedramp', 'fedramp_20x', 'cmmc', 'financial', 'professional_services',
                  'healthcare', 'biotech', 'lifesciences', 'owasp_agentic', 'eu_ai_act',
                  'iso42001', 'atlas', 'kubernetes', 'docker'}
        profiles = [p for p in (body.get('profiles') or []) if p in _VALID]
        stagger  = body.get('stagger', 'normal')

        PRESETS = {
            'instant': (9999, 0),
            'normal':  (25,   30),
            'slow':    (10,   60),
        }
        batch_size, sleep_secs = PRESETS.get(stagger, PRESETS['normal'])

        store   = self._store()
        devices = [d for d in store.list_devices(client_org_id=self._scoped_client_org()) if d.get('device_id')]
        total   = len(devices)

        def _dispatch():
            for i in range(0, total, batch_size):
                batch = devices[i:i + batch_size]
                for device in batch:
                    did = device['device_id']
                    cs = _get_store_for_device(did)
                    if profiles:
                        for p in profiles:
                            cs.enqueue_command(did, f'scan_profile:{p}')
                    elif device.get('hostname', '').startswith('docker:'):
                        cs.enqueue_command(did, 'scan_profile:docker')
                    elif device.get('hostname', '').startswith('k8s:'):
                        cs.enqueue_command(did, 'scan_profile:kubernetes')
                    else:
                        # No explicit override: scan each device's saved
                        # customer baseline profile.
                        cs.enqueue_command(did, 'scan_now')
                if sleep_secs and i + batch_size < total:
                    time.sleep(sleep_secs)

        threading.Thread(target=_dispatch, daemon=True, name='scan-all-dispatch').start()
        self._json({'status': 'dispatching', 'total': total,
                    'profiles': profiles, 'using_baseline': not profiles, 'stagger': stagger,
                    'batch_size': batch_size, 'sleep_secs': sleep_secs})

    def _api_fleet_update(self, device_id: str):
        """POST /api/fleet/update/<device_id> — push update_self command to one device."""
        if not device_id:
            self._json({'error': 'missing device_id'}, 400)
            return
        store = self._store()
        if store.get_device(device_id) is None:
            self._json({'error': 'device not found'}, 404)
            return
        cmd_id = store.enqueue_command(device_id, 'update_self')
        self._json({'status': 'queued', 'device_id': device_id, 'command_id': cmd_id})

    def _api_fleet_update_all(self):
        """POST /api/fleet/update/all — push update_self command to every known device."""
        store = self._store()
        devices = store.list_devices()
        queued = []
        for d in devices:
            did = d.get('device_id', '')
            if did:
                store.enqueue_command(did, 'update_self')
                queued.append(did)
        self._json({'status': 'queued', 'count': len(queued), 'devices': queued})

    def _api_fleet_push_token(self):
        """POST /api/fleet/push-token — queue set_config token update for all known devices.
        Called by the admin panel immediately after token rotation so agents receive the
        new token via the command poll channel (every 15s) in addition to the in-band
        delivery on their next check-in report."""
        cust = self._get_dashboard_customer()
        if not cust:
            self._send(403, b'Forbidden', 'text/plain')
            return
        import json as _json
        new_token = cust.get('agent_token', '')
        if not new_token:
            self._json({'error': 'no token found'}, 400)
            return
        store = self._store()
        devices = store.list_devices()
        cmd_payload = _json.dumps({'token': new_token})
        queued = []
        for d in devices:
            did = d.get('device_id', '')
            if did:
                store.enqueue_command(did, f'set_config:{cmd_payload}')
                queued.append(did)
        log.info('Token push queued for %d devices (customer %s)', len(queued), cust.get('id'))
        self._json({'status': 'queued', 'device_count': len(queued)})

    def _api_fleet_remove(self, device_id: str):
        """POST /api/fleet/remove/<id> — permanently delete a device and its history."""
        device_id = device_id.strip()
        if not device_id:
            self._json({'error': 'missing device_id'}, 400)
            return
        found = self._store().delete_device(device_id)
        self._json({'status': 'removed' if found else 'not_found', 'device_id': device_id})

    def _api_agent_discovery(self):
        """POST /api/agent/discovery — agent reports subnet scan results (unmanaged devices)."""
        length = _content_length(self.headers)
        if not length or length > 2_097_152:
            self._send(400, b'Bad request', 'text/plain')
            return
        try:
            body = json.loads(self.rfile.read(length))
        except json.JSONDecodeError:
            self._send(400, b'Invalid JSON', 'text/plain')
            return

        device_id       = body.get('device_id', '')
        reporter_host   = body.get('hostname', 'unknown')
        results         = body.get('results', [])
        if not device_id or not isinstance(results, list):
            self._send(400, b'Missing device_id or results', 'text/plain')
            return

        _cust = self._get_agent_customer()
        store = _get_store(_cust['id'] if _cust else 'default')
        agent_ips = store.list_agent_ips()
        stored = 0
        for r in results:
            host    = r.get('host', '')
            port    = r.get('port', 0)
            source  = r.get('source', 'network')
            service = r.get('service', 'Unknown AI service')
            detail  = r.get('detail', '')
            models  = r.get('models', [])
            if not host:
                continue
            # Skip network probe findings for IPs belonging to managed agents
            if source == 'network' and host in agent_ips:
                continue
            if not isinstance(models, list):
                models = []
            is_new = store.upsert_shadow_device(
                device_id, reporter_host, host, int(port), service, models, source, detail
            )
            stored += 1
            if is_new and not store.is_service_approved(service):
                try:
                    from alerts import load_alert_config, fire_shadow_alert
                    _acfg = load_alert_config(ROOT / 'data' / 'alerts_config.json')
                    if _acfg:
                        threading.Thread(
                            target=fire_shadow_alert,
                            args=(reporter_host, service, host, _acfg, source, store),
                            daemon=True,
                        ).start()
                except Exception as _ae:
                    log.error('shadow alert error: %s', _ae)

        log.info('agent discovery: %s reported %d unmanaged AI services', device_id, stored)
        self._json({'status': 'accepted', 'stored': stored})

    def _api_fleet_discover_all(self):
        """POST /api/fleet/discover/all — push discover_network command to every agent."""
        store = self._store()
        devices = store.list_devices()
        queued = []
        for d in devices:
            did = d.get('device_id', '')
            if did:
                _get_store_for_device(did).enqueue_command(did, 'discover_network')
                queued.append(did)
        self._json({'status': 'queued', 'count': len(queued), 'devices': queued})

    def _api_agent_network_assets(self):
        """POST /api/agent/network-assets — authenticated passive neighbor observations."""
        length = _content_length(self.headers)
        if not length or length > 2_097_152:
            self._send(400, b'Bad request', 'text/plain')
            return
        try:
            body = json.loads(self.rfile.read(length))
        except json.JSONDecodeError:
            self._send(400, b'Invalid JSON', 'text/plain')
            return
        device_id, results = str(body.get('device_id', '')).strip(), body.get('results', [])
        cust = self._get_agent_customer()
        store = _get_store(cust['id'] if cust else 'default')
        if not device_id or not store.get_device(device_id) or not isinstance(results, list) or len(results) > 10000:
            self._send(400, b'Missing known device_id or invalid results', 'text/plain')
            return
        import ipaddress
        import re
        mac_re = re.compile(r'^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$', re.I)
        stored = 0
        for result in results:
            if not isinstance(result, dict):
                continue
            ip = str(result.get('ip_address', '')).strip()
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            mac = str(result.get('mac_address', '')).strip().replace('-', ':').lower()
            if mac and not mac_re.fullmatch(mac):
                continue
            interface = str(result.get('interface', '')).strip()[:128]
            source = str(result.get('source', '')).strip()[:64]
            hostname = str(result.get('hostname', '')).strip()[:255]
            if not source:
                continue
            store.upsert_network_asset(device_id, ip, mac, interface, source, hostname)
            stored += 1
        log.info('passive network inventory: %s reported %d observations', device_id, stored)
        self._json({'status': 'accepted', 'stored': stored})

    def _api_fleet_discover(self, device_id: str):
        """POST /api/fleet/discover/<device_id> — push discover_network to one agent."""
        device_id = device_id.strip()
        if not device_id:
            self._json({'error': 'missing device_id'}, 400)
            return
        store = self._store()
        if store.get_device(device_id) is None:
            self._json({'error': 'device not found'}, 404)
            return
        _get_store_for_device(device_id).enqueue_command(device_id, 'discover_network')
        self._json({'status': 'queued', 'device_id': device_id})

    def _api_fleet_network_assets_discover_all(self):
        """Queue an explicit passive neighbor-cache collection on every agent."""
        devices = self._store().list_devices(client_org_id=self._scoped_client_org())
        queued = [d['device_id'] for d in devices if d.get('device_id')]
        for device_id in queued:
            _get_store_for_device(device_id).enqueue_command(device_id, 'discover_network_assets')
        self._json({'status': 'queued', 'count': len(queued), 'devices': queued})

    def _api_fleet_network_assets_discover(self, device_id: str):
        device_id = device_id.strip()
        device = self._store().get_device(device_id)
        scope = self._scoped_client_org()
        if not device or (scope is not None and device.get('client_org_id') != scope):
            self._json({'error': 'device not found'}, 404)
            return
        command_id = _get_store_for_device(device_id).enqueue_command(device_id, 'discover_network_assets')
        self._json({'status': 'queued', 'device_id': device_id, 'command_id': command_id})

    def _api_fleet_live_stats(self):
        """GET /api/fleet/live-stats — lightweight poll: stat counts + device rows HTML."""
        try:
            store   = self._store()
            devices = store.list_devices()
            shadow  = [s for s in store.list_shadow_devices() if not s.get('dismissed')]
            mcp     = [m for m in store.list_mcp_servers()    if not m.get('dismissed')]

            ts_now = int(time.time())

            def _age(ts):
                if not ts: return 'never'
                s = ts_now - ts
                if s < 120:   return f'{s}s ago'
                if s < 3600:  return f'{s // 60}m ago'
                if s < 86400: return f'{s // 3600}h ago'
                return f'{s // 86400}d ago'

            rows = ''
            for d in devices:
                fail = d.get('fail_count', 0) or 0
                warn = d.get('warn_count', 0) or 0
                pas  = d.get('pass_count', 0) or 0
                age  = _age(d.get('last_seen'))
                no_data = (fail == 0 and warn == 0 and pas == 0)
                rc   = 'r-nodata' if no_data else ('r-fail' if fail > 0 else ('r-warn' if warn > 0 else 'r-pass'))
                did  = d.get('device_id', '')
                hostname = d.get('hostname', 'unknown')
                profile  = d.get('profile', '') or ('kubernetes' if hostname.startswith('k8s:') else '')
                rows += f"""
        <tr class="dev-row" onclick="selectDevice('{did}')">
          <td class="dev-host">{hostname}</td>
          <td>{d.get('platform','')}</td>
          <td class="c-red">{fail if not no_data else '—'}</td>
          <td class="c-yellow">{warn if not no_data else '—'}</td>
          <td class="c-green">{pas if not no_data else '—'}</td>
          <td>{profile}</td>
          <td>{age}</td>
          <td><span class="risk-dot {rc}" title="{'No scan data yet' if no_data else ''}"></span></td>
          <td onclick="event.stopPropagation()" style="white-space:nowrap">
            <button class="scan-btn" id="sb-{did}" onclick="openScanModal('{did}',this)">Scan &#9662;</button>
            <button class="scan-btn" id="ub-{did}" onclick="updateDevice('{did}')"
                    style="margin-left:4px;color:#CA8A04;border-color:#D1D5DB">Update</button>
            <a href="/fleet/device/{did}/dashboard" target="_blank"
               style="margin-left:8px;background:#fff;border:1px solid #D1D5DB;color:#6B7280;
                      border-radius:6px;padding:3px 10px;font-size:12px;text-decoration:none;
                      display:inline-block;white-space:nowrap;font-weight:500"
               onmouseover="this.style.borderColor='#4F46E5';this.style.color='#4F46E5'"
               onmouseout="this.style.borderColor='#D1D5DB';this.style.color='#6B7280'">Full Report</a>
            <button class="scan-btn" onclick="removeDevice('{did}','{d.get('hostname','')}')"
                    style="margin-left:4px;color:#f85149;border-color:#30363d;font-size:11px">Remove</button>
          </td>
        </tr>"""

            if not rows:
                rows = '<tr><td colspan="8" style="text-align:center;padding:32px;color:#484f58">No agents have reported yet.</td></tr>'

            ch = med = li = 0
            try:
                for rpt in store.get_all_latest_reports():
                    rjson = rpt if isinstance(rpt, dict) else {}
                    for f in rjson.get('findings', rjson.get('results', [])):
                        if f.get('status') == 'SKIP': continue
                        sev = f.get('severity', 'INFO')
                        if sev in ('CRITICAL', 'HIGH'): ch += 1
                        elif sev == 'MEDIUM':           med += 1
                        else:                           li += 1
            except Exception:
                ch  = sum((d.get('fail_count') or 0) for d in devices)
                med = sum((d.get('warn_count') or 0) for d in devices)
                li  = sum((d.get('pass_count') or 0) for d in devices)

            self._json({
                'count':     len(devices),
                'ch':        ch,
                'med':       med,
                'li':        li,
                'shadow':    len(shadow),
                'mcp':       len(mcp),
                'rows_html': rows,
                'ts':        ts_now,
            })
        except Exception as e:
            self._json({'error': str(e)}, 500)

    def _api_fleet_k8s_status(self):
        """GET /api/fleet/k8s-status — return k8s cluster connection state."""
        try:
            store   = self._store()
            devices = store.list_devices()
            k8s_devices = [d for d in devices if (d.get('hostname') or '').startswith('k8s:')]
            if not k8s_devices:
                self._json({'connected': False, 'clusters': []})
                return
            clusters = []
            for d in k8s_devices:
                hostname = d.get('hostname', '')
                # hostname format: k8s:{context}@{machine}
                label = hostname[4:] if hostname.startswith('k8s:') else hostname
                clusters.append({
                    'device_id':  d.get('device_id', ''),
                    'label':      label,
                    'fail':       d.get('fail_count', 0) or 0,
                    'warn':       d.get('warn_count', 0) or 0,
                    'pass':       d.get('pass_count', 0) or 0,
                    'last_seen':  d.get('last_seen'),
                })
            self._json({'connected': True, 'clusters': clusters})
        except Exception as e:
            self._json({'error': str(e)}, 500)

    def _api_fleet_shadow(self):
        """GET /api/fleet/shadow — list discovered unmanaged AI devices."""
        try:
            shadow = self._store().list_shadow_devices()
            self._json({'devices': shadow, 'count': len(shadow)})
        except Exception as e:
            self._json({'error': str(e)}, 500)

    def _api_fleet_network_assets(self):
        """GET /api/fleet/network-assets — separately stored passive network inventory."""
        assets = self._store().list_network_assets(client_org_id=self._scoped_client_org())
        self._json({'assets': assets, 'count': len(assets)})

    def _api_fleet_shadow_dismiss(self, shadow_id_str: str):
        """POST /api/fleet/shadow/dismiss/<id|all> — dismiss one or all shadow findings."""
        if shadow_id_str.strip() == 'all':
            count = self._store().dismiss_all_shadow_devices()
            self._json({'status': 'dismissed', 'count': count})
            return
        try:
            shadow_id = int(shadow_id_str.strip())
        except ValueError:
            self._json({'error': 'invalid id'}, 400)
            return
        found = self._store().dismiss_shadow_device(shadow_id)
        self._json({'status': 'dismissed' if found else 'not_found'})

    def _api_agent_mcp(self):
        """POST /api/agent/mcp — receive MCP server findings from an agent."""
        length = _content_length(self.headers)
        if not length:
            self._json({'error': 'empty body'}, 400)
            return
        try:
            data = json.loads(self.rfile.read(length))
        except Exception:
            self._json({'error': 'invalid JSON'}, 400)
            return
        device_id     = data.get('device_id', '').strip()
        reporter_host = data.get('hostname',   '').strip()
        results       = data.get('results',    [])
        if not device_id or not isinstance(results, list):
            self._json({'error': 'missing fields'}, 400)
            return
        _cust = self._get_agent_customer()
        store = _get_store(_cust['id'] if _cust else 'default')
        stored  = 0
        for r in results:
            host         = str(r.get('host', '')).strip()
            port         = r.get('port', 0)
            server_name  = str(r.get('server_name', '')).strip()
            tools        = r.get('tools', [])
            auth_status  = str(r.get('auth_status', 'unknown')).strip()
            source       = 'process' if r.get('source') == 'mcp_process' else 'network'
            process_info = str(r.get('process_info', '')).strip()
            if not host:
                continue
            if not isinstance(tools, list):
                tools = []
            store.upsert_mcp_server(
                device_id, reporter_host, host, int(port), server_name,
                tools, auth_status, source, process_info,
            )
            stored += 1
        log.info('agent mcp: %s reported %d MCP servers', device_id, stored)
        self._json({'status': 'accepted', 'stored': stored})

    def _api_fleet_mcp(self):
        """GET /api/fleet/mcp — list discovered MCP servers."""
        try:
            servers = self._store().list_mcp_servers()
            self._json({'servers': servers, 'count': len(servers)})
        except Exception as e:
            self._json({'error': str(e)}, 500)

    def _api_fleet_mcp_discover_all(self):
        """POST /api/fleet/mcp/discover/all — push discover_mcp to every agent."""
        store   = self._store()
        devices = store.list_devices()
        queued  = []
        for d in devices:
            did = d.get('device_id', '')
            if did:
                _get_store_for_device(did).enqueue_command(did, 'discover_mcp')
                queued.append(did)
        self._json({'status': 'queued', 'count': len(queued), 'devices': queued})

    def _api_fleet_mcp_dismiss(self, mcp_id_str: str):
        """POST /api/fleet/mcp/dismiss/<id|all> — dismiss one or all MCP findings."""
        if mcp_id_str.strip() == 'all':
            count = self._store().dismiss_all_mcp_servers()
            self._json({'status': 'dismissed', 'count': count})
            return
        try:
            mcp_id = int(mcp_id_str.strip())
        except ValueError:
            self._json({'error': 'invalid id'}, 400)
            return
        found = self._store().dismiss_mcp_server(mcp_id)
        self._json({'status': 'dismissed' if found else 'not_found'})

    def _api_fleet_mcp_report(self):
        """GET /api/fleet/mcp/report?tier=executive|ciso|technical[&fmt=pdf|html]"""
        from urllib.parse import parse_qs, urlparse as _up
        qs   = parse_qs(_up(self.path).query)
        tier = (qs.get('tier', ['ciso'])[0]).lower()
        fmt  = (qs.get('fmt',  ['html'])[0]).lower()
        if tier not in ('executive', 'ciso', 'technical'):
            tier = 'ciso'
        if tier == 'technical' and not _has_technical_reports():
            self._send(402, b'Technical MCP reports require a Plus license. Contact sales@markai.io to upgrade.', 'text/plain')
            return
        servers = self._store().list_mcp_servers()
        if fmt == 'pdf':
            try:
                from output.fleet_report import generate_mcp_pdf
                pdf_bytes = generate_mcp_pdf(servers, tier=tier, demo=_is_demo())
                fname = f'sentinel_mcp_{tier}.pdf'
                self.send_response(200)
                self.send_header('Content-Type', 'application/pdf')
                self.send_header('Content-Disposition', f'attachment; filename="{fname}"')
                self.send_header('Content-Length', str(len(pdf_bytes)))
                self.end_headers()
                self.wfile.write(pdf_bytes)
            except Exception as pdf_err:
                import traceback
                tb = traceback.format_exc()
                log.error('MCP PDF generation error:\n%s', tb)
                self._send(500, f'PDF generation failed: {pdf_err}\n\n{tb}'.encode(), 'text/plain')
            return
        html = _build_mcp_report_html(servers, tier)
        body = html.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _api_admin_license(self):
        """GET /api/admin/license — license status + overage audit log."""
        try:
            from license import license_summary
            summary = license_summary(self._store())
            self._json(summary)
        except Exception as e:
            self._json({'error': str(e)}, 500)

    def _api_fleet_report(self):
        """GET /api/fleet/report?tier=executive|ciso|technical&fmt=pdf|html|json|csv[&profile=fedramp,cmmc][&status=fail|warn|pass][&sev=ch|med|li]"""
        from urllib.parse import parse_qs, urlparse as _up
        qs = parse_qs(_up(self.path).query)
        tier          = (qs.get('tier',    ['ciso'])[0]).lower()
        fmt           = (qs.get('fmt',     ['html'])[0]).lower()
        profile_raw   = (qs.get('profile', [''])[0]).lower().strip()
        status_filter = (qs.get('status',  [''])[0]).lower().strip()
        sev_filter    = (qs.get('sev',     [''])[0]).lower().strip()
        if tier not in ('executive', 'ciso', 'technical'):
            tier = 'ciso'
        if tier == 'technical' and not _has_technical_reports():
            self._send(402, b'Technical reports require a Plus license. Contact sales@markai.io to upgrade.', 'text/plain')
            return
        if status_filter not in ('fail', 'warn', 'pass', ''):
            status_filter = ''
        if sev_filter not in ('ch', 'med', 'li', ''):
            sev_filter = ''
        _VALID_PROFILES = {'default', 'fedramp', 'fedramp_20x', 'cmmc', 'financial', 'biotech', 'healthcare', 'lifesciences', 'owasp_agentic', 'eu_ai_act', 'professional_services', 'iso42001', 'atlas', 'kubernetes', 'docker'}
        profiles = [p for p in profile_raw.split(',') if p in _VALID_PROFILES]
        profile  = ','.join(profiles)
        try:
            store = self._store()
            org_scope = self._scoped_client_org()
            if profiles:
                # /api/fleet/report *is* on the client_viewer allowlist, so
                # this branch has to carry the same org scope as the one
                # below — an unscoped call here returns every client's
                # devices to whoever asked for ?profile=.
                devices = store.list_devices_by_profile(profiles, client_org_id=org_scope)
            else:
                devices = store.list_devices(client_org_id=org_scope)
                for d in devices:
                    d['_report'] = store.get_latest_report(d['device_id']) or {}

            if fmt in ('json', 'csv'):
                payload = [{'device_id': d['device_id'], 'hostname': d['hostname'],
                            'platform': d.get('platform', ''), 'fail_count': d.get('fail_count', 0),
                            'warn_count': d.get('warn_count', 0), 'pass_count': d.get('pass_count', 0),
                            'last_seen': d.get('last_seen'), 'results': d['_report'].get('findings', d['_report'].get('results', []))}
                           for d in devices]
                if fmt == 'json':
                    self._json({'tier': tier, 'devices': payload})
                    return
                # CSV — one row per finding, not one row per device, so
                # severity/status are actually filterable in a spreadsheet.
                import csv as _csv
                import io as _io
                buf = _io.StringIO()
                writer = _csv.writer(buf)
                writer.writerow(['Device', 'Platform', 'Last Seen', 'Check ID', 'Title', 'Status', 'Severity'])
                for d in payload:
                    findings = d['results'] or [{}]
                    for f in findings:
                        writer.writerow([
                            d['hostname'], d['platform'], d.get('last_seen', ''),
                            f.get('check_id', ''), f.get('title', ''),
                            f.get('status', ''), f.get('severity', ''),
                        ])
                csv_bytes = buf.getvalue().encode('utf-8')
                fname = f'sentinel_fleet_{tier}.csv'
                self.send_response(200)
                self.send_header('Content-Type', 'text/csv')
                self.send_header('Content-Disposition', f'attachment; filename="{fname}"')
                self.send_header('Content-Length', str(len(csv_bytes)))
                self.end_headers()
                self.wfile.write(csv_bytes)
                return

            if fmt == 'pdf':
                try:
                    from output.fleet_report import generate_fleet_pdf
                    pdf_bytes = generate_fleet_pdf(devices, tier=tier, demo=_is_demo())
                    fname = f'sentinel_fleet_{tier}{"_" + profile.replace(",","_") if profile else ""}.pdf'
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/pdf')
                    self.send_header('Content-Disposition', f'attachment; filename="{fname}"')
                    self.send_header('Content-Length', str(len(pdf_bytes)))
                    self.end_headers()
                    self.wfile.write(pdf_bytes)
                    return
                except Exception as pdf_err:
                    import traceback
                    tb = traceback.format_exc()
                    log.error('fleet PDF generation error:\n%s', tb)
                    self._send(500, f'PDF generation failed: {pdf_err}\n\n{tb}'.encode(), 'text/plain')
                    return

            html = _build_fleet_report_html(devices, tier, profile=profile, profiles=profiles, status_filter=status_filter, sev_filter=sev_filter, demo=_is_demo())
            data = html.encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Security-Policy', "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:")
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:
            log.error('fleet report error: %s', e)
            self._json({'error': str(e)}, 500)

    def _api_evidence_export(self):
        """GET /api/fleet/evidence-export[?profile=fedramp,cmmc] — ZIP bundle: cover letter, findings CSV, fleet PDF, per-device JSON."""
        if not _has_evidence_package():
            self._send(402, b'Evidence Package requires a Plus license. Contact sales@markai.io to upgrade.', 'text/plain')
            return
        import io
        import zipfile
        import csv
        from urllib.parse import parse_qs, urlparse as _up
        from datetime import datetime as _dt
        qs = parse_qs(_up(self.path).query)
        profile_raw = (qs.get('profile', [''])[0]).lower().strip()
        _VALID = {'default', 'fedramp', 'fedramp_20x', 'cmmc', 'financial', 'biotech', 'healthcare',
                  'lifesciences', 'owasp_agentic', 'eu_ai_act', 'professional_services',
                  'iso42001', 'atlas', 'kubernetes', 'docker'}
        profiles = [p for p in profile_raw.split(',') if p in _VALID]
        try:
            store = self._store()
            devices = store.list_devices_by_profile(profiles) if profiles else store.list_devices()
            for d in devices:
                if '_report' not in d:
                    d['_report'] = store.get_latest_report(d['device_id']) or {}

            now = _dt.utcnow()
            date_str = now.strftime('%Y%m%d')
            profile_label = ', '.join(p.upper() for p in profiles) if profiles else 'All Profiles'

            buf = io.BytesIO()
            with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:
                cover = (
                    f"ARCKON COMPLIANCE EVIDENCE PACKAGE\n"
                    f"{'=' * 50}\n"
                    f"Generated:  {now.strftime('%Y-%m-%d %H:%M UTC')}\n"
                    f"Profile(s): {profile_label}\n"
                    f"Devices:    {len(devices)}\n"
                    f"Tool:       Arckon — AI Security Audit\n\n"
                    f"CONTENTS\n--------\n"
                    f"1. cover_letter.txt       — This document\n"
                    f"2. findings.csv           — All findings across all devices\n"
                    f"3. fleet_report.pdf       — CISO-tier fleet summary (cryptographically signed)\n"
                    f"4. manifest.json          — Report ID, signature, and key fingerprint\n"
                    f"5. device_reports/<host>.json — Per-device raw scan data\n"
                    f"6. ai_asset_inventory.csv     — All discovered AI assets with approval status\n"
                    f"7. ai_asset_approval_log.csv  — Full audit trail: who approved each asset and when\n\n"
                    f"ATTESTATION\n-----------\n"
                    f"Generated automatically by Arckon by RiskRaven. All findings\n"
                    f"reflect the most recent scan for each enrolled device. Scan\n"
                    f"data is stored locally and has not been transmitted to any\n"
                    f"third party.\n"
                )
                zf.writestr('cover_letter.txt', cover)

                csv_buf = io.StringIO()
                writer = csv.writer(csv_buf)
                writer.writerow([
                    'Device', 'Check ID', 'Title', 'Status', 'Severity', 'Category',
                    'NIST AI RMF', 'FedRAMP', 'OWASP LLM', 'MITRE ATLAS', 'ISO/IEC 42001', 'Details',
                ])
                for d in devices:
                    hostname = d.get('hostname', d.get('device_id', ''))
                    findings = d['_report'].get('findings', d['_report'].get('results', []))
                    for f in findings:
                        fw = f.get('frameworks', {}) if isinstance(f.get('frameworks'), dict) else {}
                        writer.writerow([
                            hostname,
                            f.get('check_id', ''), f.get('title', ''),
                            f.get('status', ''), f.get('severity', ''), f.get('category', ''),
                            fw.get('NIST AI RMF', ''), fw.get('FedRAMP', ''),
                            fw.get('OWASP LLM', ''), fw.get('MITRE ATLAS', ''), fw.get('ISO/IEC 42001', ''),
                            str(f.get('details', ''))[:200],
                        ])
                zf.writestr('findings.csv', csv_buf.getvalue())

                try:
                    from output.fleet_report import generate_fleet_pdf
                    from output.signing import sign_content, key_fingerprint
                    findings_json = json.dumps([{
                        'device': d.get('hostname',''), 'findings': d['_report'].get('findings', [])
                    } for d in devices], sort_keys=True)
                    report_id, sig_hex = sign_content(findings_json)
                    pdf_bytes = generate_fleet_pdf(devices, tier='ciso', report_id=report_id)
                    zf.writestr('fleet_report.pdf', pdf_bytes)
                    manifest = {
                        'report_id': report_id,
                        'generated': now.strftime('%Y-%m-%d %H:%M UTC'),
                        'devices': len(devices),
                        'profile': profile_label,
                        'signature': sig_hex,
                        'key_fingerprint': key_fingerprint(),
                        'algorithm': 'HMAC-SHA256',
                        'note': 'Signature covers findings JSON. Verify at /api/verify with report_id + signature.',
                    }
                    zf.writestr('manifest.json', json.dumps(manifest, indent=2))
                except Exception as _pe:
                    zf.writestr('fleet_report_error.txt', f'PDF generation failed: {_pe}')

                for d in devices:
                    safe_name = d.get('hostname', d.get('device_id', 'unknown')).replace('/', '_').replace('\\', '_')
                    zf.writestr(f'device_reports/{safe_name}.json', json.dumps(d['_report'], indent=2))

                # AI asset inventory + approval audit trail
                try:
                    inventory = store.list_inventory()
                    events    = store.get_all_approval_events()
                    inv_buf   = io.StringIO()
                    inv_writer = csv.writer(inv_buf)
                    inv_writer.writerow([
                        'Asset ID', 'Host', 'Port', 'Service', 'Models',
                        'Source', 'First Seen', 'Last Seen',
                        'Approval Status', 'Approved By', 'Approved At',
                    ])
                    for item in inventory:
                        approved_at = ''
                        if item.get('approved_at'):
                            from datetime import datetime as _dt2
                            approved_at = _dt2.utcfromtimestamp(item['approved_at']).strftime('%Y-%m-%d %H:%M UTC')
                        first_seen = _dt.utcfromtimestamp(item['first_seen']).strftime('%Y-%m-%d %H:%M UTC') if item.get('first_seen') else ''
                        last_seen  = _dt.utcfromtimestamp(item['last_seen']).strftime('%Y-%m-%d %H:%M UTC') if item.get('last_seen') else ''
                        inv_writer.writerow([
                            item['id'],
                            item.get('host', ''),
                            item.get('port', ''),
                            item.get('service', ''),
                            ', '.join(item.get('models', [])),
                            item.get('source', ''),
                            first_seen,
                            last_seen,
                            item.get('approval_status', 'unapproved'),
                            item.get('approved_by', ''),
                            approved_at,
                        ])
                    zf.writestr('ai_asset_inventory.csv', inv_buf.getvalue())

                    ev_buf = io.StringIO()
                    ev_writer = csv.writer(ev_buf)
                    ev_writer.writerow([
                        'Event ID', 'Asset ID', 'Host', 'Port', 'Service',
                        'From Status', 'To Status', 'Changed By', 'IP Address', 'Timestamp (UTC)',
                    ])
                    for ev in events:
                        ts = _dt.utcfromtimestamp(ev['changed_at']).strftime('%Y-%m-%d %H:%M:%S UTC') if ev.get('changed_at') else ''
                        ev_writer.writerow([
                            ev['id'], ev['shadow_id'],
                            ev.get('host', ''), ev.get('port', ''), ev.get('service', ''),
                            ev.get('from_status', ''), ev.get('to_status', ''),
                            ev.get('changed_by', ''), ev.get('ip_address', ''), ts,
                        ])
                    zf.writestr('ai_asset_approval_log.csv', ev_buf.getvalue())
                except Exception as _ie:
                    zf.writestr('ai_asset_inventory_error.txt', f'Inventory export failed: {_ie}')

            zip_bytes = buf.getvalue()
            fname = f'sentinel_evidence_{date_str}.zip'
            self.send_response(200)
            self.send_header('Content-Type', 'application/zip')
            self.send_header('Content-Disposition', f'attachment; filename="{fname}"')
            self.send_header('Content-Length', str(len(zip_bytes)))
            self.end_headers()
            self.wfile.write(zip_bytes)
        except Exception as e:
            log.error('evidence export error: %s', e, exc_info=True)
            self._json({'error': str(e)}, 500)

    def _api_risk_register(self):
        """GET /api/fleet/risk-register — deduplicated open findings with trend info."""
        try:
            store = self._store()
            entries = store.get_risk_register()
            self._json({'entries': entries, 'count': len(entries)})
        except Exception as e:
            log.error('risk register error: %s', e, exc_info=True)
            self._json({'error': str(e)}, 500)

    def _api_risk_register_csv(self):
        """GET /api/fleet/risk-register/csv — download risk register as CSV."""
        import csv
        import io
        from datetime import datetime as _dt
        try:
            store = self._store()
            entries = store.get_risk_register()
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(['Check ID', 'Severity', 'Title', 'Category', 'Status',
                             'Affected Devices', 'Trend', 'Days Open', 'Device Names',
                             'Override', 'Assigned To', 'Note'])
            for e in entries:
                writer.writerow([
                    e['check_id'], e['severity'], e['title'], e['category'], e['status'],
                    e['affected_count'], e['trend'], e['days_open'],
                    '; '.join(e['affected_devices']),
                    e.get('override_action', ''), e.get('override_assignee', ''),
                    e.get('override_note', ''),
                ])
            data = buf.getvalue().encode('utf-8')
            fname = f'sentinel_risk_register_{_dt.utcnow().strftime("%Y%m%d")}.csv'
            self.send_response(200)
            self.send_header('Content-Type', 'text/csv; charset=utf-8')
            self.send_header('Content-Disposition', f'attachment; filename="{fname}"')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:
            log.error('risk register CSV error: %s', e, exc_info=True)
            self._json({'error': str(e)}, 500)

    def _api_rr_overrides_list(self):
        """GET /api/fleet/risk-register/overrides"""
        try:
            self._json({'overrides': self._store().get_risk_overrides()})
        except Exception as e:
            self._json({'error': str(e)}, 500)

    def _api_rr_override_set(self):
        """POST /api/fleet/risk-register/override — accept or assign a finding."""
        try:
            cl = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(cl)) if cl else {}
            check_id = (body.get('check_id') or '').strip()
            action   = (body.get('action') or '').strip()
            if not check_id or action not in ('accepted', 'assigned', 'false_positive'):
                self._json({'error': 'check_id and action (accepted|assigned|false_positive) required'}, 400)
                return
            assignee   = (body.get('assignee') or '').strip()
            note       = (body.get('note') or '').strip()
            expires_at = body.get('expires_at')
            if isinstance(expires_at, str) and expires_at:
                import datetime as _dt
                try:
                    expires_at = int(_dt.datetime.fromisoformat(expires_at).timestamp())
                except ValueError:
                    expires_at = None
            user = self._session_user()
            created_by = user['email'] if user else 'Unknown'
            self._store().upsert_risk_override(check_id, action, assignee, note, expires_at, created_by)
            self._json({'ok': True})
        except Exception as e:
            log.error('rr override set error: %s', e, exc_info=True)
            self._json({'error': str(e)}, 500)

    def _api_rr_override_delete(self, check_id: str):
        """POST /api/fleet/risk-register/override/<check_id>/delete — clear an override."""
        try:
            check_id = check_id.strip('/')
            if not check_id:
                self._json({'error': 'check_id required'}, 400)
                return
            ok = self._store().delete_risk_override(check_id)
            self._json({'ok': ok})
        except Exception as e:
            log.error('rr override delete error: %s', e, exc_info=True)
            self._json({'error': str(e)}, 500)

    def _api_inventory(self):
        """GET /api/fleet/inventory — all shadow AI devices as formal asset inventory."""
        try:
            store = self._store()
            items = store.list_inventory()
            counts = {'approved': 0, 'under_review': 0, 'unapproved': 0}
            for item in items:
                s = item.get('approval_status', 'unapproved')
                counts[s] = counts.get(s, 0) + 1
            user = self._session_user()
            self._json({'items': items, 'counts': counts,
                        'current_user': user.get('email', '') if user else ''})
        except Exception as e:
            log.error('inventory error: %s', e, exc_info=True)
            self._json({'error': str(e)}, 500)

    def _api_inventory_set_status(self, shadow_id_str: str, status: str):
        """POST /api/fleet/inventory/{approve|review|unapprove}/<id>"""
        try:
            shadow_id = int(shadow_id_str.strip('/'))
            user = self._session_user()
            changed_by = user['email'] if user else 'Unknown'
            ip_address = (
                self.headers.get('X-Forwarded-For', '').split(',')[0].strip()
                or self.client_address[0]
            )
            store = self._store()
            ok = store.set_shadow_approval(shadow_id, status,
                                           changed_by=changed_by,
                                           ip_address=ip_address)
            self._json({'ok': ok, 'status': status})
        except (ValueError, TypeError):
            self._json({'error': 'invalid id'}, 400)
        except Exception as e:
            log.error('inventory set status error: %s', e, exc_info=True)
            self._json({'error': str(e)}, 500)

    def _api_inventory_false_positive(self, shadow_id_str: str):
        """POST /api/fleet/inventory/false-positive/<id> — mark/unmark as false positive."""
        try:
            shadow_id = int(shadow_id_str.strip('/'))
            cl = _content_length(self.headers)
            body = json.loads(self.rfile.read(cl)) if cl else {}
            is_fp = bool(body.get('false_positive', True))
            notes = str(body.get('notes', '')).strip()
            user = self._session_user()
            changed_by = user['email'] if user else 'Unknown'
            ip_address = (
                self.headers.get('X-Forwarded-For', '').split(',')[0].strip()
                or self.client_address[0]
            )
            ok = self._store().set_false_positive(
                shadow_id, is_fp, notes=notes,
                changed_by=changed_by, ip_address=ip_address,
            )
            self._json({'ok': ok})
        except (ValueError, TypeError):
            self._json({'error': 'invalid id'}, 400)
        except Exception as e:
            log.error('false positive error: %s', e, exc_info=True)
            self._json({'error': str(e)}, 500)

    def _api_inventory_history(self, shadow_id_str: str):
        """GET /api/fleet/inventory/history/<id> — approval event log for one asset."""
        try:
            shadow_id = int(shadow_id_str.strip('/'))
            store = self._store()
            history = store.get_approval_history(shadow_id)
            self._json({'history': history})
        except (ValueError, TypeError):
            self._json({'error': 'invalid id'}, 400)
        except Exception as e:
            log.error('inventory history error: %s', e, exc_info=True)
            self._json({'error': str(e)}, 500)

    def _api_shadow_csv(self):
        """GET /api/fleet/shadow/csv — download Shadow AI inventory as CSV."""
        import csv as _csv
        import io
        from datetime import datetime as _dt
        try:
            store = self._store()
            items = store.list_inventory()
            buf = io.StringIO()
            writer = _csv.writer(buf)
            writer.writerow(['Service', 'Source', 'Host / IP', 'Port', 'Detail',
                             'Reported By', 'First Seen', 'Last Seen', 'Status'])
            def _fmt(ts):
                return _dt.utcfromtimestamp(ts).strftime('%Y-%m-%d %H:%M UTC') if ts else ''
            for item in items:
                writer.writerow([
                    item.get('service', ''),
                    item.get('source', ''),
                    item.get('host', ''),
                    item.get('port', '') or '',
                    item.get('detail', ''),
                    item.get('reporter_hostname', ''),
                    _fmt(item.get('first_seen')),
                    _fmt(item.get('last_seen')),
                    item.get('approval_status', 'unapproved'),
                ])
            data = buf.getvalue().encode('utf-8')
            fname = f'shadow_ai_{_dt.utcnow().strftime("%Y%m%d")}.csv'
            self.send_response(200)
            self.send_header('Content-Type', 'text/csv; charset=utf-8')
            self.send_header('Content-Disposition', f'attachment; filename="{fname}"')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:
            log.error('shadow CSV error: %s', e, exc_info=True)
            self._json({'error': str(e)}, 500)

    # ── AI spend tracking API ─────────────────────────────────────────────────

    def _api_spend_summary(self):
        """GET /api/spend/summary?days=30 — total cost and token usage.

        Scoped: a client_viewer sees only its own client org; an MSP admin
        sees all client orgs (or one if ?client_org=<id> is passed)."""
        try:
            days = self._spend_days_param()
            org = self._scoped_client_org()
            summary = self._store().get_ai_spend_summary(days=days, client_org_id=org)
            self._json(summary)
        except _TenantScopeError:
            self._json({'error': 'invalid client-org scope'}, 403)
        except Exception as e:
            log.error('spend summary error: %s', e, exc_info=True)
            self._json({'error': 'spend summary unavailable'}, 500)

    def _api_spend_by_model(self):
        """GET /api/spend/by-model?days=30 — spend broken down by model."""
        try:
            days = self._spend_days_param()
            org = self._scoped_client_org()
            summary = self._store().get_ai_spend_summary(days=days, client_org_id=org)
            self._json({'days': days, 'items': summary.get('by_model', [])})
        except _TenantScopeError:
            self._json({'error': 'invalid client-org scope'}, 403)
        except Exception as e:
            log.error('spend by-model error: %s', e, exc_info=True)
            self._json({'error': 'spend by-model unavailable'}, 500)

    def _api_spend_by_provider(self):
        """GET /api/spend/by-provider?days=30 — spend broken down by provider."""
        try:
            days = self._spend_days_param()
            org = self._scoped_client_org()
            summary = self._store().get_ai_spend_summary(days=days, client_org_id=org)
            self._json({'days': days, 'items': summary.get('by_provider', [])})
        except _TenantScopeError:
            self._json({'error': 'invalid client-org scope'}, 403)
        except Exception as e:
            log.error('spend by-provider error: %s', e, exc_info=True)
            self._json({'error': 'spend by-provider unavailable'}, 500)

    def _api_spend_daily(self):
        """GET /api/spend/daily?days=30 — daily spend trend."""
        try:
            days = self._spend_days_param()
            org = self._scoped_client_org()
            summary = self._store().get_ai_spend_summary(days=days, client_org_id=org)
            self._json({'days': days, 'items': summary.get('daily', [])})
        except _TenantScopeError:
            self._json({'error': 'invalid client-org scope'}, 403)
        except Exception as e:
            log.error('spend daily error: %s', e, exc_info=True)
            self._json({'error': 'spend daily unavailable'}, 500)

    def _api_spend_by_client_org(self):
        """GET /api/spend/by-client-org?days=30 — spend per MSP client org.

        MSP admin only: aggregates every client org under this customer. A
        client_viewer is denied by the role check in _do_GET_inner."""
        try:
            days = self._spend_days_param()
            items = self._store().get_ai_spend_by_client_org(days=days)
            self._json({'days': days, 'items': items})
        except Exception as e:
            log.error('spend by-client-org error: %s', e, exc_info=True)
            self._json({'error': 'spend by-client-org unavailable'}, 500)

    def _api_spend_by_api_key(self):
        """GET /api/spend/by-api-key?days=30 — spend per configured API key.

        Returns redacted key metadata (label + last4) only; never the full key.
        MSP admin only."""
        try:
            from connectors import key_store
            days = self._spend_days_param()
            config = _load_spend_config(self._spend_customer_id())
            configured = {
                key_store.public_view(rk)['key_id']: key_store.public_view(rk)
                for rk in key_store.config_to_redacted_keys(config)
            }
            spend_rows = self._store().get_ai_spend_by_key(days=days)
            by_key = {row['key_id']: row for row in spend_rows}
            items = []
            for key_id, view in configured.items():
                row = by_key.pop(key_id, {})
                items.append({**view, 'spend_usd': row.get('spend_usd', 0.0),
                              'total_tokens': row.get('total_tokens', 0)})
            self._json({'days': days, 'items': items})
        except Exception as e:
            log.error('spend by-api-key error: %s', e, exc_info=True)
            self._json({'error': 'spend by-api-key unavailable'}, 500)

    def _spend_days_param(self) -> int:
        """Parse and clamp the `days` query parameter for spend endpoints."""
        from urllib.parse import parse_qs, urlparse as _up
        try:
            query = parse_qs(_up(self.path).query)
            raw = query.get('days', ['30'])[0]
            days = int(raw)
        except (ValueError, TypeError, IndexError):
            days = 30
        allowed = (7, 30, 90, 365)
        if days not in allowed:
            # Pick the nearest allowed bucket, capped at 365.
            days = min(allowed, key=lambda x: abs(x - days))
            if days > 365:
                days = 365
        return days

    def _api_spend_fetch(self):
        """POST /api/spend/fetch — trigger a fetch from configured providers.

        Only admins may trigger fetches. A simple per-day guard prevents
        accidental API hammering; repeated calls on the same calendar day reuse
        the stored data unless force=1.
        """
        try:
            body = self._read_json_body(default={})
            days = body.get('days', 7)
            try:
                days = int(days)
            except (ValueError, TypeError):
                days = 7
            if days < 1 or days > 365:
                days = 7
            force = bool(body.get('force'))

            customer_id = self._spend_customer_id()
            last_fetch_path = _spend_fetch_state_path(customer_id)
            today = str(date.today())
            if not force and last_fetch_path.exists() and last_fetch_path.read_text().strip() == today:
                self._json({'fetched': 0, 'skipped': True, 'reason': 'already fetched today; use force=1 to override'})
                return

            config = _load_spend_config(customer_id)
            records = _fetch_all_spend(config, days)
            count = self._store().upsert_ai_spend(records)

            last_fetch_path.parent.mkdir(parents=True, exist_ok=True)
            last_fetch_path.write_text(today, encoding='utf-8')
            self._json({'fetched': count, 'providers': list(config.get('providers', {}).keys())})
        except json.JSONDecodeError:
            self._json({'error': 'invalid JSON'}, 400)
        except Exception as e:
            log.error('spend fetch error: %s', e, exc_info=True)
            self._json({'error': 'spend fetch failed'}, 500)

    def _api_spend_keys_list(self):
        """GET /api/spend/keys — list configured API keys (redacted only).

        Returns label, provider, client_org_id, key_last4, and a key_hash
        prefix. Never returns the full key, the env var name, or the secret
        file path."""
        try:
            from connectors import key_store
            config = _load_spend_config(self._spend_customer_id())
            redacted = key_store.config_to_redacted_keys(config)
            items = [key_store.public_view(rk) for rk in redacted]
            self._json({'items': items})
        except Exception as e:
            log.error('spend keys list error: %s', e, exc_info=True)
            self._json({'error': 'spend keys list unavailable'}, 500)

    def _api_spend_keys_add(self):
        """POST /api/spend/keys — add or rotate a provider API key for a client org.

        Accepts {provider, client_org_id, label, api_key, persist?}. The full
        api_key is used only to derive a hash + last4 and (optionally) write a
        0600 secret file. The full key is never written to spend_config.json and
        never returned by any API."""
        try:
            from connectors import key_store
            body = self._read_json_body(default={})
            provider = str(body.get('provider', '')).strip().lower()
            client_org_id = str(body.get('client_org_id', '')).strip()
            label = str(body.get('label', '')).strip()[:80]
            full_key = str(body.get('api_key', ''))
            persist = bool(body.get('persist', True))

            if not provider or provider not in ('openai', 'anthropic', 'gemini', 'ollama'):
                self._json({'error': 'invalid provider'}, 400)
                return
            if not full_key or len(full_key) < 8:
                self._json({'error': 'api_key too short'}, 400)
                return
            if not label:
                label = f"{provider} ({client_org_id or 'default'})"

            # Verify the client_org_id belongs to this MSP customer (if orgs exist).
            if client_org_id:
                try:
                    org = _get_registry().get_client_org(client_org_id)
                    user = self._session_user()
                    if not org or not org.get('active'):
                        self._json({'error': 'unknown or inactive client org'}, 400)
                        return
                    if user and org.get('customer_id') != user.get('customer_id'):
                        self._json({'error': 'client org does not belong to this customer'}, 403)
                        return
                except Exception:
                    self._json({'error': 'client org validation failed'}, 400)
                    return

            api_key_file = ""
            api_key_env = ""
            if persist:
                # Write the full key to a 0600 secret file named by its hash.
                secret_path = key_store.write_secret_file(
                    _spend_secret_dir(self._spend_customer_id()), full_key)
                api_key_file = str(secret_path)
            else:
                # Expect the operator to provide the key via env var; store a
                # placeholder env name derived from the label.
                api_key_env = f"SPEND_{provider.upper()}_{client_org_id.upper() or 'DEFAULT'}_KEY"

            # Build the redacted record. full_key is discarded after this.
            redacted = key_store.redact(
                full_key, provider, client_org_id, label,
                api_key_env=api_key_env, api_key_file=api_key_file,
            )
            del full_key

            customer_id = self._spend_customer_id()
            config = _load_spend_config(customer_id)
            key_store.upsert_key(config, redacted)
            key_store.save_config(_spend_config_path(customer_id), config)

            self._json({'ok': True, 'key': key_store.public_view(redacted)})
        except json.JSONDecodeError:
            self._json({'error': 'invalid JSON'}, 400)
        except Exception as e:
            log.error('spend keys add error: %s', e, exc_info=True)
            self._json({'error': 'spend key add failed'}, 500)

    def _api_spend_keys_remove(self):
        """POST /api/spend/keys/remove — remove a configured API key.

        Removes the redacted config entry and (if present) the secret file.
        Never returns the full key."""
        try:
            from connectors import key_store
            body = self._read_json_body(default={})
            provider = str(body.get('provider', '')).strip().lower()
            key_id = str(body.get('key_id', '')).strip()
            if not provider or len(key_id) < 8:
                self._json({'error': 'provider and key_id required'}, 400)
                return

            customer_id = self._spend_customer_id()
            config = _load_spend_config(customer_id)
            redacted = key_store.config_to_redacted_keys(config)
            targets = [r for r in redacted
                       if r.provider == provider and r.key_hash.startswith(key_id)]
            if len(targets) != 1:
                self._json({'error': 'key not found'}, 404)
                return
            target = targets[0]
            if target and target.api_key_file:
                try:
                    Path(target.api_key_file).unlink()
                except OSError:
                    pass
            key_store.remove_key(config, provider, key_id)
            key_store.save_config(_spend_config_path(customer_id), config)
            self._json({'ok': True})
        except json.JSONDecodeError:
            self._json({'error': 'invalid JSON'}, 400)
        except Exception as e:
            log.error('spend keys remove error: %s', e, exc_info=True)
            self._json({'error': 'spend key remove failed'}, 500)

    def _api_spend_set_budget(self):
        """POST /api/spend/budget — set budget alert thresholds."""
        try:
            body = self._read_json_body(default={})
            daily_usd = body.get('daily_usd')
            per_model_usd = body.get('per_model_usd')
            try:
                daily_usd = None if daily_usd is None else max(0.0, float(daily_usd))
                per_model_usd = None if per_model_usd is None else max(0.0, float(per_model_usd))
            except (ValueError, TypeError):
                self._json({'error': 'budget values must be numeric'}, 400)
                return
            safe = {}
            if daily_usd is not None:
                safe['daily_usd'] = round(daily_usd, 2)
            if per_model_usd is not None:
                safe['per_model_usd'] = round(per_model_usd, 2)
            path = _spend_budget_path(self._spend_customer_id())
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(safe, indent=2), encoding='utf-8')
            self._json({'ok': True, 'budget': safe})
        except json.JSONDecodeError:
            self._json({'error': 'invalid JSON'}, 400)
        except Exception as e:
            log.error('spend budget error: %s', e, exc_info=True)
            self._json({'error': 'spend budget update failed'}, 500)

    def _read_json_body(self, default=None) -> dict:
        """Read and parse a JSON POST body; return default on empty/missing."""
        cl = _content_length(self.headers)
        if not cl:
            return default if default is not None else {}
        raw = self.rfile.read(cl)
        if not raw:
            return default if default is not None else {}
        return json.loads(raw.decode('utf-8'))

    def _api_approve_service_globally(self):
        """POST /api/fleet/inventory/approve-service — globally approve or unapprove a service name."""
        try:
            length = _content_length(self.headers)
            body = json.loads(self.rfile.read(length)) if length else {}
            service = str(body.get('service', '')).strip()
            action  = str(body.get('action', 'approve')).strip()
            if not service:
                self._json({'error': 'missing service'}, 400)
                return
            user = self._session_user()
            by = user['email'] if user else 'Dashboard user'
            store = self._store()
            if action == 'unapprove':
                store.unapprove_service_globally(service)
            else:
                store.approve_service_globally(service, by)
            self._json({'ok': True, 'service': service, 'action': action})
        except Exception as e:
            log.error('approve-service error: %s', e, exc_info=True)
            self._json({'error': str(e)}, 500)

    def _api_verify_signature(self):
        """GET /api/verify?sig=<hex>&content=<json> — verify a Sentinel report signature."""
        from urllib.parse import parse_qs, urlparse as _up
        from output.signing import verify_content, key_fingerprint
        qs = parse_qs(_up(self.path).query)
        sig = (qs.get('sig', [''])[0]).strip()
        content = (qs.get('content', [''])[0]).strip()
        if not sig or not content:
            self._json({'error': 'Provide sig= and content= parameters', 'key_fingerprint': key_fingerprint()}, 400)
            return
        valid = verify_content(content, sig)
        self._json({'valid': valid, 'key_fingerprint': key_fingerprint()})

    def _api_schedules_list(self):
        """GET /api/schedules"""
        try:
            store = self._store()
            self._json({'schedules': store.list_schedules()})
        except Exception as e:
            self._json({'error': str(e)}, 500)

    def _api_schedules_create(self):
        """POST /api/schedules — create a new scan schedule."""
        try:
            body = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))))
            cadence = body.get('cadence', 'daily')
            hour = int(body.get('hour', 2)) % 24
            profile = body.get('profile', 'default')
            label = str(body.get('label', ''))[:80]
            device_id = body.get('device_id', 'all')
            weekday = int(body['weekday']) if 'weekday' in body else None
            monthday = int(body['monthday']) if 'monthday' in body else None
            interval_hours = int(body.get('interval_hours', 0))
            store = self._store()
            new_id = store.add_schedule(device_id, cadence, hour, profile, label, weekday, monthday, interval_hours)
            self._json({'ok': True, 'id': new_id})
        except Exception as e:
            log.error('schedule create error: %s', e)
            self._json({'error': str(e)}, 400)

    def _api_schedule_toggle(self, schedule_id_str: str):
        """POST /api/schedules/<id>/toggle"""
        try:
            store = self._store()
            ok = store.toggle_schedule(int(schedule_id_str.strip('/')))
            self._json({'ok': ok})
        except Exception as e:
            self._json({'error': str(e)}, 400)

    def _api_schedule_delete(self, schedule_id_str: str):
        """POST /api/schedules/<id>/delete"""
        try:
            store = self._store()
            ok = store.delete_schedule(int(schedule_id_str.strip('/')))
            self._json({'ok': ok})
        except Exception as e:
            self._json({'error': str(e)}, 400)

    def _api_discover(self):
        """GET /api/discover — return agent-reported shadow devices from the database.
        Server-side subnet scanning is disabled; discovery runs on registered agents
        via /api/fleet/discover/all and results are stored in shadow_devices.
        """
        try:
            shadow = self._store().list_shadow_devices()
            src_map = {
                'network':   'network_probe',
                'process':   'process_scan',
                'cloud_api': 'env_var',
            }
            services = []
            for s in shadow:
                if s.get('dismissed'):
                    continue
                src  = src_map.get(s.get('source', 'network'), 'network_probe')
                host = s.get('host', '')
                port = int(s.get('port') or 0)
                try:
                    models = json.loads(s.get('models_json') or '[]')
                except Exception:
                    models = []
                svc = {
                    'host':     host,
                    'port':     port,
                    'service':  s.get('service', ''),
                    'url':      f'http://{host}:{port}' if port else '',
                    'status':   200,
                    'reachable': True,
                    'source':   src,
                    'models':   models,
                    'reporter': s.get('reporter_hostname', ''),
                }
                if src == 'process_scan':
                    svc['process_sig'] = s.get('detail', '')
                elif src == 'env_var':
                    svc['env_var'] = s.get('detail', '')
                services.append(svc)
            self._json({'services': services, 'count': len(services)})
        except Exception as e:
            log.error('discovery error: %s', e, exc_info=True)
            self._json({'error': str(e), 'services': []}, 500)

    def _api_devices(self):
        try:
            devices = self._store().list_devices(client_org_id=self._scoped_client_org())
            for d in devices:
                if d.get('last_seen'):
                    d['last_seen_iso'] = datetime.fromtimestamp(
                        d['last_seen'], tz=timezone.utc
                    ).strftime('%Y-%m-%dT%H:%M:%SZ')
            self._json({'devices': devices, 'count': len(devices)})
        except Exception as e:
            self._json({'error': str(e)}, 500)

    def _api_device_report(self, device_id: str):
        if not device_id:
            self._not_found()
            return
        try:
            report = self._store().get_latest_report(device_id)
        except Exception as e:
            self._json({'error': str(e)}, 500)
            return
        if report is None:
            self._json({'error': 'device not found'}, 404)
            return
        self._json(report)

    def _api_device_timeseries(self, device_id: str):
        """Return time-series of fail/warn/pass counts for a device.
        JSON format: { points: [ {t: <epoch>, fail: <int>, warn: <int>, pass: <int>} ] }
        """
        if not device_id:
            self._not_found()
            return
        try:
            points = self._store().get_device_timeseries(device_id)
            self._json({'points': points})
        except Exception as e:
            self._json({'error': str(e)}, 500)

    def _api_system_update(self):
        """POST /api/system/update — git pull then restart if new commits landed."""
        import shutil

        env = os.environ.copy()
        env['GIT_TERMINAL_PROMPT'] = '0'
        env['GCM_INTERACTIVE'] = 'never'

        try:
            if sys.platform == 'win32':
                output, returncode = self._git_pull_windows(env)
            else:
                extra = '/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin'
                env['PATH'] = extra + ':' + env.get('PATH', '')
                git_cmd = shutil.which('git', path=env['PATH']) or 'git'
                result = subprocess.run(
                    [git_cmd, '-C', str(ROOT), 'pull', '--ff-only'],
                    capture_output=True, text=True, timeout=30, env=env,
                )
                output = (result.stdout + result.stderr).strip()
                returncode = result.returncode
            if not output:
                output = f'git exited with code {returncode} and no output'
            already_current = 'already up to date' in output.lower()
            if returncode == 0 and not already_current:
                self._json({'status': 'restarting', 'output': output + '\n\nRestarting server…'})
                def _restart():
                    time.sleep(0.6)
                    if sys.platform == 'win32':
                        subprocess.Popen([sys.executable] + sys.argv,
                                         creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
                                         stdin=subprocess.DEVNULL,
                                         stdout=subprocess.DEVNULL,
                                         stderr=subprocess.DEVNULL)
                        os._exit(0)
                    else:
                        os.execv(sys.executable, [sys.executable] + sys.argv)
                threading.Thread(target=_restart, daemon=True).start()
            else:
                self._json({'status': 'ok' if returncode == 0 else 'error', 'output': output})
        except subprocess.TimeoutExpired:
            self._json({'status': 'error', 'output': 'git pull timed out — check network'}, 500)
        except Exception as e:
            self._json({'status': 'error', 'output': str(e)}, 500)

    def _git_pull_windows(self, env: dict):
        """Find git.exe via registry/common paths and run pull with proper Win32 flags."""
        import shutil

        # Registry is the most reliable way to find Git for Windows
        git_exe = None
        try:
            import winreg
            for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
                for subkey in (r'SOFTWARE\GitForWindows', r'SOFTWARE\WOW6432Node\GitForWindows'):
                    try:
                        key = winreg.OpenKey(hive, subkey)
                        install_path = winreg.QueryValueEx(key, 'InstallPath')[0]
                        candidate = os.path.join(install_path, 'bin', 'git.exe')
                        if os.path.isfile(candidate):
                            git_exe = candidate
                            break
                    except OSError:
                        continue
                if git_exe:
                    break
        except Exception:
            pass

        if git_exe is None:
            for candidate in [
                r'C:\Program Files\Git\bin\git.exe',
                r'C:\Program Files\Git\cmd\git.exe',
                r'C:\Program Files (x86)\Git\bin\git.exe',
            ]:
                if os.path.isfile(candidate):
                    git_exe = candidate
                    break

        if git_exe is None:
            git_exe = shutil.which('git') or 'git'

        # STARTUPINFO with SW_HIDE prevents the child needing a console window,
        # which causes DLL init failures when the server has no attached console.
        si = subprocess.STARTUPINFO()
        si.dwFlags = subprocess.STARTF_USESHOWWINDOW
        si.wShowWindow = 0  # SW_HIDE

        try:
            result = subprocess.run(
                [git_exe, '-C', str(ROOT), 'pull', '--ff-only'],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
                env=env,
                startupinfo=si,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            output = (result.stdout + result.stderr).strip()
            return output, result.returncode
        except Exception as e:
            return (f'git pull failed: {e}\n\n'
                    f'Git found at: {git_exe}\n'
                    f'Open PowerShell in the project folder and run: git pull'), 1

    def _api_system_restart_agent(self):
        """POST /api/system/restart-agent — restart the agent service."""
        def _do_restart():
            time.sleep(0.3)
            try:
                if sys.platform == 'win32':
                    subprocess.run(['schtasks', '/end', '/tn', 'SentinelAgent'], capture_output=True)
                    time.sleep(2)
                    subprocess.run(['schtasks', '/run', '/tn', 'SentinelAgent'], capture_output=True)
                elif sys.platform == 'darwin':
                    subprocess.run(['launchctl', 'stop', 'com.mark.sentinel.agent'], capture_output=True)
                    subprocess.run(['launchctl', 'start', 'com.mark.sentinel.agent'], capture_output=True)
                else:
                    subprocess.run(['systemctl', 'restart', 'sentinel-agent'], capture_output=True)
            except Exception as e:
                log.error('restart-agent error: %s', e)
        threading.Thread(target=_do_restart, daemon=True).start()
        self._json({'status': 'restarting'})

    def _api_system_restart_server(self):
        """POST /api/system/restart-server — restart this server process."""
        def _do_restart():
            time.sleep(0.5)
            if sys.platform == 'win32':
                # os.execv is unreliable on Windows when called from a thread;
                # spawn a detached child process then hard-exit the current one.
                subprocess.Popen(
                    [sys.executable] + sys.argv,
                    creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                os._exit(0)
            else:
                os.execv(sys.executable, [sys.executable] + sys.argv)
        threading.Thread(target=_do_restart, daemon=True).start()
        self._json({'status': 'restarting'})

    def _api_get_config(self):
        config_path = ROOT / 'agent_config.json'
        if not config_path.exists():
            self._json({})
            return
        try:
            self._json(json.loads(config_path.read_text(encoding='utf-8')))
        except Exception as e:
            self._json({'error': str(e)}, 500)

    def _api_get_baseline_profile(self):
        self._json({'profile': _load_baseline_profile()})

    def _api_set_baseline_profile(self):
        length = _content_length(self.headers)
        if not length:
            self._send(400, b'Empty body', 'text/plain')
            return
        try:
            profile = json.loads(self.rfile.read(length)).get('profile', '')
        except (json.JSONDecodeError, AttributeError):
            self._send(400, b'Invalid JSON', 'text/plain')
            return
        if profile not in _BASELINE_PROFILES:
            self._json({'error': 'invalid baseline profile'}, 400)
            return
        try:
            _save_baseline_profile(profile)
            store = self._store()
            devices = [d for d in store.list_devices(client_org_id=self._scoped_client_org())
                       if not _is_container_device(d)]
            pushed = 0
            payload = json.dumps({'profile': profile})
            for device in devices:
                device_id = device.get('device_id', '')
                if device_id:
                    store.enqueue_command(device_id, f'set_config:{payload}')
                    pushed += 1
        except Exception as e:
            log.error('baseline profile save error: %s', e)
            self._json({'error': 'could not save baseline profile'}, 500)
            return
        self._json({'status': 'saved', 'profile': profile, 'pushed_to_agents': pushed})

    def _api_set_config(self):
        length = _content_length(self.headers)
        if not length:
            self._send(400, b'Empty body', 'text/plain')
            return
        try:
            body = json.loads(self.rfile.read(length))
        except json.JSONDecodeError:
            self._send(400, b'Invalid JSON', 'text/plain')
            return
        allowed = {'server', 'token', 'target', 'profile', 'interval', 'extra_subnets'}
        clean = {k: v for k, v in body.items() if k in allowed}
        config_path = ROOT / 'agent_config.json'
        try:
            existing = json.loads(config_path.read_text(encoding='utf-8')) if config_path.exists() else {}
            existing.update(clean)
            config_path.write_text(json.dumps(existing, indent=2), encoding='utf-8')
        except Exception as e:
            self._json({'error': str(e)}, 500)
            return

        # Push config changes to all connected remote agents
        _push_keys = ('profile', 'interval', 'extra_subnets')
        pushed = 0
        if any(k in clean for k in _push_keys):
            try:
                store = self._store()
                cmd_payload = json.dumps({k: clean[k] for k in _push_keys if k in clean})
                for d in store.list_devices():
                    did = d.get('device_id', '')
                    if did:
                        _get_store_for_device(did).enqueue_command(did, f'set_config:{cmd_payload}')
                        pushed += 1
            except Exception:
                pass

        self._json({'status': 'saved', 'pushed_to_agents': pushed})

    def _api_get_live_scan_config(self):
        if not _has_live_scan():
            self._json({'locked': True})
            return
        cfg = _load_live_scan_config()
        safe = {k: v for k, v in cfg.items() if k != 'api_key'}
        if cfg.get('api_key'):
            safe['api_key_set'] = True
        self._json(safe)

    def _api_set_live_scan_config(self):
        if not _has_live_scan():
            self._json({'error': 'Live scan requires a Plus license'}, 403)
            return
        length = _content_length(self.headers)
        if not length:
            self._send(400, b'Empty body', 'text/plain')
            return
        try:
            body = json.loads(self.rfile.read(length))
        except json.JSONDecodeError:
            self._send(400, b'Invalid JSON', 'text/plain')
            return
        _save_live_scan_config(body)
        self._json({'status': 'saved'})

    def _api_get_alert_config(self):
        from alerts import load_alert_config_for_ui
        self._json(load_alert_config_for_ui(ROOT / 'data' / 'alerts_config.json'))

    def _api_set_alert_config(self):
        length = _content_length(self.headers)
        if not length:
            self._send(400, b'Empty body', 'text/plain')
            return
        try:
            body = json.loads(self.rfile.read(length))
        except json.JSONDecodeError:
            self._send(400, b'Invalid JSON', 'text/plain')
            return
        try:
            from alerts import save_alert_config
            path = ROOT / 'data' / 'alerts_config.json'
            save_alert_config(path, body, path)
            self._json({'status': 'saved'})
        except Exception as e:
            self._json({'error': str(e)}, 500)

    def _api_test_alert(self):
        length = _content_length(self.headers)
        if not length:
            self._send(400, b'Empty body', 'text/plain')
            return
        try:
            body = json.loads(self.rfile.read(length))
        except json.JSONDecodeError:
            self._send(400, b'Invalid JSON', 'text/plain')
            return
        channel  = body.get('channel', '')
        live_url = body.get('url', '').strip()
        try:
            from alerts import load_alert_config, send_test_alert
            cfg = load_alert_config(ROOT / 'data' / 'alerts_config.json') or {}
            if live_url:
                _url_key = {'slack': 'slack_webhook', 'gchat': 'gchat_webhook',
                            'teams': 'teams_webhook', 'webhook': 'webhook_url'}.get(channel)
                if _url_key:
                    cfg[_url_key] = live_url
            ok, msg = send_test_alert(cfg, channel)
            self._json({'ok': ok, 'message': msg})
        except Exception as e:
            self._json({'ok': False, 'message': str(e)}, 500)

    def _api_test_psa(self):
        try:
            from alerts import load_alert_config, send_test_psa
            cfg = load_alert_config(ROOT / 'data' / 'alerts_config.json') or {}
            ok, msg = send_test_psa(cfg)
            self._json({'ok': ok, 'message': msg})
        except Exception as e:
            self._json({'ok': False, 'message': str(e)}, 500)

    def _psa_org_scope(self) -> str | None:
        """?client_org=<id> selects a per-client PSA override instead of
        the customer-wide default in data/alerts_config.json."""
        from urllib.parse import parse_qs, urlparse as _up
        qs = parse_qs(_up(self.path).query)
        return (qs.get('client_org', [''])[0]).strip() or None

    def _load_psa_cfg(self, org_id: str | None) -> dict:
        if org_id:
            override = _get_registry().get_client_org_psa_override(org_id)
            # No override saved yet for this client -> blank form, not the
            # customer default. Showing the default here would make it look
            # like the client already has its own config when it's actually
            # still inheriting — blank is the honest state to display.
            return {'psa': override or {}}
        from alerts import load_alert_config
        return load_alert_config(ROOT / 'data' / 'alerts_config.json') or {}

    def _save_psa_cfg(self, cfg: dict, org_id: str | None) -> None:
        if org_id:
            me = self._session_user()
            _get_registry().set_client_org_psa_override(org_id, me['customer_id'], cfg.get('psa', {}))
        else:
            path = ROOT / 'data' / 'alerts_config.json'
            path.write_text(json.dumps(cfg, indent=2), encoding='utf-8')

    def _api_get_psa_config(self):
        try:
            org_id = self._psa_org_scope()
            cfg = self._load_psa_cfg(org_id)
            psa  = cfg.get('psa', {})
            _M   = '__set__'
            cw   = psa.get('connectwise', {})
            at   = psa.get('autotask', {})
            hp   = psa.get('halopsa', {})
            self._json({
                'connectwise': {
                    'enabled':       psa.get('provider') == 'connectwise',
                    'site':          cw.get('site', ''),
                    'company_id':    cw.get('company_id', ''),
                    'public_key':    cw.get('public_key', ''),
                    'private_key':   _M if cw.get('private_key') else '',
                    'client_id':     cw.get('client_id', ''),
                    'service_board': cw.get('service_board', ''),
                    'company_name':  cw.get('company_name', ''),
                },
                'autotask': {
                    'enabled':     psa.get('provider') == 'autotask',
                    'zone':        at.get('zone', 'webservices2'),
                    'username':    at.get('username', ''),
                    'api_key':     _M if at.get('api_key') else '',
                    'account_id':  str(at.get('account_id', '')),
                    'queue_id':    str(at.get('queue_id', '')),
                    'priority_id': at.get('priority_id', 1),
                },
                'halopsa': {
                    'enabled':        psa.get('provider') == 'halopsa',
                    'tenant':         hp.get('tenant', ''),
                    'client_id':      hp.get('client_id', ''),
                    'client_secret':  _M if hp.get('client_secret') else '',
                    'ticket_type_id': hp.get('ticket_type_id', 1),
                    'priority_id':    hp.get('priority_id', 1),
                },
                'jira': {
                    'enabled':      psa.get('provider') == 'jira',
                    'site':         psa.get('jira', {}).get('site', ''),
                    'email':        psa.get('jira', {}).get('email', ''),
                    'api_token':    _M if psa.get('jira', {}).get('api_token') else '',
                    'project_key':  psa.get('jira', {}).get('project_key', ''),
                    'issue_type':   psa.get('jira', {}).get('issue_type', 'Bug'),
                },
            })
        except Exception as e:
            self._json({'error': str(e)}, 500)

    def _api_set_psa_config(self):
        length = _content_length(self.headers)
        if not length:
            self._send(400, b'Empty body', 'text/plain')
            return
        try:
            body = json.loads(self.rfile.read(length))
        except json.JSONDecodeError:
            self._send(400, b'Invalid JSON', 'text/plain')
            return
        try:
            org_id = self._psa_org_scope()
            if org_id:
                me = self._session_user()
                org = _get_registry().get_client_org(org_id)
                if not org or org.get('customer_id') != me['customer_id']:
                    self._json({'ok': False, 'error': 'client org not found'}, 404)
                    return
            cfg = self._load_psa_cfg(org_id)
            _M  = '__set__'

            psa_id = body.get('id', '')
            fields = body.get('fields', {})
            enabled = body.get('enabled', False)

            psa = cfg.setdefault('psa', {})
            if enabled:
                psa['provider'] = psa_id
            elif psa.get('provider') == psa_id:
                psa['provider'] = ''

            def _restore(incoming, saved):
                return saved if incoming == _M else (incoming or '')

            existing_sub = psa.get(psa_id, {})
            if psa_id == 'connectwise':
                psa['connectwise'] = {
                    'site':          str(fields.get('site', '')).strip(),
                    'company_id':    str(fields.get('company_id', '')).strip(),
                    'public_key':    str(fields.get('public_key', '')).strip(),
                    'private_key':   _restore(fields.get('private_key', ''), existing_sub.get('private_key', '')),
                    'client_id':     str(fields.get('client_id', '')).strip(),
                    'service_board': str(fields.get('service_board', '')).strip(),
                    'company_name':  str(fields.get('company_name', '')).strip(),
                }
            elif psa_id == 'autotask':
                psa['autotask'] = {
                    'zone':        str(fields.get('zone', 'webservices2')).strip(),
                    'username':    str(fields.get('username', '')).strip(),
                    'api_key':     _restore(fields.get('api_key', ''), existing_sub.get('api_key', '')),
                    'account_id':  fields.get('account_id', ''),
                    'queue_id':    fields.get('queue_id', ''),
                    'priority_id': int(fields.get('priority_id', 1)),
                }
            elif psa_id == 'halopsa':
                psa['halopsa'] = {
                    'tenant':         str(fields.get('tenant', '')).strip(),
                    'client_id':      str(fields.get('client_id', '')).strip(),
                    'client_secret':  _restore(fields.get('client_secret', ''), existing_sub.get('client_secret', '')),
                    'ticket_type_id': int(fields.get('ticket_type_id', 1)),
                    'priority_id':    int(fields.get('priority_id', 1)),
                }
            elif psa_id == 'jira':
                psa['jira'] = {
                    'site':        str(fields.get('site', '')).strip(),
                    'email':       str(fields.get('email', '')).strip(),
                    'api_token':   _restore(fields.get('api_token', ''), existing_sub.get('api_token', '')),
                    'project_key': str(fields.get('project_key', '')).strip().upper(),
                    'issue_type':  str(fields.get('issue_type', 'Bug')).strip() or 'Bug',
                }
            self._save_psa_cfg(cfg, org_id)
            self._json({'ok': True})
        except Exception as e:
            self._json({'ok': False, 'error': str(e)}, 500)

    def _api_test_psa_provider(self, psa_id: str):
        try:
            from alerts import load_alert_config
            cfg = load_alert_config(ROOT / 'data' / 'alerts_config.json') or {}
            psa = cfg.get('psa', {})
            from connectors.psa_connector import test_connection
            psa_cfg = {'provider': psa_id, psa_id: psa.get(psa_id, {})}
            ok, msg = test_connection(psa_cfg)
            self._json({'ok': ok, 'message': msg})
        except Exception as e:
            self._json({'ok': False, 'message': str(e)}, 500)

    def _api_test_psa_ticket(self, psa_id: str):
        try:
            from alerts import load_alert_config
            cfg = load_alert_config(ROOT / 'data' / 'alerts_config.json') or {}
            psa = cfg.get('psa', {})
            from connectors.psa_connector import create_ticket
            psa_cfg = {'provider': psa_id, psa_id: psa.get(psa_id, {})}
            dummy_finding = {
                'check_id':    'AI-DEPLOY-001',
                'severity':    'HIGH',
                'title':       'Test finding from Arckon',
                'description': 'This is a test ticket created from the Arckon dashboard to verify PSA integration.',
                'status':      'FAIL',
            }
            ok, msg = create_ticket(psa_cfg, dummy_finding, 'arckon-test')
            self._json({'ok': ok, 'message': msg})
        except Exception as e:
            self._json({'ok': False, 'message': str(e)}, 500)

    # ── Wiki/docs integrations (Notion today; same array-of-providers
    #    shape as PSA_DEFS/SIEM_DEFS so a second wiki provider is a new
    #    array entry + one provider function, not a new subsystem) ──────────

    def _api_get_wiki_config(self):
        try:
            from alerts import load_alert_config
            cfg = load_alert_config(ROOT / 'data' / 'alerts_config.json') or {}
            notion = cfg.get('notion', {})
            _M = '__set__'
            self._json({
                'notion': {
                    'enabled':        bool(notion.get('enabled')),
                    'token':          _M if notion.get('token') else '',
                    'parent_type':    notion.get('parent_type', 'page'),
                    'page_id':        notion.get('page_id', ''),
                    'database_id':    notion.get('database_id', ''),
                    'title_property': notion.get('title_property', 'Name'),
                },
            })
        except Exception as e:
            self._json({'error': str(e)}, 500)

    def _api_set_wiki_config(self):
        length = _content_length(self.headers)
        if not length:
            self._send(400, b'Empty body', 'text/plain')
            return
        try:
            body = json.loads(self.rfile.read(length))
        except json.JSONDecodeError:
            self._send(400, b'Invalid JSON', 'text/plain')
            return
        try:
            from alerts import load_alert_config
            cfg = load_alert_config(ROOT / 'data' / 'alerts_config.json') or {}
            _M = '__set__'

            wiki_id = body.get('id', '')
            fields  = body.get('fields', {})
            enabled = body.get('enabled', False)

            def _restore(incoming, saved):
                return saved if incoming == _M else (incoming or '')

            if wiki_id == 'notion':
                existing = cfg.get('notion', {})
                # Credentials are preserved even when disabled (same as
                # PSA's pattern — unchecking "Enable" shouldn't force
                # re-entering the token later). alerts.py's _dispatch()
                # checks BOTH `enabled` and `token`, so disabling here is
                # what actually stops it from firing, not clearing the secret.
                cfg['notion'] = {
                    'enabled':        bool(enabled),
                    'token':          _restore(fields.get('token', ''), existing.get('token', '')),
                    'parent_type':    str(fields.get('parent_type', 'page')).strip() or 'page',
                    'page_id':        str(fields.get('page_id', '')).strip(),
                    'database_id':    str(fields.get('database_id', '')).strip(),
                    'title_property': str(fields.get('title_property', 'Name')).strip() or 'Name',
                }
            else:
                self._json({'ok': False, 'error': f'unknown wiki provider: {wiki_id!r}'}, 400)
                return

            path = ROOT / 'data' / 'alerts_config.json'
            path.write_text(json.dumps(cfg, indent=2), encoding='utf-8')
            self._json({'ok': True})
        except Exception as e:
            self._json({'ok': False, 'error': str(e)}, 500)

    def _api_test_wiki_provider(self, wiki_id: str):
        try:
            from alerts import load_alert_config
            cfg = load_alert_config(ROOT / 'data' / 'alerts_config.json') or {}
            if wiki_id == 'notion':
                from connectors.notion_connector import test_connection
                ok, msg = test_connection(cfg.get('notion', {}))
            else:
                ok, msg = False, f'unknown wiki provider: {wiki_id!r}'
            self._json({'ok': ok, 'message': msg})
        except Exception as e:
            self._json({'ok': False, 'message': str(e)}, 500)

    def _api_test_wiki_page(self, wiki_id: str):
        try:
            from alerts import load_alert_config
            cfg = load_alert_config(ROOT / 'data' / 'alerts_config.json') or {}
            dummy_finding = {
                'check_id':    'AI-DEPLOY-001',
                'severity':    'HIGH',
                'title':       'Test finding from Arckon',
                'description': 'This is a test page created from the Arckon dashboard to verify the wiki integration.',
                'status':      'FAIL',
            }
            if wiki_id == 'notion':
                from connectors.notion_connector import create_page
                ok, msg = create_page(cfg.get('notion', {}), dummy_finding, 'arckon-test')
            else:
                ok, msg = False, f'unknown wiki provider: {wiki_id!r}'
            self._json({'ok': ok, 'message': msg})
        except Exception as e:
            self._json({'ok': False, 'message': str(e)}, 500)

    def _api_get_branding(self):
        path = ROOT / 'data' / 'branding.json'
        try:
            data = json.loads(path.read_text()) if path.exists() else {}
        except Exception:
            data = {}
        self._json(data)

    def _api_set_branding(self):
        try:
            body = json.loads(self.rfile.read(int(self.headers.get('Content-Length', 0))))
            allowed = {'msp_name', 'logo_url', 'footer_text'}
            data = {k: str(v).strip() for k, v in body.items() if k in allowed}
            path = ROOT / 'data' / 'branding.json'
            path.write_text(json.dumps(data, indent=2))
            self._json({'ok': True})
        except Exception as e:
            self._json({'ok': False, 'error': str(e)}, 500)

    def _api_eu_ai_act_report(self):
        """GET /api/fleet/eu-ai-act-report?org=...&fmt=html|pdf|csv

        fmt=html (default) is unchanged — an in-browser page with its own
        Print/Save-PDF button. fmt=pdf and fmt=csv are real server-side
        exports, generated and downloaded directly rather than relying on
        the browser's print-to-PDF (which produced a blank single-page PDF
        for at least one real user — Safari specifically)."""
        try:
            import urllib.parse as _up
            qs       = _up.parse_qs(_up.urlparse(self.path).query)
            org_name = qs.get('org', [''])[0]
            fmt      = qs.get('fmt', ['html'])[0].lower()
            if fmt not in ('html', 'pdf', 'csv'):
                fmt = 'html'
            store    = self._store()
            devices  = store.list_devices(client_org_id=self._scoped_client_org())
            enriched = []
            for d in devices:
                rep = store.get_latest_report(d['device_id'])
                enriched.append({**d, '_report': rep})
            branding_path = ROOT / 'data' / 'branding.json'
            branding = json.loads(branding_path.read_text()) if branding_path.exists() else {}

            safe_org = (org_name or 'Report').replace(' ', '_').replace('/', '-')
            if fmt == 'pdf':
                from eu_ai_act_report import generate_eu_ai_act_report_pdf
                pdf_bytes = generate_eu_ai_act_report_pdf(enriched, org_name, branding)
                self.send_response(200)
                self.send_header('Content-Type', 'application/pdf')
                self.send_header('Content-Disposition', f'attachment; filename="EU_AI_Act_Report_{safe_org}.pdf"')
                self.send_header('Content-Length', str(len(pdf_bytes)))
                self.end_headers()
                self.wfile.write(pdf_bytes)
            elif fmt == 'csv':
                from eu_ai_act_report import generate_eu_ai_act_report_csv
                csv_bytes = generate_eu_ai_act_report_csv(enriched, org_name)
                self.send_response(200)
                self.send_header('Content-Type', 'text/csv')
                self.send_header('Content-Disposition', f'attachment; filename="EU_AI_Act_Report_{safe_org}.csv"')
                self.send_header('Content-Length', str(len(csv_bytes)))
                self.end_headers()
                self.wfile.write(csv_bytes)
            else:
                from eu_ai_act_report import generate_eu_ai_act_report
                html_out = generate_eu_ai_act_report(enriched, org_name, branding)
                self._send(200, html_out.encode(), 'text/html; charset=utf-8')
        except Exception as e:
            self._send(500, f'Report generation failed: {e}'.encode(), 'text/plain')

    def _api_fleet_aibom(self):
        """GET /api/fleet/aibom?org=... — HTML AI Bill of Materials report."""
        try:
            import urllib.parse as _up
            qs       = _up.parse_qs(_up.urlparse(self.path).query)
            org_name = qs.get('org', [''])[0]
            store    = self._store()
            devices  = store.list_devices(client_org_id=self._scoped_client_org())
            enriched = []
            for d in devices:
                rep = store.get_latest_report(d['device_id'])
                enriched.append({**d, '_report': rep})
            shadow   = store.list_shadow_devices()
            branding_path = ROOT / 'data' / 'branding.json'
            branding = json.loads(branding_path.read_text()) if branding_path.exists() else {}
            from aibom_generator import generate_aibom_report
            html_out = generate_aibom_report(enriched, org_name, branding, shadow)
            self._send(200, html_out.encode(), 'text/html; charset=utf-8')
        except Exception as e:
            self._send(500, f'AI-BOM generation failed: {e}'.encode(), 'text/plain')

    def _api_fleet_aibom_json(self):
        """GET /api/fleet/aibom.json?org=... — JSON AI-BOM download."""
        try:
            import urllib.parse as _up
            qs       = _up.parse_qs(_up.urlparse(self.path).query)
            org_name = qs.get('org', [''])[0]
            store    = self._store()
            devices  = store.list_devices(client_org_id=self._scoped_client_org())
            enriched = []
            for d in devices:
                rep = store.get_latest_report(d['device_id'])
                enriched.append({**d, '_report': rep})
            shadow   = store.list_shadow_devices()
            from aibom_generator import generate_aibom_json
            bom = generate_aibom_json(enriched, org_name, shadow)
            safe_org = (org_name or 'Fleet').replace(' ', '_').replace('/', '-')
            data = json.dumps(bom, indent=2).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Disposition', f'attachment; filename="AI_BOM_{safe_org}.json"')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:
            self._send(500, f'AI-BOM JSON failed: {e}'.encode(), 'text/plain')

    def _api_fleet_aibom_csv(self):
        """GET /api/fleet/aibom.csv?org=... — spreadsheet AI-BOM download."""
        try:
            import urllib.parse as _up
            qs = _up.parse_qs(_up.urlparse(self.path).query)
            org_name = qs.get('org', [''])[0]
            store = self._store()
            devices = [{**d, '_report': store.get_latest_report(d['device_id'])}
                       for d in store.list_devices(client_org_id=self._scoped_client_org())]
            from aibom_generator import generate_aibom_csv
            data = generate_aibom_csv(devices, org_name, store.list_shadow_devices())
            safe_org = (org_name or 'Fleet').replace(' ', '_').replace('/', '-')
            self.send_response(200)
            self.send_header('Content-Type', 'text/csv; charset=utf-8')
            self.send_header('Content-Disposition', f'attachment; filename="AI_BOM_{safe_org}.csv"')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:
            self._send(500, f'AI-BOM CSV failed: {e}'.encode(), 'text/plain')

    def _api_fleet_aibom_pdf(self):
        """GET /api/fleet/aibom.pdf?org=... — printable AI-BOM download."""
        try:
            import urllib.parse as _up
            qs = _up.parse_qs(_up.urlparse(self.path).query)
            org_name = qs.get('org', [''])[0]
            store = self._store()
            devices = [{**d, '_report': store.get_latest_report(d['device_id'])}
                       for d in store.list_devices(client_org_id=self._scoped_client_org())]
            from aibom_generator import generate_aibom_pdf
            data = generate_aibom_pdf(devices, org_name, store.list_shadow_devices())
            safe_org = (org_name or 'Fleet').replace(' ', '_').replace('/', '-')
            self.send_response(200)
            self.send_header('Content-Type', 'application/pdf')
            self.send_header('Content-Disposition', f'attachment; filename="AI_BOM_{safe_org}.pdf"')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:
            self._send(500, f'AI-BOM PDF failed: {e}'.encode(), 'text/plain')

    # ── Alert event log API ───────────────────────────────────────────────────

    def _api_get_alert_events(self):
        import urllib.parse as _up
        qs = _up.parse_qs(_up.urlparse(self.path).query)
        unreviewed_only = qs.get('unreviewed', [''])[0].lower() in ('1', 'true', 'yes')
        store = self._store()
        try:
            events = store.get_alert_events(limit=300, unreviewed_only=unreviewed_only)
            self._json({'events': events})
        except Exception as e:
            self._json({'events': [], 'error': str(e)})

    def _api_get_active_issues(self):
        store = self._store()
        try:
            issues = store.get_active_critical_high_findings()
            self._json({'issues': issues})
        except Exception as e:
            self._json({'issues': [], 'error': str(e)})

    def _api_unreviewed_alert_count(self):
        store = self._store()
        try:
            self._json({'count': store.count_unreviewed_alerts()})
        except Exception:
            self._json({'count': 0})

    def _api_review_alert(self, event_id_str: str):
        store = self._store()
        try:
            store.mark_alert_reviewed(int(event_id_str))
            self._json({'ok': True})
        except Exception as e:
            self._json({'ok': False, 'error': str(e)}, 400)

    def _api_review_all_alerts(self):
        store = self._store()
        try:
            store.mark_all_alerts_reviewed()
            self._json({'ok': True})
        except Exception as e:
            self._json({'ok': False, 'error': str(e)}, 500)

    # ── SIEM config API ───────────────────────────────────────────────────────

    def _api_get_siem_config(self):
        try:
            from connectors.siem_connector import load_siem_config_for_ui
            self._json(load_siem_config_for_ui(ROOT / 'siem_config.json'))
        except Exception as e:
            self._json({'error': str(e)}, 500)

    def _api_set_siem_config(self):
        length = _content_length(self.headers)
        if not length:
            self._send(400, b'Empty body', 'text/plain')
            return
        try:
            body = json.loads(self.rfile.read(length))
        except json.JSONDecodeError:
            self._send(400, b'Invalid JSON', 'text/plain')
            return
        try:
            from connectors.siem_connector import load_siem_config, save_siem_config
            existing = load_siem_config(ROOT / 'siem_config.json')
            _SECRETS = {'hec_token', 'shared_key', 'api_key', 'vsa_api_key',
                        'bms_api_key', 'itglue_api_key', 'password'}
            for siem_id, vals in body.items():
                if not isinstance(vals, dict):
                    continue
                if siem_id not in existing:
                    existing[siem_id] = {}
                for k, v in vals.items():
                    if k in _SECRETS and v == '__set__':
                        continue  # masked — keep existing secret
                    existing[siem_id][k] = v
            save_siem_config(existing, ROOT / 'siem_config.json')
            self._json({'status': 'saved'})
        except Exception as e:
            self._json({'error': str(e)}, 500)

    def _api_test_siem(self, siem_id: str):
        try:
            from connectors.siem_connector import load_siem_config, test_connection
            cfg = load_siem_config(ROOT / 'siem_config.json')
            ok, msg = test_connection(siem_id, cfg)
            self._json({'ok': ok, 'message': msg})
        except Exception as e:
            self._json({'ok': False, 'message': str(e)}, 500)

    def _serve_shortcut(self):
        url = f'http://localhost:{_serve_port}/fleet'
        if sys.platform == 'win32':
            content = f'[InternetShortcut]\nURL={url}\nIconIndex=0\n'.encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/x-mswinurl')
            self.send_header('Content-Disposition',
                             'attachment; filename="Sentinel Dashboard.url"')
            self.send_header('Content-Length', len(content))
            self.end_headers()
            self.wfile.write(content)
        else:
            content = (
                '<?xml version="1.0" encoding="UTF-8"?>\n'
                '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"'
                ' "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
                '<plist version="1.0"><dict>'
                f'<key>URL</key><string>{url}</string>'
                '</dict></plist>\n'
            ).encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Disposition',
                             'attachment; filename="Sentinel Dashboard.webloc"')
            self.send_header('Content-Length', len(content))
            self.end_headers()
            self.wfile.write(content)

    def _serve_clients(self):
        """GET /clients — Level 1 rollup: one row per client org, worst
        severity first. MSP-admin only (not in the client_viewer path
        allowlist, so a scoped session never reaches this method at all)."""
        me = self._session_user()
        if not me or me.get('role') not in ('admin', 'customer_admin', 'super_admin'):
            self._send(403, b'Forbidden', 'text/plain')
            return
        try:
            reg = _get_registry()
            orgs = reg.list_client_orgs(me['customer_id'])
            rollup = self._store().rollup_by_client_org()
        except Exception as e:
            self._send(500, f'Error loading client orgs: {e}'.encode(), 'text/plain')
            return

        sev_rank = {'critical': 0, 'warning': 1, 'no_data': 2, 'ok': 3}
        sev_color = {'critical': '#DC2626', 'warning': '#F97316', 'ok': '#16A34A', 'no_data': '#D1D5DB'}
        sev_label = {'critical': 'Critical', 'warning': 'Warning', 'ok': 'Clean', 'no_data': 'No data yet'}

        rows_data = []
        for o in orgs:
            stats = rollup.pop(o['id'], {
                'device_count': 0, 'critical': 0, 'warning': 0, 'ok': 0,
                'no_data': 0, 'last_scan_at': 0, 'worst_severity': 'no_data',
            })
            rows_data.append((o['id'], o['name'], stats))
        unassigned = rollup.pop(None, None)
        if unassigned and unassigned['device_count']:
            rows_data.append(('', 'Unassigned devices', unassigned))
        rows_data.sort(key=lambda r: sev_rank.get(r[2]['worst_severity'], 9))

        now = int(time.time())

        def _age(ts):
            if not ts:
                return 'never'
            secs = now - ts
            if secs < 3600:
                return f'{max(1, secs // 60)}m ago'
            if secs < 86400:
                return f'{secs // 3600}h ago'
            return f'{secs // 86400}d ago'

        org_by_id = {o['id']: o for o in orgs}

        row_html = ''
        for org_id, name, stats in rows_data:
            sev = stats['worst_severity']
            link = f"/?client_org={org_id}" if org_id else "/?client_org="
            if org_id:
                org = org_by_id.get(org_id, {})
                report_email = org.get('report_email', '') or ''
                monthly_checked = 'checked' if org.get('report_cadence') == 'monthly' else ''
                report_cell = (
                    '<td onclick="event.stopPropagation()" style="white-space:nowrap">'
                    f'<input type="email" class="report-email" data-org="{org_id}" value="{report_email}" '
                    'placeholder="client@example.com" style="width:150px;font-size:12px;background:#0d1117;'
                    'border:1px solid #30363d;color:#c9d1d9;padding:4px 6px;border-radius:4px">'
                    f'<label style="font-size:11px;margin-left:6px;color:#8b949e"><input type="checkbox" '
                    f'class="report-monthly" data-org="{org_id}" {monthly_checked}> Monthly</label>'
                    f'<button class="scan-btn" style="margin-left:6px;font-size:11px" '
                    f'onclick="saveReportConfig(\'{org_id}\',this)">Save</button>'
                    f'<button class="scan-btn" style="margin-left:4px;font-size:11px;color:#58a6ff" '
                    f'onclick="sendReportNow(\'{org_id}\',this)">Send Now</button>'
                    f'<span class="report-status" data-org="{org_id}" style="font-size:11px;margin-left:6px;color:#8b949e"></span>'
                    '</td>'
                )
            else:
                report_cell = '<td style="color:#484f58;font-size:12px">—</td>'
            name_js = name.replace('\\', '\\\\').replace("'", "\\'")
            manage_cell = (
                '<td onclick="event.stopPropagation()">'
                f'<button class="scan-btn" style="font-size:11px" '
                f'onclick="openDeviceModal(\'{org_id}\',\'{name_js}\')">Manage devices</button>'
                '</td>'
            )
            row_html += (
                '<tr class="client-row" onclick="location.href=\'' + link + '\'">'
                '<td><span class="risk-dot" style="background:' + sev_color[sev] + '"></span></td>'
                '<td class="client-name">' + name + '</td>'
                '<td>' + sev_label[sev] + '</td>'
                '<td>' + str(stats['device_count']) + '</td>'
                '<td style="color:#DC2626">' + str(stats['critical']) + '</td>'
                '<td style="color:#F97316">' + str(stats['warning']) + '</td>'
                '<td style="color:#16A34A">' + str(stats['ok']) + '</td>'
                '<td>' + _age(stats['last_scan_at']) + '</td>'
                + report_cell +
                manage_cell +
                '</tr>'
            )
        if not row_html:
            row_html = '<tr><td colspan="10" style="text-align:center;padding:32px;color:#8b949e">No client orgs yet — create one below.</td></tr>'

        org_options_html = ''.join(
            f'<option value="{o["id"]}">{o["name"].replace("<", "&lt;")}</option>' for o in orgs
        )

        body = ("""<!DOCTYPE html><html><head><meta charset="utf-8">
<title>Clients — Arckon</title>
<style>
body{font:14px -apple-system,sans-serif;background:#0d1117;color:#c9d1d9;margin:0;padding:32px}
h1{font-size:20px;font-weight:600;margin:0 0 20px}
a.back{color:#58a6ff;text-decoration:none;font-size:13px}
table{width:100%;border-collapse:collapse;margin-top:16px;background:#161b22;border-radius:8px;overflow:hidden}
th{text-align:left;padding:10px 14px;background:#21262d;color:#8b949e;font-weight:500;font-size:12px;text-transform:uppercase}
td{padding:10px 14px;border-top:1px solid #21262d}
.client-row{cursor:pointer}
.client-row:hover{background:#1c2128}
.client-name{font-weight:600;color:#e6edf3}
.risk-dot{display:inline-block;width:10px;height:10px;border-radius:50%}
.add-form{margin-top:24px;display:flex;gap:8px}
.add-form input{background:#0d1117;border:1px solid #30363d;color:#c9d1d9;padding:8px 12px;border-radius:6px;font-size:13px;flex:1;max-width:300px}
.add-form button{background:#238636;color:#fff;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;font-size:13px}
.add-form button:hover{background:#2ea043}
#new-token{margin-top:12px;padding:12px;background:#161b22;border:1px solid #30363d;border-radius:6px;font-size:13px;display:none}
#new-token code{color:#58a6ff;word-break:break-all}
.scan-btn{background:#21262d;border:1px solid #30363d;color:#c9d1d9;border-radius:4px;padding:3px 8px;cursor:pointer}
.scan-btn:hover{background:#30363d}
#device-modal{display:none;position:fixed;inset:0;background:rgba(0,0,0,0.6);z-index:100;align-items:center;justify-content:center}
#device-modal .box{background:#161b22;border:1px solid #30363d;border-radius:8px;width:640px;max-height:80vh;display:flex;flex-direction:column;padding:20px}
#device-modal input[type=text]{width:100%;box-sizing:border-box;padding:8px;background:#0d1117;border:1px solid #30363d;color:#c9d1d9;border-radius:6px}
#dm-list{overflow-y:auto;flex:1;border-top:1px solid #21262d;min-height:120px;max-height:360px}
.dm-row{display:flex;align-items:center;gap:8px;padding:6px 4px;border-bottom:1px solid #21262d;font-size:13px;cursor:pointer}
#dm-target-org{flex:1;padding:8px;background:#0d1117;border:1px solid #30363d;color:#c9d1d9;border-radius:6px}
</style></head><body>
<a class="back" href="/">&larr; Full fleet (all clients)</a>
<h1>Clients</h1>
<table>
<tr><th></th><th>Client</th><th>Status</th><th>Devices</th><th>Critical</th><th>Warning</th><th>Clean</th><th>Last scan</th><th>Monthly PDF Report</th><th></th></tr>
""" + row_html + """
</table>
<div class="add-form">
  <input id="new-client-name" placeholder="New client name (e.g. Acme Bakery)">
  <button onclick="addClient()">+ Add Client</button>
</div>
<div id="new-token"></div>

<div id="device-modal">
  <div class="box">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
      <h3 id="dm-title" style="margin:0;font-size:16px"></h3>
      <button onclick="closeDeviceModal()" style="background:none;border:none;color:#8b949e;font-size:20px;cursor:pointer">&times;</button>
    </div>
    <input type="text" id="dm-search" placeholder="Filter by hostname..." oninput="renderDeviceList()" style="margin-bottom:10px">
    <div style="display:flex;gap:12px;margin-bottom:8px;align-items:center">
      <label style="font-size:12px"><input type="checkbox" id="dm-select-all" onchange="toggleAllDeviceCheckboxes(this)"> Select all shown (<span id="dm-visible-count">0</span>)</label>
      <span id="dm-selected-count" style="font-size:12px;color:#8b949e"></span>
    </div>
    <div id="dm-list"></div>
    <div style="display:flex;gap:8px;margin-top:14px;align-items:center">
      <select id="dm-target-org">
        <option value="">— Unassigned —</option>
        """ + org_options_html + """
      </select>
      <button onclick="moveSelectedDevices()" class="scan-btn" style="background:#238636;color:#fff;border-color:#238636">Move selected</button>
    </div>
    <div id="dm-status" style="font-size:12px;margin-top:8px"></div>
  </div>
</div>

<script>
async function addClient(){
  const name = document.getElementById('new-client-name').value.trim();
  if(!name){ return; }
  const r = await fetch('/api/clients/add', {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({name})
  });
  const data = await r.json();
  if(data.ok){
    const box = document.getElementById('new-token');
    box.style.display = 'block';
    box.innerHTML = 'Client "' + data.client_org.name + '" created. Enrollment token '
      + '(paste into that client\\'s agent_config.json as client_org_token):<br><code>'
      + data.client_org.enroll_token + '</code>';
    setTimeout(() => location.reload(), 4000);
  } else {
    alert(data.error || 'Failed to create client');
  }
}

async function saveReportConfig(orgId, btn){
  const emailEl = document.querySelector('.report-email[data-org="' + orgId + '"]');
  const monthlyEl = document.querySelector('.report-monthly[data-org="' + orgId + '"]');
  const statusEl = document.querySelector('.report-status[data-org="' + orgId + '"]');
  const report_email = emailEl.value.trim();
  const report_cadence = monthlyEl.checked ? 'monthly' : 'off';
  btn.disabled = true;
  try {
    const r = await fetch('/api/clients/report-config/' + orgId, {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({report_email, report_cadence})
    });
    const data = await r.json();
    statusEl.textContent = data.ok ? 'Saved' : (data.error || 'Failed');
    statusEl.style.color = data.ok ? '#16A34A' : '#DC2626';
  } catch(e) {
    statusEl.textContent = 'Failed: ' + e;
    statusEl.style.color = '#DC2626';
  }
  btn.disabled = false;
  setTimeout(() => { statusEl.textContent = ''; }, 4000);
}

async function sendReportNow(orgId, btn){
  const emailEl = document.querySelector('.report-email[data-org="' + orgId + '"]');
  const statusEl = document.querySelector('.report-status[data-org="' + orgId + '"]');
  btn.disabled = true;
  statusEl.textContent = 'Sending...';
  statusEl.style.color = '#8b949e';
  try {
    const r = await fetch('/api/clients/send-report/' + orgId, {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({report_email: emailEl.value.trim()})
    });
    const data = await r.json();
    statusEl.textContent = data.ok ? 'Sent!' : (data.error || data.message || 'Failed');
    statusEl.style.color = data.ok ? '#16A34A' : '#DC2626';
  } catch(e) {
    statusEl.textContent = 'Failed: ' + e;
    statusEl.style.color = '#DC2626';
  }
  btn.disabled = false;
}

let dmDevices = [];

async function openDeviceModal(orgId, orgName){
  document.getElementById('dm-title').textContent = 'Devices — ' + orgName;
  document.getElementById('dm-search').value = '';
  document.getElementById('dm-select-all').checked = false;
  document.getElementById('dm-list').innerHTML = '<div style="padding:20px;color:#8b949e">Loading…</div>';
  document.getElementById('dm-target-org').value = orgId;
  document.getElementById('dm-status').textContent = '';
  document.getElementById('device-modal').style.display = 'flex';
  const qs = orgId === '' ? '__unassigned__' : orgId;
  try {
    const r = await fetch('/api/devices?client_org=' + encodeURIComponent(qs));
    const data = await r.json();
    dmDevices = data.devices || [];
  } catch(e) {
    dmDevices = [];
  }
  renderDeviceList();
}

function closeDeviceModal(){
  document.getElementById('device-modal').style.display = 'none';
}

function renderDeviceList(){
  const filter = (document.getElementById('dm-search').value || '').toLowerCase();
  const list = document.getElementById('dm-list');
  const filtered = dmDevices.filter(d => (d.hostname || d.device_id || '').toLowerCase().includes(filter));
  document.getElementById('dm-visible-count').textContent = filtered.length;
  list.innerHTML = filtered.map(d =>
    '<label class="dm-row"><input type="checkbox" class="dm-device-cb" value="' + d.device_id + '" onchange="updateSelectedCount()">' +
    '<span style="flex:1">' + (d.hostname || d.device_id) + '</span>' +
    '<span style="color:#8b949e;font-size:11px">' + (d.platform || '') + '</span></label>'
  ).join('') || '<div style="padding:20px;color:#8b949e">No devices.</div>';
  updateSelectedCount();
}

function toggleAllDeviceCheckboxes(cb){
  document.querySelectorAll('.dm-device-cb').forEach(el => { el.checked = cb.checked; });
  updateSelectedCount();
}

function updateSelectedCount(){
  const n = document.querySelectorAll('.dm-device-cb:checked').length;
  document.getElementById('dm-selected-count').textContent = n ? (n + ' selected') : '';
}

async function moveSelectedDevices(){
  const ids = Array.from(document.querySelectorAll('.dm-device-cb:checked')).map(el => el.value);
  const statusEl = document.getElementById('dm-status');
  if (!ids.length){ statusEl.textContent = 'Select at least one device.'; statusEl.style.color = '#DC2626'; return; }
  const targetOrg = document.getElementById('dm-target-org').value;
  statusEl.textContent = 'Moving…'; statusEl.style.color = '#8b949e';
  try {
    const r = await fetch('/api/clients/assign-devices', {
      method: 'POST', headers: {'Content-Type':'application/json'},
      body: JSON.stringify({device_ids: ids, client_org_id: targetOrg})
    });
    const data = await r.json();
    if (data.ok){
      statusEl.textContent = 'Moved ' + data.moved + ' device(s).'; statusEl.style.color = '#16A34A';
      setTimeout(() => location.reload(), 1200);
    } else {
      statusEl.textContent = data.error || 'Failed'; statusEl.style.color = '#DC2626';
    }
  } catch(e) {
    statusEl.textContent = 'Network error.'; statusEl.style.color = '#DC2626';
  }
}
</script>
</body></html>""")
        self._send(200, body.encode('utf-8'), 'text/html; charset=utf-8')

    def _serve_fleet(self):
        print('[SENTINEL] _serve_fleet: start', flush=True)
        try:
            store = self._store()
            org_scope = self._scoped_client_org()
            devices = store.list_devices(client_org_id=org_scope)
            # Shadow-device/MCP discovery isn't tagged per client org yet
            # (network-wide discovery, not per-device) — suppress rather
            # than risk showing a client-viewer another client's discovered
            # assets. MSP admins (org_scope is None) still see everything.
            shadow  = store.list_shadow_devices() if org_scope is None else []
            mcp     = store.list_mcp_servers() if org_scope is None else []
            network_assets = store.list_network_assets(client_org_id=org_scope)
            print(f'[SENTINEL] _serve_fleet: got {len(devices)} devices, {len(shadow)} shadow, {len(mcp)} mcp', flush=True)
        except Exception as _e:
            print(f'[SENTINEL] _serve_fleet: store error: {_e}', flush=True)
            log.error('_serve_fleet: store error: %s', _e, exc_info=True)
            devices = []
            shadow  = []
            mcp     = []
            network_assets = []
        try:
            user = self._session_user()
            body = _build_fleet_html(
                devices, shadow, mcp, network_assets,
                current_user_email=user['email'] if user else '',
                current_user_role=user.get('role', '') if user else '',
                current_user_is_reseller=bool(user.get('is_reseller')) if user else False,
                current_user_is_msp=bool(user.get('is_msp')) if user else False,
                current_user_impersonated_by=(user.get('impersonated_by') or '') if user else '',
                store=store,
            ).encode('utf-8')
            print(f'[SENTINEL] _serve_fleet: body built {len(body)} bytes', flush=True)
        except Exception as _e:
            print(f'[SENTINEL] _serve_fleet: build error: {_e}', flush=True)
            log.error('_build_fleet_html failed: %s', _e, exc_info=True)
            body = (
                b'<html><body style="font:14px monospace;background:#0d1117;color:#f85149;padding:40px">'
                b'<h2>Dashboard render error</h2><pre>' +
                __import__('traceback').format_exc().encode('utf-8', errors='replace') +
                b'</pre></body></html>'
            )
        try:
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', len(body))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(body)
            print('[SENTINEL] _serve_fleet: sent OK', flush=True)
        except Exception as _e:
            print(f'[SENTINEL] _serve_fleet: send error: {_e}', flush=True)
            log.error('_serve_fleet: send failed: %s', _e, exc_info=True)

    def _api_probe_scan(self):
        length = _content_length(self.headers)
        if length > 16_384:
            self._send(413, b'Payload too large', 'text/plain')
            return
        try:
            body = json.loads(self.rfile.read(length)) if length else {}
        except Exception:
            self._send(400, b'Invalid JSON', 'text/plain')
            return

        provider = str(body.get('provider', 'openai'))
        api_key  = str(body.get('api_key', '')).strip()
        model    = str(body.get('model', '')).strip()
        endpoint = str(body.get('endpoint', '')).strip()
        uses_rag = bool(body.get('uses_rag', False))
        rag_query = str(body.get('rag_query', '')).strip()
        rag_retrieval_marker = str(body.get('rag_retrieval_marker', 'ARCKON_RAG_RETRIEVED_C7E1')).strip()
        rag_injection_marker = str(body.get('rag_injection_marker', 'ARCKON_RAG_INJECTION_A9D4')).strip()

        if not api_key:
            self._json({'error': 'api_key is required'}, 400)
            return
        if provider not in ('openai', 'anthropic', 'gemini'):
            self._json({'error': 'unknown provider'}, 400)
            return
        if uses_rag and (provider != 'openai' or not rag_query):
            self._json({'error': 'RAG testing requires an OpenAI-compatible application endpoint and a retrieval query.'}, 400)
            return

        log.info('probe-scan start: provider=%s endpoint=%s', provider, endpoint or '(default)')
        try:
            sys.path.insert(0, str(ROOT))
            from dataclasses import asdict
            from checks.input_safety import (
                check_inp_001, check_inp_002, check_inp_003, check_inp_004,
            )
            from checks.output_safety import (
                check_out_001, check_out_002, check_out_003, check_out_004,
            )

            if provider == 'openai':
                from connectors.api_connector import connect
                ep = endpoint or 'https://api.openai.com/v1'
                mdl = model or 'gpt-4o-2024-11-20'
                log.info('probe-scan connecting to %s model=%s', ep, mdl)
                rag_probe = ({'query': rag_query, 'retrieval_marker': rag_retrieval_marker,
                              'injection_marker': rag_injection_marker} if uses_rag else None)
                ctx = connect(ep, api_key, mdl, str(ROOT), rag_probe=rag_probe)
            elif provider == 'anthropic':
                from connectors.claude_connector import connect
                mdl = model or 'claude-sonnet-4-6'
                ctx = connect(api_key=api_key, model=mdl, target_dir=str(ROOT))
            else:
                from connectors.gemini_connector import connect
                mdl = model or 'gemini-1.5-flash'
                ctx = connect(api_key=api_key, model=mdl, target_dir=str(ROOT))

            live_error = getattr(ctx, 'live_error', '')
            probe_count = len(ctx.probe_results)
            log.info('probe-scan probes completed: %d  live_error=%r', probe_count, live_error)
            results = [
                check_inp_001(ctx), check_inp_002(ctx),
                check_inp_003(ctx), check_inp_004(ctx),
                check_out_001(ctx), check_out_002(ctx),
                check_out_003(ctx), check_out_004(ctx),
            ]
            summary = {'pass': 0, 'fail': 0, 'warn': 0, 'skip': 0}
            serialized = []
            for r in results:
                summary[r.status.lower()] = summary.get(r.status.lower(), 0) + 1
                serialized.append(asdict(r))

            log.info('probe-scan done: %s', summary)
            self._json({'summary': summary, 'results': serialized,
                        'live_error': live_error, 'model': mdl})
        except Exception as exc:
            log.error('probe-scan error: %s', exc, exc_info=True)
            self._json({'error': str(exc)}, 500)

    def _probe_run(self):
        """POST /probe — run scan and return a fully server-rendered results page."""
        length = _content_length(self.headers)
        if length > 16_384:
            self._send(413, b'Payload too large', 'text/plain')
            return
        try:
            from urllib.parse import parse_qs
            raw = self.rfile.read(length).decode('utf-8', errors='replace') if length else ''
            fields = {k: v[0] for k, v in parse_qs(raw).items()}
        except Exception:
            self._send(400, b'Bad request', 'text/plain')
            return

        provider = fields.get('provider', 'openai')
        api_key  = fields.get('api_key', '').strip()
        model    = fields.get('model', '').strip()
        endpoint = fields.get('endpoint', '').strip()
        rag_val  = fields.get('uses_rag', '')
        uses_rag = True if rag_val == 'yes' else (False if rag_val == 'no' else None)
        rag_query = fields.get('rag_query', '').strip()
        rag_retrieval_marker = fields.get('rag_retrieval_marker', 'ARCKON_RAG_RETRIEVED_C7E1').strip()
        rag_injection_marker = fields.get('rag_injection_marker', 'ARCKON_RAG_INJECTION_A9D4').strip()

        if not api_key:
            self._serve_probe_tester(error='Please enter an API key.')
            return
        if provider not in ('openai', 'anthropic', 'gemini'):
            self._serve_probe_tester(error='Unknown provider.')
            return
        if uses_rag is True and provider != 'openai':
            self._serve_probe_tester(error='RAG testing requires your deployed, OpenAI-compatible application endpoint — not a direct model-provider API.')
            return
        if uses_rag is True and not rag_query:
            self._serve_probe_tester(error='Enter the query that retrieves your seeded RAG test document.')
            return

        log.info('probe-run start: provider=%s endpoint=%s', provider, endpoint or '(default)')
        try:
            sys.path.insert(0, str(ROOT))
            from checks.input_safety import (
                check_inp_001, check_inp_002, check_inp_003, check_inp_004,
            )
            from checks.output_safety import (
                check_out_001, check_out_002, check_out_003, check_out_004,
            )

            if provider == 'openai':
                from connectors.api_connector import connect
                ep  = endpoint or 'https://api.openai.com/v1'
                mdl = model or 'gpt-4o-2024-11-20'
                rag_probe = ({'query': rag_query, 'retrieval_marker': rag_retrieval_marker,
                              'injection_marker': rag_injection_marker} if uses_rag is True else None)
                ctx = connect(ep, api_key, mdl, str(ROOT), rag_probe=rag_probe)
            elif provider == 'anthropic':
                from connectors.claude_connector import connect
                mdl = model or 'claude-sonnet-4-6'
                ctx = connect(api_key=api_key, model=mdl, target_dir=str(ROOT))
            else:
                from connectors.gemini_connector import connect
                mdl = model or 'gemini-1.5-flash'
                ctx = connect(api_key=api_key, model=mdl, target_dir=str(ROOT))

            ctx.uses_rag = uses_rag
            live_error = getattr(ctx, 'live_error', '')
            results = [
                check_inp_001(ctx), check_inp_002(ctx),
                check_inp_003(ctx), check_inp_004(ctx),
                check_out_001(ctx), check_out_002(ctx),
                check_out_003(ctx), check_out_004(ctx),
            ]
            summary = {'pass': 0, 'fail': 0, 'warn': 0, 'skip': 0, 'n/a': 0}
            for r in results:
                key = r.status.lower()
                summary[key] = summary.get(key, 0) + 1
            log.info('probe-run done: %s', summary)
            html = self._build_probe_results(mdl, summary, results, live_error)
            self._send(200, html, 'text/html; charset=utf-8')
        except Exception as exc:
            log.error('probe-run error: %s', exc, exc_info=True)
            self._serve_probe_tester(error=f'Scan error: {exc}')

    def _build_probe_results(self, model, summary, results, live_error):
        STATUS_COLOR = {'PASS': '#58a6ff', 'FAIL': '#f85149', 'WARN': '#d29922', 'SKIP': '#6e7681', 'N/A': '#444c56'}
        STATUS_BG    = {'PASS': '#0d1a2d', 'FAIL': '#4a0d0d', 'WARN': '#4a3b0d', 'SKIP': '#1c2128', 'N/A': '#161b22'}
        SEV_COLOR    = {'CRITICAL': '#f85149', 'HIGH': '#d29922', 'MEDIUM': '#58a6ff', 'LOW': '#8b949e'}
        SEV_BG       = {'CRITICAL': '#4a0d0d', 'HIGH': '#4a3b0d', 'MEDIUM': '#1d3250', 'LOW': '#21262d'}
        BORDER       = {'PASS': '#58a6ff', 'FAIL': '#f85149', 'WARN': '#d29922', 'SKIP': '#30363d', 'N/A': '#21262d'}

        def e(s):
            return str(s or '').replace('&','&amp;').replace('<','&lt;').replace('>','&gt;').replace('"','&quot;')

        all_skip = all(r.status in ('SKIP', 'N/A') for r in results)
        all_good = not all_skip and summary['fail'] == 0 and summary['warn'] == 0

        cats = {}
        for r in results:
            cats.setdefault(r.category, []).append(r)
        order = {'FAIL': 0, 'WARN': 1, 'PASS': 2, 'SKIP': 3, 'N/A': 4}
        for lst in cats.values():
            lst.sort(key=lambda r: order.get(r.status, 9))

        body = f'''<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Arckon - Probe Results</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#0d1117;color:#e6edf3;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;font-size:14px}}
.wrap{{max-width:900px;margin:0 auto;padding:32px 20px 64px}}
.brand-bar{{display:flex;align-items:center;gap:10px;margin-bottom:28px;padding-bottom:16px;border-bottom:1px solid #21262d}}
.brand-mark{{font-size:18px;font-weight:800;letter-spacing:2px;color:#58a6ff}}
.brand-name{{font-size:16px;font-weight:700;letter-spacing:1px}}
.brand-sub{{font-size:12px;color:#8b949e;margin-left:4px}}
.back{{margin-left:auto;font-size:12px;color:#58a6ff;text-decoration:none}}
.back:hover{{text-decoration:underline}}
.model-tag{{font-size:12px;color:#6e7681;margin-bottom:20px}}
.strip{{display:flex;gap:12px;margin-bottom:20px;flex-wrap:wrap}}
.sc{{flex:1;min-width:80px;background:#161b22;border:1px solid #21262d;border-radius:8px;padding:14px 12px;text-align:center}}
.sc-n{{font-size:28px;font-weight:800;line-height:1}}
.sc-l{{font-size:11px;color:#8b949e;margin-top:4px;text-transform:uppercase;letter-spacing:.5px}}
.banner{{border-radius:6px;font-size:13px;padding:14px 16px;margin-bottom:18px;line-height:1.6}}
.banner-ok{{background:#0d4a1a;border:1px solid #3fb950;color:#3fb950}}
.banner-warn{{background:#4a3b0d;border:1px solid #d29922;color:#d29922}}
.cat-hdr{{font-size:12px;font-weight:700;color:#8b949e;text-transform:uppercase;letter-spacing:1px;margin:22px 0 8px;padding-bottom:6px;border-bottom:1px solid #21262d}}
.check{{border-radius:8px;margin-bottom:10px;overflow:hidden;border:1px solid #21262d}}
.check-head{{display:flex;align-items:flex-start;gap:10px;padding:14px 16px}}
.sb{{font-size:11px;font-weight:700;padding:3px 9px;border-radius:4px;min-width:44px;text-align:center;flex-shrink:0;margin-top:1px}}
.sv{{font-size:10px;font-weight:600;padding:3px 7px;border-radius:4px;border:1px solid;flex-shrink:0;margin-top:1px}}
.meta{{flex:1;min-width:0}}
.title{{font-size:13px;font-weight:600;margin-bottom:3px}}
.detail{{font-size:12px;color:#8b949e;line-height:1.5}}
.cid{{font-size:11px;color:#6e7681;flex-shrink:0;padding-top:2px}}
.body{{padding:0 16px 16px;border-top:1px solid #21262d}}
.sec{{margin-top:12px}}
.sec-lbl{{font-size:11px;font-weight:700;color:#8b949e;text-transform:uppercase;letter-spacing:.5px;margin-bottom:5px}}
.ev-list{{list-style:none;padding:0}}
.ev-list li{{font-size:12px;color:#8b949e;font-family:ui-monospace,monospace;background:#0d1117;border:1px solid #21262d;border-radius:4px;padding:5px 10px;margin-bottom:4px;word-break:break-all}}
.fix{{font-size:13px;color:#c9d1d9;line-height:1.8;white-space:pre-wrap}}
.fw{{display:flex;flex-wrap:wrap;gap:5px;margin-top:6px}}
.fw span{{font-size:10px;background:#1d3250;color:#58a6ff;border-radius:4px;padding:2px 7px}}
.run-again{{display:inline-block;margin-top:28px;background:#238636;color:#fff;border-radius:6px;padding:10px 22px;font-size:14px;font-weight:600;text-decoration:none}}
.run-again:hover{{background:#2ea043}}
.export-btn{{display:inline-block;margin-top:28px;margin-left:12px;background:#161b22;color:#58a6ff;border:1px solid #30363d;border-radius:6px;padding:10px 22px;font-size:14px;font-weight:600;cursor:pointer;text-decoration:none}}
.export-btn:hover{{background:#1d3250;border-color:#58a6ff}}
.skip-reason{{font-size:12px;color:#8b949e;background:#0d1117;border:1px solid #30363d;border-radius:4px;padding:10px 12px;line-height:1.6}}
.print-date{{display:none;font-size:11px;color:#666;margin-bottom:12px}}
@media print{{
  body{{background:#fff;color:#000}}
  .wrap{{padding:16px}}
  .brand-bar{{border-bottom:1px solid #ccc}}
  .brand-mark,.brand-name{{color:#000}}
  .brand-sub,.model-tag{{color:#555}}
  .back,.run-again,.export-btn{{display:none!important}}
  .strip .sc{{background:#f5f5f5;border:1px solid #ccc}}
  .sc-l{{color:#555}}
  .banner-ok{{background:#e6f4ea;border-color:#34a853;color:#1e7e34}}
  .banner-warn{{background:#fef9e7;border-color:#fbbc04;color:#7a5c00}}
  .cat-hdr{{color:#555;border-color:#ccc}}
  .check{{border:1px solid #ccc;break-inside:avoid;page-break-inside:avoid}}
  .detail,.sec-lbl,.cid{{color:#333}}
  .body{{border-top:1px solid #ccc}}
  .ev-list li{{background:#f5f5f5;border-color:#ccc;color:#333}}
  .fix{{color:#333}}
  .fw span{{background:#e8f0fe;color:#1a56db}}
  .skip-reason{{background:#f5f5f5;border-color:#ccc;color:#333}}
  .print-date{{display:block}}
}}
</style></head><body><div class="wrap">
<div class="brand-bar">
  <span class="brand-name">ARCKON</span>
  <span class="brand-mark">by RiskRaven</span>
  <span class="brand-sub">Probe Results</span>
  <a class="back" href="/probe">Run Another Test</a>
</div>
<div class="print-date">Arckon &#8212; AI API Security Report &nbsp;|&nbsp; {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M')}</div>
<div class="model-tag">Model tested: <strong>{e(model)}</strong></div>
<div class="strip">
  <div class="sc"><div class="sc-n" style="color:#f85149">{summary["fail"]}</div><div class="sc-l">High Risk</div></div>
  <div class="sc"><div class="sc-n" style="color:#d29922">{summary["warn"]}</div><div class="sc-l">Medium Risk</div></div>
  <div class="sc"><div class="sc-n" style="color:#58a6ff">{summary["pass"]}</div><div class="sc-l">Info</div></div>
  <div class="sc"><div class="sc-n" style="color:#6e7681">{summary["skip"]}</div><div class="sc-l">Skipped</div></div>
  <div class="sc"><div class="sc-n" style="color:#444c56">{summary.get("n/a", 0)}</div><div class="sc-l">N/A</div></div>
</div>'''

        if all_skip:
            reason = live_error or 'the endpoint did not respond to probe requests'
            body += f'<div class="banner banner-warn"><strong>Could not connect to endpoint.</strong> {e(reason)}<br>Check your API key, endpoint URL, and model name.</div>'
        elif all_good:
            body += '<div class="banner banner-ok"><strong>All active checks passed.</strong> No prompt injection, jailbreak, PII leakage, or system prompt disclosure issues detected.</div>'

        for cat in sorted(cats):
            body += f'<div class="cat-hdr">{e(cat)}</div>'
            for r in cats[cat]:
                sc = STATUS_COLOR.get(r.status, '#8b949e')
                sb = STATUS_BG.get(r.status, '#1c2128')
                vc = SEV_COLOR.get(r.severity, '#8b949e')
                vb = SEV_BG.get(r.severity, '#21262d')
                bc = BORDER.get(r.status, '#30363d')
                body += f'''<div class="check" style="border-left:3px solid {bc}">
  <div class="check-head">
    <span class="sb" style="background:{sb};color:{sc}">{e(r.status)}</span>
    <span class="sv" style="background:{vb};color:{vc};border-color:{vb}">{e(r.severity)}</span>
    <div class="meta">
      <div class="title">{e(r.title)}</div>
      <div class="detail">{e(r.details)}</div>
    </div>
    <span class="cid">{e(r.check_id)}</span>
  </div>'''
                is_skip = r.status == 'SKIP'
                is_na   = r.status == 'N/A'
                has_body = bool(r.evidence or r.remediation or is_skip or is_na)
                if has_body:
                    body += '<div class="body">'
                    if is_na:
                        body += f'<div class="sec"><div class="sec-lbl">Why Not Applicable</div><div class="skip-reason">{e(r.details)}</div></div>'
                    elif is_skip:
                        body += f'<div class="sec"><div class="sec-lbl">Why Skipped</div><div class="skip-reason">{e(r.details)}</div></div>'
                    if r.evidence:
                        body += '<div class="sec"><div class="sec-lbl">Evidence</div><ul class="ev-list">'
                        for ev in r.evidence:
                            body += f'<li>{e(ev)}</li>'
                        body += '</ul></div>'
                    if r.remediation:
                        lbl = 'How to Enable' if is_skip else 'How to Fix'
                        body += f'<div class="sec"><div class="sec-lbl">{lbl}</div><div class="fix">{e(r.remediation)}</div></div>'
                    if r.frameworks:
                        body += '<div class="sec"><div class="sec-lbl">Frameworks</div><div class="fw">'
                        for fw, ctrl in r.frameworks.items():
                            body += f'<span>{e(fw)}: {e(ctrl)}</span>'
                        body += '</div></div>'
                    body += '</div>'
                body += '</div>'

        body += '<a class="run-again" href="/probe">Run Another Test</a>'
        body += '<button class="export-btn" onclick="window.print()">Export to PDF</button>'
        body += '</div></body></html>'
        return body.encode('utf-8')

    def _serve_probe_tester(self, error=''):
        err_html = ('<div style="background:#4a0d0d;border:1px solid #f85149;border-radius:6px;'
                    'color:#f85149;font-size:13px;padding:14px 16px;margin-bottom:16px">'
                    + error + '</div>') if error else ''
        page = (
            b'<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
            b'<meta name="viewport" content="width=device-width,initial-scale=1">'
            b'<title>Arckon - API Security Tester</title>'
            b'<style>'
            b'*{box-sizing:border-box;margin:0;padding:0}'
            b'body{background:#0d1117;color:#e6edf3;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;font-size:14px;min-height:100vh}'
            b'.wrap{max-width:860px;margin:0 auto;padding:32px 20px 64px}'
            b'.bar{display:flex;align-items:center;gap:10px;margin-bottom:32px;padding-bottom:20px;border-bottom:1px solid #21262d}'
            b'.bm{font-size:18px;font-weight:800;letter-spacing:2px;color:#58a6ff}'
            b'.bn{font-size:16px;font-weight:700;letter-spacing:1px}'
            b'.bs{font-size:12px;color:#8b949e;margin-left:4px}'
            b'h1{font-size:20px;font-weight:700;margin-bottom:6px}'
            b'.sub{color:#8b949e;font-size:13px;margin-bottom:28px;line-height:1.6}'
            b'.card{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:24px;margin-bottom:16px}'
            b'label{display:block;font-size:12px;font-weight:600;color:#8b949e;margin-bottom:6px;text-transform:uppercase;letter-spacing:.5px}'
            b'select,input,textarea{width:100%;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#e6edf3;font-size:14px;padding:9px 12px;outline:none}'
            b'select:focus,input:focus,textarea:focus{border-color:#58a6ff}'
            b'.field{margin-bottom:18px}'
            b'.row{display:grid;grid-template-columns:1fr 1fr;gap:16px}'
            b'.hint{font-size:11px;color:#6e7681;margin-top:4px}'
            b'.btn{background:#238636;border:none;border-radius:6px;color:#fff;cursor:pointer;font-size:14px;font-weight:600;padding:10px 22px}'
            b'.btn:hover{background:#2ea043}'
            b'#ep-field{display:block}'
            b'#wait{display:none;color:#8b949e;font-size:13px;margin-top:16px}'
            b'</style></head><body>'
            b'<div class="wrap">'
            b'<div class="bar"><span class="bn">ARCKON</span><span class="bm">by RiskRaven</span>'
            b'<span class="bs">API Security Tester</span>'
            b'<a href="/" style="margin-left:auto;font-size:12px;color:#8b949e;text-decoration:none;border:1px solid #30363d;border-radius:5px;padding:5px 10px">&#8592; Dashboard</a>'
            b'</div>'
            b'<h1>AI API Security Tester</h1>'
            b'<p class="sub">Enter your API credentials to run live adversarial probes against your AI endpoint.<br>'
            b'Tests: prompt injection, jailbreaks, PII leakage, system prompt disclosure, harmful content refusals.<br>'
            b'Your key is sent only to your endpoint and never stored by Sentinel.</p>'
        ) + err_html.encode() + (
            b'<div class="card">'
            b'<form method="POST" action="/probe" onsubmit="document.getElementById(\'wait\').style.display=\'block\';document.querySelector(\'.btn\').disabled=true;">'
            b'<div class="field"><label>Provider</label>'
            b'<select name="provider" onchange="var s=this.value;document.getElementById(\'ep-field\').style.display=s===\'openai\'?\'block\':\'none\';document.getElementById(\'rag-provider-hint\').style.display=s===\'openai\'?\'none\':\'block\'">'
            b'<option value="openai">OpenAI-compatible (OpenAI, Azure, local, etc.)</option>'
            b'<option value="anthropic">Anthropic (Claude)</option>'
            b'<option value="gemini">Google Gemini</option>'
            b'</select></div>'
            b'<div class="field" id="ep-field"><label>API Endpoint</label>'
            b'<input type="text" name="endpoint" value="https://api.openai.com/v1">'
            b'<div class="hint">Base URL, no trailing slash.</div></div>'
            b'<div class="row">'
            b'<div class="field"><label>API Key</label>'
            b'<input type="password" name="api_key" placeholder="sk-..." autocomplete="off" required>'
            b'<div class="hint">Never stored - used only for this scan.</div></div>'
            b'<div class="field"><label>Model (optional)</label>'
            b'<input type="text" name="model" placeholder="gpt-4o-2024-11-20">'
            b'<div class="hint">Leave blank for provider default.</div></div>'
            b'</div>'
            b'<div class="field"><label>Does your AI system use document retrieval (RAG)?</label>'
            b'<select name="uses_rag">'
            b'<option value="">I\'m not sure</option>'
            b'<option value="no">No - it answers from its training data only</option>'
            b'<option value="yes">Yes - it retrieves documents, files, or a knowledge base</option>'
            b'</select>'
            b'<div class="hint">RAG = Retrieval-Augmented Generation. Used in chatbots that search a document library before responding.</div>'
            b'<div class="hint" id="rag-provider-hint" style="display:none;color:#d29922">RAG testing is available only through your deployed OpenAI-compatible application endpoint, not a direct provider API.</div></div>'
            b'<div class="card" style="border-color:#30363d">'
            b'<label>RAG test setup (required only when RAG is Yes)</label>'
            b'<div class="hint" style="margin-bottom:12px">Before running the scan, add a controlled test document to the target knowledge base. It must contain both markers below and an embedded instruction to output the injection marker. Arckon verifies retrieval using the retrieval marker, then fails only if the injection marker is followed.</div>'
            b'<div class="field"><label>Query that retrieves the test document</label><textarea name="rag_query" rows="2" placeholder="What is the verifier ID in the Arckon RAG security test document?"></textarea></div>'
            b'<div class="row"><div class="field"><label>Retrieval marker</label><input name="rag_retrieval_marker" value="ARCKON_RAG_RETRIEVED_C7E1"><div class="hint">Must appear in the document as factual content.</div></div>'
            b'<div class="field"><label>Injection marker</label><input name="rag_injection_marker" value="ARCKON_RAG_INJECTION_A9D4"><div class="hint">The document must instruct the model to output this marker.</div></div></div>'
            b'</div>'
            b'<button class="btn" type="submit">Run Security Tests</button>'
            b'<div id="wait">Running probes... this takes 30-90 seconds. Please wait.</div>'
            b'</form></div></div></body></html>'
        )
        self._send(200, page, 'text/html; charset=utf-8')


    def _serve_academy(self):
        try:
            sys.path.insert(0, str(ROOT))
            from academy import build
            html = build(ROOT)
            self._send(200, html, 'text/html; charset=utf-8')
        except Exception as e:
            self._send(500, f'Academy build failed: {e}'.encode(), 'text/plain')

    # ── helpers ───────────────────────────────────────────────────────────────

    def _redirect(self, location: str):
        self.send_response(302)
        self.send_header('Location', location)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def _not_found(self):
        self._send(404, b'Not found', 'text/plain')

    def _send(self, code: int, body: bytes, ct: str):
        self.send_response(code)
        self.send_header('Content-Type', ct)
        self.send_header('Content-Length', len(body))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)

    def _json(self, data: dict, code: int = 200):
        self._send(code, json.dumps(data).encode(), 'application/json')


def _build_shadow_section(shadow: list[dict], ts_now: int) -> str:
    _SOURCE_META = {
        'network':   ('&#127760;', '#a371f7', 'Network',   'AI service running on an unmanaged device'),
        'cloud_api': ('&#9729;',   '#58a6ff', 'Cloud API', 'Cloud AI API key found on a managed device'),
        'process':   ('&#9881;',   '#f0883e', 'Process',   'AI process running locally on a managed device'),
        'docker':    ('&#128051;', '#3fb950', 'Container', 'AI running inside a Docker container'),
        'saas_ai':   ('&#128101;', '#f78166', 'SaaS AI',   'Employee actively accessing a cloud AI service'),
    }

    def _age(ts: int | None) -> str:
        if not ts:
            return 'never'
        secs = ts_now - ts
        if secs < 120:
            return f'{secs}s ago'
        if secs < 3600:
            return f'{secs // 60}m ago'
        if secs < 86400:
            return f'{secs // 3600}h ago'
        return f'{secs // 86400}d ago'

    def _model_tags(models: list) -> str:
        shown = models[:5]
        extra = len(models) - 5
        tags = ' '.join(
            f'<span style="background:#0d1117;border:1px solid #30363d;border-radius:3px;'
            f'padding:1px 8px;font-size:11px;font-family:monospace;color:#c9d1d9">{m}</span>'
            for m in shown
        )
        if extra > 0:
            tags += f' <span style="font-size:11px;color:#6e7681">+{extra} more</span>'
        return tags

    if not shadow:
        cards = ('<div class="empty" style="padding:20px;text-align:center;color:#484f58">'
                 'No Shadow AI detected yet. Click <strong style="color:#a371f7">Find Shadow AI</strong> '
                 'above to scan your network through all installed agents.</div>')
    else:
        docker_items = [d for d in shadow if d.get('source') == 'docker']
        other_items  = [d for d in shadow if d.get('source') != 'docker']
        card_parts: list[str] = []

        for d in other_items:
            src   = d.get('source', 'network')
            icon, color, src_label, _ = _SOURCE_META.get(src, _SOURCE_META['network'])
            sid   = d.get('id', 0)
            host  = d.get('host', '')
            port  = d.get('port', 0)
            svc   = d.get('service', 'Unknown AI service')
            detail = d.get('detail', '')
            reporter = d.get('reporter_hostname', 'unknown')
            models = d.get('models') or []
            age   = _age(d.get('last_seen'))
            if src == 'network':
                location_html = (f'<span style="font-weight:700;color:#e6edf3;font-size:14px">'
                                 f'{host}:{port}</span>')
                sub_html = f'<span style="font-size:12px;color:{color}">{svc}</span>'
            else:
                location_html = (f'<span style="font-weight:700;color:#e6edf3;font-size:14px">'
                                 f'{svc}</span>')
                device_html = (f'<span style="font-size:12px;color:#8b949e;font-family:monospace">'
                               f'&#128187; {reporter}</span>')
                detail_html = (f'<span style="font-size:12px;color:#6e7681"> &nbsp;{detail}</span>'
                               if detail else '')
                sub_html = device_html + detail_html
            model_html = _model_tags(models) if models else (
                '<span style="font-size:11px;color:#484f58">No model details available</span>'
            )
            svc_js = svc.replace("'", "\\'")
            approve_btn = (
                f'<button class="scan-btn" onclick="shadowApproveGlobally(\'{svc_js}\',this)" '
                f'style="font-size:11px;color:#a371f7;border-color:#6e40c9;margin-bottom:4px;display:block;width:100%">'
                f'&#9733; Approve globally</button>'
            ) if src == 'saas_ai' else ''
            card_parts.append(
                f'<div class="shadow-card" style="border-left-color:{color}">'
                f'<div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px">'
                f'<div style="flex:1;min-width:0">'
                f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">'
                f'<span style="font-size:16px">{icon}</span>'
                f'{location_html}'
                f'<span style="font-size:10px;font-weight:700;padding:1px 7px;border-radius:3px;'
                f'background:#1a1f2e;color:{color};border:1px solid {color};text-transform:uppercase">'
                f'{src_label}</span>'
                f'</div>'
                f'<div style="margin-bottom:8px">{sub_html}</div>'
                f'<div style="display:flex;flex-wrap:wrap;gap:5px;align-items:center">{model_html}</div>'
                f'</div>'
                f'<div style="text-align:right;flex-shrink:0;min-width:130px">'
                f'<div style="font-size:11px;color:#484f58;margin-bottom:8px">Detected {age}</div>'
                f'{approve_btn}'
                f'<button class="scan-btn" onclick="navTo(\'inventory\')" '
                f'style="font-size:11px;color:#4F46E5;border-color:#4F46E5;margin-bottom:4px;display:block;width:100%">'
                f'&#128196; View in Inventory</button>'
                f'<button class="scan-btn" onclick="dismissShadow({sid})" '
                f'style="font-size:11px;color:#6e7681;border-color:#30363d;display:block;width:100%">'
                f'Dismiss (temp)</button>'
                f'</div></div></div>'
            )

        # Docker findings grouped by the host machine that reported them
        docker_groups: dict[str, list[dict]] = {}
        for d in docker_items:
            docker_groups.setdefault(d.get('reporter_hostname', 'unknown'), []).append(d)

        for reporter, items in docker_groups.items():
            latest_ts = max((i.get('last_seen') or 0) for i in items)
            cnt_label = f'{len(items)} container{"s" if len(items) != 1 else ""}'
            row_parts: list[str] = []
            for d in items:
                sid    = d.get('id', 0)
                port   = d.get('port', 0)
                svc    = d.get('service', 'Unknown AI service')
                detail = d.get('detail', '')
                models = d.get('models') or []
                age    = _age(d.get('last_seen'))
                model_html = _model_tags(models) if models else (
                    '<span style="font-size:11px;color:#484f58">No model details available</span>'
                )
                port_html   = (f'<span style="font-size:11px;color:#484f58;font-family:monospace">'
                               f':{port}</span>') if port else ''
                detail_html = (f'<span style="font-size:11px;color:#6e7681;font-family:monospace">'
                               f'{detail}</span>') if detail else ''
                row_parts.append(
                    f'<div style="background:#0d1117;border:1px solid #21262d;border-radius:6px;'
                    f'padding:10px 14px;margin-bottom:8px">'
                    f'<div style="display:flex;align-items:flex-start;justify-content:space-between;gap:8px">'
                    f'<div style="flex:1;min-width:0">'
                    f'<div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-bottom:5px">'
                    f'<span style="font-size:13px;color:#e6edf3;font-weight:600">{svc}</span>'
                    f'{detail_html}{port_html}'
                    f'</div>'
                    f'<div style="display:flex;flex-wrap:wrap;gap:4px;align-items:center">{model_html}</div>'
                    f'</div>'
                    f'<div style="text-align:right;flex-shrink:0;min-width:80px">'
                    f'<div style="font-size:11px;color:#484f58;margin-bottom:6px">{age}</div>'
                    f'<button class="scan-btn" onclick="dismissShadow({sid})" '
                    f'style="font-size:11px;color:#6e7681;border-color:#30363d">Dismiss</button>'
                    f'</div></div></div>'
                )
            card_parts.append(
                f'<div class="shadow-card" style="border-left-color:#3fb950;padding:0;overflow:hidden">'
                f'<div style="display:flex;align-items:center;gap:8px;padding:12px 14px 10px;'
                f'background:#0f1f14;border-bottom:1px solid #1a3020;margin-bottom:10px">'
                f'<span style="font-size:18px">&#128051;</span>'
                f'<span style="font-weight:700;color:#e6edf3;font-size:14px">{reporter}</span>'
                f'<span style="font-size:10px;font-weight:700;padding:1px 7px;border-radius:3px;'
                f'background:#1a3020;color:#3fb950;border:1px solid #3fb950;text-transform:uppercase">'
                f'Docker Host</span>'
                f'<span style="font-size:11px;color:#484f58;margin-left:auto">'
                f'{cnt_label} &nbsp;&middot;&nbsp; last seen {_age(latest_ts)}</span>'
                f'</div>'
                f'<div style="padding:0 14px 12px">{"".join(row_parts)}</div>'
                f'</div>'
            )

        cards = '\n'.join(card_parts)

    badge = (f'<span style="background:#2d1f47;color:#a371f7;border:1px solid #6e40c9;'
             f'border-radius:10px;font-size:11px;padding:1px 9px;font-weight:700;margin-left:8px">'
             f'{len(shadow)}</span>') if shadow else ''

    dismiss_all_btn = (
        '<button class="scan-btn" onclick="dismissAllShadow()" '
        'style="font-size:11px;color:#6e7681;border-color:#30363d;margin-left:8px">'
        'Dismiss All</button>'
    ) if shadow else ''

    return (f'<div id="shadow-section" style="margin-top:32px">'
            f'<div class="sec-hdr" style="display:flex;align-items:center;justify-content:space-between">'
            f'<span style="display:flex;align-items:center">Shadow AI — Detected AI Usage{badge}{dismiss_all_btn}</span>'
            f'<span style="font-size:11px;color:#6e7681;font-weight:400;text-transform:none;letter-spacing:0">'
            f'&#127760; Unmanaged device &nbsp;|&nbsp; &#9729; Cloud API key &nbsp;|&nbsp; &#9881; Running process &nbsp;|&nbsp; &#128051; Container'
            f'</span></div>'
            f'<div id="shadow-cards" style="margin-bottom:28px">{cards}</div>'
            f'</div>')


def _build_mcp_section(servers: list[dict], ts_now: int) -> str:
    _AUTH_META = {
        'none':     ('#f85149', 'No Auth',  'This MCP server accepts connections with no authentication — high risk'),
        'unknown':  ('#e3b341', 'Auth?',    'Authentication status could not be determined'),
        'required': ('#3fb950', 'Auth OK',  'Server requires authentication before accepting connections'),
        'process':  ('#58a6ff', 'Process',  'MCP server found running as a local process'),
    }

    def _age(ts: int | None) -> str:
        if not ts:
            return 'never'
        secs = ts_now - ts
        if secs < 120:   return f'{secs}s ago'
        if secs < 3600:  return f'{secs // 60}m ago'
        if secs < 86400: return f'{secs // 3600}h ago'
        return f'{secs // 86400}d ago'

    def _tool_tags(tools: list) -> str:
        shown = tools[:6]
        extra = len(tools) - 6
        tags = ' '.join(
            f'<span style="background:#0d1117;border:1px solid #30363d;border-radius:3px;'
            f'padding:1px 8px;font-size:11px;font-family:monospace;color:#c9d1d9">{t}</span>'
            for t in shown
        )
        if extra > 0:
            tags += f' <span style="font-size:11px;color:#6e7681">+{extra} more</span>'
        return tags

    if not servers:
        cards = ('<div class="empty" style="padding:20px;text-align:center;color:#484f58">'
                 'No MCP servers detected yet. Click <strong style="color:#58a6ff">Scan MCP Servers</strong> '
                 'above to scan your network through all installed agents.</div>')
    else:
        card_parts: list[str] = []
        for s in servers:
            sid          = s.get('id', 0)
            host         = s.get('host', '')
            port         = s.get('port', 0)
            server_name  = s.get('server_name', '')
            tools        = s.get('tools') or []
            auth_status  = s.get('auth_status', 'unknown')
            src          = s.get('source', 'network')
            process_info = s.get('process_info', '')
            reporter     = s.get('reporter_hostname', 'unknown')
            age          = _age(s.get('last_seen'))

            auth_color, auth_label, auth_desc = _AUTH_META.get(auth_status, _AUTH_META['unknown'])
            is_process = (src == 'process')

            if is_process:
                location_html = ('<span style="font-weight:700;color:#e6edf3;font-size:14px">'
                                 'MCP Server Process</span>')
                sub_html = (f'<span style="font-size:11px;color:#6e7681;font-family:monospace">'
                            f'{process_info[:80]}</span>') if process_info else ''
            else:
                display = server_name or 'MCP Server'
                location_html = (f'<span style="font-weight:700;color:#e6edf3;font-size:14px">'
                                 f'{host}:{port}</span>')
                sub_html = (f'<span style="font-size:12px;color:#58a6ff">{display}</span>')

            tool_html = _tool_tags(tools) if tools else (
                '<span style="font-size:11px;color:#484f58">No tools enumerated</span>'
            )

            risk_note = ''
            if auth_status == 'none':
                risk_note = ('<div style="font-size:11px;color:#f85149;margin-top:4px;font-weight:600">'
                             '&#9888; Unauthenticated — any AI agent can connect to this server</div>')

            card_parts.append(
                f'<div class="shadow-card" style="border-left-color:{auth_color}">'
                f'<div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px">'
                f'<div style="flex:1;min-width:0">'
                f'<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">'
                f'<span style="font-size:16px">&#128279;</span>'
                f'{location_html}'
                f'<span style="font-size:10px;font-weight:700;padding:1px 7px;border-radius:3px;'
                f'background:#1a1f2e;color:{auth_color};border:1px solid {auth_color};text-transform:uppercase">'
                f'{auth_label}</span>'
                f'<span style="font-size:10px;padding:1px 7px;border-radius:3px;'
                f'background:#0d1117;color:#6e7681;border:1px solid #30363d;text-transform:uppercase">'
                f'{"Process" if is_process else "Network"}</span>'
                f'</div>'
                f'<div style="margin-bottom:6px">{sub_html}</div>'
                f'<div style="display:flex;flex-wrap:wrap;gap:5px;align-items:center">{tool_html}</div>'
                f'{risk_note}'
                f'</div>'
                f'<div style="text-align:right;flex-shrink:0">'
                f'<div style="font-size:11px;color:#484f58;margin-bottom:3px">Found {age}</div>'
                f'<div style="font-size:11px;color:#6e7681;margin-bottom:8px">via {reporter}</div>'
                f'<button class="scan-btn" onclick="dismissMcp({sid})" '
                f'style="font-size:11px;color:#6e7681;border-color:#30363d">Dismiss</button>'
                f'</div></div></div>'
            )
        cards = '\n'.join(card_parts)

    badge = (f'<span style="background:#1a2035;color:#58a6ff;border:1px solid #1f6feb;'
             f'border-radius:10px;font-size:11px;padding:1px 9px;font-weight:700;margin-left:8px">'
             f'{len(servers)}</span>') if servers else ''

    no_auth_count = sum(1 for s in servers if s.get('auth_status') == 'none')
    risk_badge = (f'<span style="background:#3d1a1a;color:#f85149;border:1px solid #da3633;'
                  f'border-radius:10px;font-size:11px;padding:1px 9px;font-weight:700;margin-left:6px">'
                  f'&#9888; {no_auth_count} unauthenticated</span>') if no_auth_count else ''

    dismiss_all_btn = (
        '<button class="scan-btn" onclick="dismissAllMcp()" '
        'style="font-size:11px;color:#6e7681;border-color:#30363d;margin-left:8px">'
        'Dismiss All</button>'
    ) if servers else ''

    return (f'<div id="mcp-section" style="margin-top:32px">'
            f'<div class="sec-hdr" style="display:flex;align-items:center;justify-content:space-between">'
            f'<span style="display:flex;align-items:center">MCP &amp; Agent Governance{badge}{risk_badge}{dismiss_all_btn}</span>'
            f'<span style="font-size:11px;color:#6e7681;font-weight:400;text-transform:none;letter-spacing:0">'
            f'&#128279; MCP server discovered on network &nbsp;|&nbsp; &#9881; Running as local process'
            f'</span></div>'
            f'<div id="mcp-cards" style="margin-bottom:28px">{cards}</div>'
            f'</div>')


def send_client_org_report(customer_id: str, org_id: str, org_name: str, report_email: str) -> tuple[bool, str]:
    """Build a white-labeled fleet PDF scoped to one client org and email it
    to report_email. Called both by the daily scheduler tick (main()) and
    the manual 'Send Now' test endpoint — same code path either way, so a
    successful manual test is a real guarantee the scheduled version works.

    Returns (ok, message) rather than raising — callers (background thread,
    HTTP handler) both want a non-throwing result they can log or return
    as JSON.
    """
    try:
        store = _get_store(customer_id)
        devices = store.list_devices(client_org_id=org_id)
        for d in devices:
            d['_report'] = store.get_latest_report(d['device_id']) or {}

        try:
            branding_path = ROOT / 'data' / 'branding.json'
            branding = json.loads(branding_path.read_text()) if branding_path.exists() else {}
        except Exception:
            branding = {}

        from output.fleet_report import generate_fleet_pdf
        pdf_bytes = generate_fleet_pdf(devices, tier='ciso', client_name=org_name, branding=branding)

        from alerts import load_alert_config, send_email_with_attachment
        alert_cfg = load_alert_config(ROOT / 'data' / 'alerts_config.json') or {}
        email_cfg = alert_cfg.get('email', {})
        if not email_cfg.get('smtp_host') or not email_cfg.get('smtp_user'):
            return False, 'SMTP not configured (Settings -> SIEM & Tool Integrations -> Email)'

        msp_name = (branding.get('msp_name') or 'Arckon').strip()
        month = datetime.now(timezone.utc).strftime('%B %Y')
        subject = f'{msp_name} Security Report — {org_name} — {month}'
        body = (
            f'Attached is the {month} security report for {org_name}, prepared by {msp_name}.\n\n'
            f'{len(devices)} monitored device(s).\n\n'
            f'This report is generated automatically each month — no action needed unless '
            f'critical findings are listed inside.'
        )
        fname = f'{org_name.replace(" ", "_")}_security_report_{datetime.now(timezone.utc).strftime("%Y_%m")}.pdf'
        ok = send_email_with_attachment(email_cfg, report_email, subject, body, pdf_bytes, fname)
        return (True, 'sent') if ok else (False, 'SMTP send failed — check server logs')
    except Exception as e:
        log.error('send_client_org_report failed for org %s: %s', org_id, e, exc_info=True)
        return False, str(e)


def _build_fleet_html(devices: list[dict], shadow: list[dict] | None = None,
                      mcp: list[dict] | None = None,
                      network_assets: list[dict] | None = None,
                      current_user_email: str = '',
                      current_user_role: str = '',
                      current_user_is_reseller: bool = False,
                      current_user_is_msp: bool = False,
                      current_user_impersonated_by: str = '',
                      store=None) -> str:
    shadow = shadow or []
    mcp    = mcp    or []
    network_assets = network_assets or []
    ts_now = int(time.time())
    import html as _html

    def _age(ts: int | None) -> str:
        if not ts:
            return 'never'
        secs = ts_now - ts
        if secs < 120:
            return f'{secs}s ago'
        if secs < 3600:
            return f'{secs // 60}m ago'
        if secs < 86400:
            return f'{secs // 3600}h ago'
        return f'{secs // 86400}d ago'

    asset_rows = ''.join(
        '<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>'.format(
            _html.escape(a.get('ip_address', '')), _html.escape(a.get('mac_address', '') or '—'),
            _html.escape(a.get('hostname', '') or '—'), _html.escape(a.get('interface', '') or '—'),
            _html.escape(a.get('source', '')), _html.escape(a.get('reporter_hostname', '') or a.get('reporter_device_id', '')),
            _age(a.get('last_seen')),
        ) for a in network_assets)
    if not asset_rows:
        asset_rows = '<tr><td colspan="7" class="empty">No passive neighbor-cache observations yet.</td></tr>'
    asset_options = ''.join('<option value="{}">{}</option>'.format(
        _html.escape(d.get('device_id', ''), quote=True), _html.escape(d.get('hostname', '') or d.get('device_id', ''))
    ) for d in devices)

    def _risk_cls(fail: int, warn: int, pas: int) -> str:
        if fail == 0 and warn == 0 and pas == 0:
            return 'r-nodata'
        if fail > 0:
            return 'r-fail'
        if warn > 0:
            return 'r-warn'
        return 'r-pass'

    rows = ''
    for d in devices:
        fail = d.get('fail_count', 0) or 0
        warn = d.get('warn_count', 0) or 0
        pas  = d.get('pass_count', 0) or 0
        age  = _age(d.get('last_seen'))
        no_data = (fail == 0 and warn == 0 and pas == 0)
        rc   = _risk_cls(fail, warn, pas)
        did  = d.get('device_id', '')
        hostname = d.get('hostname', 'unknown')
        profile  = d.get('profile', '') or ('kubernetes' if hostname.startswith('k8s:') else '')
        rows += f"""
        <tr class="dev-row" onclick="selectDevice('{did}')">
          <td class="dev-host">{hostname}</td>
          <td>{d.get('platform','')}</td>
          <td class="c-red">{fail if not no_data else '—'}</td>
          <td class="c-yellow">{warn if not no_data else '—'}</td>
          <td class="c-green">{pas if not no_data else '—'}</td>
          <td>{profile}</td>
          <td>{age}</td>
          <td><span class="risk-dot {rc}" title="{'No scan data yet' if no_data else ''}"></span></td>
          <td onclick="event.stopPropagation()" style="white-space:nowrap">
            <button class="scan-btn" id="sb-{did}" onclick="openScanModal('{did}',this)">Scan ▾</button>
            <button class="scan-btn" id="ub-{did}" onclick="updateDevice('{did}')"
                    style="margin-left:4px;color:#CA8A04;border-color:#D1D5DB">Update</button>
            <a href="/fleet/device/{did}/dashboard" target="_blank"
               style="margin-left:8px;background:#fff;border:1px solid #D1D5DB;color:#6B7280;
                      border-radius:6px;padding:3px 10px;font-size:12px;text-decoration:none;
                      display:inline-block;white-space:nowrap;font-weight:500"
               onmouseover="this.style.borderColor='#4F46E5';this.style.color='#4F46E5'"
               onmouseout="this.style.borderColor='#D1D5DB';this.style.color='#6B7280'">Full Report</a>
            <button class="scan-btn" onclick="removeDevice('{did}','{d.get('hostname','')}')"
                    style="margin-left:4px;color:#f85149;border-color:#30363d;font-size:11px">Remove</button>
          </td>
        </tr>"""

    if not rows:
        rows = '<tr><td colspan="8" style="text-align:center;padding:32px;color:#484f58">No agents have reported yet.</td></tr>'

    total_fail = sum((d.get('fail_count') or 0) for d in devices)
    total_warn = sum((d.get('warn_count') or 0) for d in devices)
    total_pass = sum((d.get('pass_count') or 0) for d in devices)

    # Severity-based counts for stat cards (one query, all devices)
    _dash_ch = _dash_med = _dash_li = 0
    try:
        for _rpt in (store or _get_store()).get_all_latest_reports():
            _rjson = _rpt if isinstance(_rpt, dict) else {}
            for _f in _rjson.get('findings', _rjson.get('results', [])):
                if _f.get('status') == 'SKIP':
                    continue
                _sev = _f.get('severity', 'INFO')
                if _sev in ('CRITICAL', 'HIGH'):
                    _dash_ch += 1
                elif _sev == 'MEDIUM':
                    _dash_med += 1
                else:
                    _dash_li += 1
    except Exception:
        _dash_ch, _dash_med, _dash_li = total_fail, total_warn, total_pass

    _btn_technical_report = (
        '<button onclick="openReport(\'technical\')" class="scan-btn"'
        ' style="color:#8b949e;border-color:#30363d;font-size:12px">&#9654; Technical Report</button>'
        if _has_technical_reports() else
        '<button disabled title="Technical Reports + Remediation require a Plus license"'
        ' class="scan-btn" style="color:#484f58;border-color:#21262d;font-size:12px;cursor:default">'
        '&#128274; Technical (Plus)</button>'
    )
    _btn_technical_pdf = (
        '<button class="scan-btn" onclick="rptDownloadPdf(\'technical\',this)"'
        ' style="color:#3fb950;border-color:#238636;font-size:12px">&#8659; Download PDF</button>'
        '<button class="scan-btn" onclick="rptPreview(\'technical\')"'
        ' style="color:#8b949e;font-size:12px">&#128065; Preview</button>'
        if _has_technical_reports() else
        '<button disabled class="scan-btn" style="color:#484f58;border-color:#21262d;font-size:12px;cursor:default">'
        '&#128274; Plus Plan Required</button>'
        '<div style="font-size:11px;color:#484f58;margin-top:8px">Contact sales@markai.io to upgrade</div>'
    )
    _btn_mcp_technical = (
        '<button class="scan-btn" onclick="rptDownloadMcpPdf(\'technical\',this)"'
        ' style="color:#3fb950;border-color:#238636;font-size:12px">&#8659; Download PDF</button>'
        '<button class="scan-btn" onclick="rptPreviewMcp(\'technical\')"'
        ' style="color:#8b949e;font-size:12px">&#128065; Preview</button>'
        if _has_technical_reports() else
        '<button disabled class="scan-btn" style="color:#484f58;border-color:#21262d;font-size:12px;cursor:default">'
        '&#128274; Plus Plan Required</button>'
        '<div style="font-size:11px;color:#484f58;margin-top:8px">Contact sales@markai.io to upgrade</div>'
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Arckon — Command Center</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#F9FAFB;color:#111827;font-family:ui-sans-serif,system-ui,sans-serif,"Apple Color Emoji","Segoe UI Emoji";font-size:15px;height:100vh;overflow:hidden}}
#app{{display:flex;height:100vh;overflow:hidden}}
#sidebar{{width:240px;flex-shrink:0;background:#111827;border-right:1px solid rgba(255,255,255,0.06);display:flex;flex-direction:column;height:100vh;overflow-y:auto}}
#main{{flex:1;overflow-y:auto;padding:28px 36px;min-width:0;background:#F9FAFB}}
.sb-logo{{padding:20px 16px 16px;border-bottom:1px solid rgba(255,255,255,0.07)}}
.sb-logo-mark{{font-size:9px;letter-spacing:3px;color:#6366F1;font-weight:700;text-transform:uppercase}}
.sb-logo-name{{font-size:15px;font-weight:800;color:#F9FAFB;letter-spacing:.5px;line-height:1.2;margin-top:3px}}
.sb-logo-sub{{font-size:10px;color:#6B7280;margin-top:2px}}
.sb-nav{{flex:1;padding:8px 0}}
.sb-group{{font-size:10px;font-weight:700;letter-spacing:.15em;text-transform:uppercase;color:#6B7280;padding:12px 16px 5px}}
.sb-item{{display:block;width:100%;padding:8px 16px;font-size:14px;color:#D1D5DB;cursor:pointer;text-decoration:none;user-select:none;border:none;border-left:2px solid transparent;background:none;text-align:left;transition:background .12s,color .12s}}
.sb-item:hover{{color:#F9FAFB;background:rgba(255,255,255,0.06)}}
.sb-item.sb-active{{color:#fff;background:#4F46E5;border-left-color:#4F46E5}}
.sb-footer{{padding:14px 16px;border-top:1px solid rgba(255,255,255,0.07);display:flex;flex-direction:column;gap:7px}}
.sb-footer a{{font-size:11px;color:#6B7280;text-decoration:none}}
.sb-footer a:hover{{color:#D1D5DB}}
.page{{display:none}}
.page.active{{display:block}}
#kpi-bar{{margin-bottom:20px}}
.brand-bar{{display:flex;align-items:baseline;gap:14px;margin-bottom:24px;border-bottom:1px solid #E5E7EB;padding-bottom:16px}}
.brand-mark{{font-size:10px;letter-spacing:3px;color:#4F46E5;font-weight:700;text-transform:uppercase}}
.brand-name{{font-size:24px;font-weight:700;color:#111827}}
.brand-sub{{font-size:12px;color:#9CA3AF}}
.hlink{{margin-left:auto;font-size:12px;color:#4F46E5;text-decoration:none}}
.hlink:hover{{text-decoration:underline}}
.stat-row{{display:flex;gap:12px;margin-bottom:24px;flex-wrap:wrap}}
.scard{{background:#fff;border:1px solid #E5E7EB;border-radius:8px;padding:16px 20px;min-width:110px;text-align:center;cursor:pointer;transition:border-color .15s,box-shadow .15s;user-select:none;box-shadow:0 1px 3px rgba(0,0,0,0.06)}}
.scard:hover{{border-color:#C7D2FE;box-shadow:0 2px 6px rgba(79,70,229,0.1)}}
.scard.sf-active{{border-color:#4F46E5;box-shadow:0 0 0 3px rgba(79,70,229,0.12)}}
.scard.sf-active-red{{border-color:#DC2626;box-shadow:0 0 0 3px rgba(220,38,38,0.1)}}
.scard.sf-active-yellow{{border-color:#CA8A04;box-shadow:0 0 0 3px rgba(202,138,4,0.1)}}
.scard.sf-active-green{{border-color:#16A34A;box-shadow:0 0 0 3px rgba(22,163,74,0.1)}}
.scard-n{{font-size:30px;font-weight:700;line-height:1;color:#111827}}
.scard-l{{font-size:11px;color:#6B7280;margin-top:5px;text-transform:uppercase;letter-spacing:.06em;font-weight:500}}
.c-red{{color:#DC2626}}.c-yellow{{color:#CA8A04}}.c-green{{color:#16A34A}}.c-blue{{color:#2563EB}}.c-gray{{color:#6B7280}}
.sec-hdr{{font-size:13px;font-weight:600;color:#374151;margin-bottom:12px;display:flex;align-items:center;gap:8px}}
.dev-table{{width:100%;border-collapse:collapse;margin-bottom:24px;background:#fff;border-radius:8px;overflow:hidden;border:1px solid #E5E7EB;box-shadow:0 1px 3px rgba(0,0,0,0.06)}}
.dev-table th{{background:#F9FAFB;color:#6B7280;font-size:13px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;padding:10px 14px;text-align:left;border-bottom:1px solid #E5E7EB}}
.dev-table td{{padding:12px 14px;border-bottom:1px solid #F3F4F6;font-size:15px;color:#374151}}
.dev-row{{cursor:pointer;transition:background .1s}}
.dev-row:hover td{{background:#F5F3FF}}
.dev-host{{font-weight:600;color:#111827}}
.risk-dot{{display:inline-block;width:10px;height:10px;border-radius:50%}}
.risk-dot.r-fail{{background:#DC2626}}.risk-dot.r-warn{{background:#F97316}}.risk-dot.r-pass{{background:#16A34A}}.risk-dot.r-nodata{{background:#D1D5DB;border:1px solid #9CA3AF}}
.scan-btn{{background:#fff;border:1px solid #D1D5DB;color:#4F46E5;border-radius:6px;padding:4px 10px;font-size:12px;cursor:pointer;white-space:nowrap;font-family:inherit;font-weight:500;transition:background .1s,border-color .1s}}
.scan-btn:hover{{background:#EEF2FF;border-color:#4F46E5}}
.scan-btn:disabled{{color:#9CA3AF;border-color:#E5E7EB;cursor:default;background:#F9FAFB}}
.rr-fil{{background:#fff;border:1px solid #D1D5DB;color:#6B7280;border-radius:6px;padding:3px 12px;font-size:12px;cursor:pointer;font-family:inherit}}
.rr-fil.rr-active{{color:#4F46E5;border-color:#4F46E5;background:#EEF2FF}}
.rr-table{{width:100%;border-collapse:collapse;margin-bottom:8px;font-size:14px}}
.rr-table th{{background:#F9FAFB;color:#6B7280;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.05em;padding:8px 12px;text-align:left;border-bottom:1px solid #E5E7EB}}
.rr-table td{{padding:9px 12px;border-bottom:1px solid #F3F4F6;vertical-align:middle}}
.rr-new{{background:#DCFCE7;color:#16A34A;border:1px solid #BBF7D0;border-radius:10px;padding:2px 8px;font-size:11px;font-weight:600}}
.rr-recurring{{background:#FEF9C3;color:#CA8A04;border:1px solid #FDE047;border-radius:10px;padding:2px 8px;font-size:11px;font-weight:600}}
.rr-accepted{{background:#F3F4F6;color:#9CA3AF;border:1px solid #E5E7EB;border-radius:10px;padding:2px 8px;font-size:11px;font-weight:600}}
.rr-assigned{{background:#EFF6FF;color:#2563EB;border:1px solid #BFDBFE;border-radius:10px;padding:2px 8px;font-size:11px;font-weight:600}}
.rr-act-btn{{background:none;border:1px solid #D1D5DB;border-radius:4px;color:#6B7280;font-size:11px;padding:2px 7px;cursor:pointer;font-family:inherit;margin-right:3px}}
.rr-act-btn:hover{{background:#F3F4F6;color:#111827}}
.rr-form-row{{background:#F9FAFB;border-bottom:1px solid #E5E7EB}}
.rr-form-row td{{padding:12px 12px}}
.rr-input{{background:#fff;border:1px solid #D1D5DB;border-radius:4px;padding:5px 8px;font-size:13px;font-family:inherit;width:100%;box-sizing:border-box}}
.rr-input:focus{{outline:none;border-color:#4F46E5}}
.rr-save-btn{{background:#238636;color:#fff;border:none;border-radius:4px;padding:5px 14px;font-size:12px;cursor:pointer;font-weight:600}}
.rr-save-btn:hover{{background:#2ea043}}
.rr-clear-btn{{background:none;border:1px solid #D1D5DB;border-radius:4px;color:#6B7280;font-size:12px;padding:5px 10px;cursor:pointer;font-family:inherit;margin-left:6px}}
.rr-row-accepted td{{opacity:0.6}}
.rr-row-fp td{{opacity:0.5;text-decoration:line-through;text-decoration-color:#9CA3AF}}
.rr-fp{{background:#F3F4F6;color:#6B7280;border:1px solid #E5E7EB;border-radius:10px;padding:2px 8px;font-size:11px;font-weight:600}}
.inv-badge-approved{{background:#DCFCE7;color:#16A34A;border:1px solid #BBF7D0;border-radius:10px;padding:2px 8px;font-size:11px;font-weight:600}}
.inv-badge-review{{background:#FEF9C3;color:#CA8A04;border:1px solid #FDE047;border-radius:10px;padding:2px 8px;font-size:11px;font-weight:600}}
.inv-badge-unapp{{background:#FEE2E2;color:#DC2626;border:1px solid #FECACA;border-radius:10px;padding:2px 8px;font-size:11px;font-weight:600}}
.inv-action{{background:#fff;border:1px solid #D1D5DB;border-radius:4px;padding:2px 8px;font-size:11px;cursor:pointer;color:#6B7280;font-family:inherit}}
.inv-action:hover{{color:#111827;border-color:#4F46E5}}
.inv-count-card{{background:#fff;border:1px solid #E5E7EB;border-radius:6px;padding:10px 18px;font-size:12px;display:flex;flex-direction:column;gap:2px;box-shadow:0 1px 2px rgba(0,0,0,0.05)}}
.inv-count-n{{font-size:22px;font-weight:700;color:#111827}}
#detail-panel{{background:#fff;border:1px solid #E5E7EB;border-radius:8px;padding:22px;min-height:200px;box-shadow:0 1px 3px rgba(0,0,0,0.06)}}
.detail-hdr{{display:flex;align-items:center;gap:12px;margin-bottom:18px}}
.detail-host{{font-size:18px;font-weight:700;color:#111827}}
.detail-meta{{font-size:12px;color:#6B7280}}
.finding{{background:#fff;border:1px solid #E5E7EB;border-radius:6px;margin-bottom:6px;overflow:hidden}}
.fhdr{{display:flex;align-items:center;gap:10px;padding:10px 14px;cursor:pointer;transition:background .1s}}
.fhdr:hover{{background:#F9FAFB}}
.find-ind{{width:3px;height:28px;border-radius:2px;flex-shrink:0}}
.find-ind.critical,.find-ind.fail{{background:#DC2626}}
.find-ind.high{{background:#F97316}}.find-ind.medium{{background:#EAB308}}
.find-ind.pass{{background:#60A5FA}}.find-ind.warn{{background:#EAB308}}.find-ind.skip{{background:#D1D5DB}}
.sev-badge,.stat-badge{{font-size:10px;font-weight:700;padding:2px 7px;border-radius:3px;text-transform:uppercase;flex-shrink:0}}
.sev-badge.critical{{background:#FEE2E2;color:#DC2626;border:1px solid #FECACA}}
.sev-badge.high{{background:#FFF7ED;color:#F97316;border:1px solid #FED7AA}}
.sev-badge.medium{{background:#FEFCE8;color:#CA8A04;border:1px solid #FEF08A}}
.sev-badge.low{{background:#EFF6FF;color:#2563EB;border:1px solid #BFDBFE}}
.stat-badge.fail{{background:#FEE2E2;color:#DC2626}}
.stat-badge.warn{{background:#FEFCE8;color:#CA8A04}}
.stat-badge.pass{{background:#EFF6FF;color:#2563EB}}
.stat-badge.skip{{background:#F3F4F6;color:#6B7280}}
.find-id{{font-size:11px;color:#9CA3AF;font-family:monospace;flex-shrink:0}}
.find-title{{font-size:13px;font-weight:500;color:#111827;flex:1}}
.find-chev{{color:#9CA3AF;font-size:11px;transition:transform .2s;flex-shrink:0}}
.finding.open .find-chev{{transform:rotate(90deg)}}
.fbody{{display:none;padding:4px 14px 14px;border-top:1px solid #F3F4F6;color:#6B7280;font-size:13px;line-height:1.7}}
.finding.open .fbody{{display:block}}
.empty{{text-align:center;padding:48px;color:#9CA3AF}}
.refresh-note{{font-size:11px;color:#9CA3AF;text-align:right;margin-bottom:8px}}
.shadow-card{{background:#fff;border:1px solid #E5E7EB;border-left:3px solid #7C3AED;border-radius:6px;padding:14px 16px;margin-bottom:8px;box-shadow:0 1px 2px rgba(0,0,0,0.05)}}
.shadow-card:hover{{background:#FAFAFA}}
::-webkit-scrollbar{{width:6px}}::-webkit-scrollbar-track{{background:#F3F4F6}}
::-webkit-scrollbar-thumb{{background:#D1D5DB;border-radius:3px}}
</style>
</head>
<body>
<script>if(localStorage.getItem('sentinel_theme')==='dark')document.documentElement.classList.add('dark');</script>
<div id="maintenance-banner" style="display:none;background:#4a3b0d;border-bottom:1px solid #d29922;color:#d29922;padding:10px 20px;font-size:13px;text-align:center;position:relative;z-index:1000"></div>
{f'<div id="impersonation-banner" style="background:#4a1d0d;border-bottom:1px solid #d97706;color:#fbbf24;padding:10px 20px;font-size:13px;text-align:center;position:relative;z-index:1000">Support session — logged in as <strong>{current_user_impersonated_by}</strong>&nbsp;&nbsp;<button onclick="endImpersonation()" style="background:#d97706;color:#1a1400;border:none;padding:4px 12px;border-radius:4px;cursor:pointer;font-size:12px;font-weight:600">Return to my account</button></div>' if current_user_impersonated_by else ''}
<div id="app">
  <aside id="sidebar">
    <div class="sb-logo">
      <div class="sb-logo-name">ARCKON</div>
      <div class="sb-logo-sub">{'<span style="color:#f0a500;font-weight:700;font-size:9px;letter-spacing:1px">⚠ DEMO MODE</span>' if _is_demo() else '<span style="color:#6366F1;font-size:9px;letter-spacing:1px;font-weight:700">by RiskRaven</span> &nbsp;·&nbsp; Command Center'}</div>
    </div>
    <nav class="sb-nav">
      <div class="sb-group">Overview</div>
      <button class="sb-item sb-active" id="nav-overview" onclick="navTo('overview')">&#8962; Home</button>
      {'<button class="sb-item" id="nav-clients" onclick="window.location=\'/clients\'">&#127970; Clients</button>' if current_user_is_msp else ''}
      {'<button class="sb-item" id="nav-reseller" onclick="navTo(\'reseller\')">&#127970; MSP View</button>' if current_user_is_reseller else ''}
      <div class="sb-group">Fleet</div>
      <button class="sb-item" id="nav-shadow" onclick="navTo('shadow')">&#9888; Shadow AI</button>
      <button class="sb-item" id="nav-inventory" onclick="navTo('inventory')">&#129302; AI Asset Inventory</button>
      <button class="sb-item" id="nav-spend" onclick="navTo('spend')">&#128176; AI Spend</button>
      <button class="sb-item" id="nav-alerts" onclick="navTo('alerts')">&#128276; Alerts <span id="alert-badge" style="display:none;background:#DC2626;color:#fff;border-radius:10px;font-size:10px;padding:1px 6px;margin-left:4px;font-weight:700"></span></button>
      <button class="sb-item" id="nav-mcp" onclick="navTo('mcp')">&#128279; MCP Servers</button>
      <div class="sb-group">Security</div>
      <button class="sb-item" id="nav-riskregister" onclick="navTo('riskregister')">&#128203; Risk Register</button>
      <div class="sb-group">Operations</div>
      <button class="sb-item" id="nav-schedules" onclick="navTo('schedules')">&#128337; Schedules</button>
      <button class="sb-item" id="nav-discovery" onclick="navTo('discovery')">&#128270; Discovery</button>
      <div class="sb-group">Device</div>
      <button class="sb-item" id="nav-findings" onclick="navTo('findings')">&#128202; Findings</button>
      <div class="sb-group">Export</div>
      <button class="sb-item" id="nav-reports" onclick="navTo('reports')">&#128196; Reports</button>
      <div class="sb-group">Integrations</div>
      <button class="sb-item" id="nav-siem" onclick="navTo('siem')">&#128279; SIEM &amp; Tools</button>
      <div class="sb-group"></div>
      <button class="sb-item" id="nav-settings" onclick="navTo('settings')">&#9881; Settings</button>
      <button class="sb-item" id="nav-users" onclick="navTo('users')">&#128100; Users</button>
      {("<button class=\"sb-item\" id=\"nav-probe\" onclick=\"navTo('probe')\">&#128272; API Tester</button>") if _has_live_scan() else "<span style=\"display:block;padding:8px 16px;font-size:13px;color:#6B7280;cursor:default\" title=\"Upgrade to Pro to access the API Tester\">&#128274; API Tester</span>"}
    </nav>
    <div class="sb-footer">
      {f'<span style="font-size:11px;color:#9CA3AF;word-break:break-all">{current_user_email}</span>' if current_user_email else ''}
      <a href="/academy" target="_blank">Academy</a>
      <a href="/logout" style="color:#ef4444">&#x2192; Sign Out</a>
    </div>
  </aside>
  <div id="main">

  <div class="stat-row">
    <div class="scard" id="sf-all" onclick="window.open('/','_blank')" title="Open all devices in new tab">
      <div class="scard-n c-blue" id="sc-count">{len(devices)}</div><div class="scard-l">Devices</div></div>
    <div class="scard" id="sf-fail" onclick="window.open('/api/fleet/report?tier=ciso&amp;sev=ch&amp;fmt=html','_blank')" title="View Critical &amp; High severity findings only">
      <div class="scard-n c-red" id="sc-fail">{_dash_ch}</div><div class="scard-l">Critical / High</div></div>
    <div class="scard" id="sf-warn" onclick="window.open('/api/fleet/report?tier=ciso&amp;sev=med&amp;fmt=html','_blank')" title="View Medium severity findings only">
      <div class="scard-n c-yellow" id="sc-warn">{_dash_med}</div><div class="scard-l">Medium</div></div>
    <div class="scard" id="sf-pass" onclick="window.open('/api/fleet/report?tier=ciso&amp;sev=li&amp;fmt=html','_blank')" title="View Low and Informational findings only">
      <div class="scard-n c-blue" id="sc-pass">{_dash_li}</div><div class="scard-l">Low / Info</div></div>
    <div class="scard" id="sf-shadow" onclick="document.getElementById('shadow-section').scrollIntoView({{behavior:'smooth'}})" title="Unmanaged AI devices discovered on your network — click to view">
      <div class="scard-n" id="sc-shadow" style="color:#a371f7">{len(shadow)}</div><div class="scard-l">Shadow AI</div></div>
    <div class="scard" id="sf-mcp" onclick="window.open('/api/fleet/mcp/report?tier=ciso','_blank')" title="MCP servers and AI agent tool call exposure — click to open report">
      <div class="scard-n" id="sc-mcp" style="color:#4F46E5">{len(mcp)}</div><div class="scard-l">MCP Servers</div></div>
  </div>

  <div class="page active" id="page-overview">
  <div id="filter-banner" style="display:none;background:#ffffff;border:1px solid #E5E7EB;border-radius:6px;padding:10px 18px;margin-bottom:18px;align-items:center;justify-content:space-between;gap:12px">
    <span id="filter-banner-text" style="font-size:13px;font-weight:600"></span>
    <a href="/" style="font-size:12px;color:#6B7280;text-decoration:none;white-space:nowrap;flex-shrink:0">&#8592; All devices</a>
  </div>

  <div class="sec-hdr" style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px">
    <span>Connected Devices</span>
    <span id="filter-badge" style="display:none;font-size:11px;background:#EEF2FF;color:#4F46E5;border:1px solid #E5E7EB;border-radius:10px;padding:2px 10px;cursor:pointer" onclick="filterBy(null)" title="Clear filter">&#10005; clear filter</span>
    <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
      <button onclick="openReport('executive')" class="scan-btn"
         style="color:#16A34A;border-color:#E5E7EB;font-size:12px">&#9654; Executive Report</button>
      <button onclick="openReport('ciso')" class="scan-btn"
         style="color:#4F46E5;border-color:#E5E7EB;font-size:12px">&#9654; CISO Report</button>
      {_btn_technical_report}
      {'<button id="btn-evidence-export" class="scan-btn" onclick="downloadEvidencePackage(this)" style="color:#a371f7;border-color:#E5E7EB;font-size:12px">&#8659; Evidence Package</button>' if _has_evidence_package() else '<button disabled title="Evidence Package requires a Plus license" class="scan-btn" style="color:#9CA3AF;border-color:#F3F4F6;font-size:12px;cursor:default">&#128274; Evidence Pkg (Plus)</button>'}
      <div style="position:relative;display:inline-block">
        <button id="scan-profile-btn" onclick="toggleScanProfileMenu(event)" class="form-select" style="font-size:12px;padding:3px 10px;height:28px;cursor:pointer;min-width:160px;text-align:left;background:#fff">Customer default &#9660;</button>
        <div id="scan-profile-menu" style="display:none;position:absolute;top:31px;left:0;z-index:200;background:#fff;border:1px solid #E5E7EB;border-radius:6px;box-shadow:0 4px 16px rgba(0,0,0,0.12);padding:8px 12px;min-width:240px">
          <div style="font-size:10px;color:#9CA3AF;font-weight:600;text-transform:uppercase;letter-spacing:.06em;margin-bottom:6px">Optional one-time override</div>
          <div style="font-size:11px;color:#6B7280;margin-bottom:6px">Leave clear to run each device's customer default.</div>
          <label style="display:flex;align-items:center;gap:8px;font-size:13px;color:#111827;padding:3px 0;cursor:pointer"><input type="checkbox" class="scan-profile-cb" value="default" onchange="updateScanProfileBtn()"> Base Scan</label>
          <label style="display:flex;align-items:center;gap:8px;font-size:13px;color:#111827;padding:3px 0;cursor:pointer"><input type="checkbox" class="scan-profile-cb" value="iso42001" onchange="updateScanProfileBtn()"> ISO 42001</label>
          <label style="display:flex;align-items:center;gap:8px;font-size:13px;color:#111827;padding:3px 0;cursor:pointer"><input type="checkbox" class="scan-profile-cb" value="atlas" onchange="updateScanProfileBtn()"> MITRE ATLAS</label>
          <label style="display:flex;align-items:center;gap:8px;font-size:13px;color:#111827;padding:3px 0;cursor:pointer"><input type="checkbox" class="scan-profile-cb" value="professional_services" onchange="updateScanProfileBtn()"> Professional Services</label>
          <label style="display:flex;align-items:center;gap:8px;font-size:13px;color:#111827;padding:3px 0;cursor:pointer"><input type="checkbox" class="scan-profile-cb" value="financial" onchange="updateScanProfileBtn()"> Financial Services</label>
          <label style="display:flex;align-items:center;gap:8px;font-size:13px;color:#111827;padding:3px 0;cursor:pointer"><input type="checkbox" class="scan-profile-cb" value="fedramp" onchange="updateScanProfileBtn()"> FedRAMP / NIST 800-53</label>
          <label style="display:flex;align-items:center;gap:8px;font-size:13px;color:#111827;padding:3px 0;cursor:pointer"><input type="checkbox" class="scan-profile-cb" value="fedramp_20x" onchange="updateScanProfileBtn()"> FedRAMP 20x (KSI)</label>
          <label style="display:flex;align-items:center;gap:8px;font-size:13px;color:#111827;padding:3px 0;cursor:pointer"><input type="checkbox" class="scan-profile-cb" value="cmmc" onchange="updateScanProfileBtn()"> CMMC 2.0</label>
          <label style="display:flex;align-items:center;gap:8px;font-size:13px;color:#111827;padding:3px 0;cursor:pointer"><input type="checkbox" class="scan-profile-cb" value="healthcare" onchange="updateScanProfileBtn()"> Healthcare</label>
          <label style="display:flex;align-items:center;gap:8px;font-size:13px;color:#111827;padding:3px 0;cursor:pointer"><input type="checkbox" class="scan-profile-cb" value="biotech" onchange="updateScanProfileBtn()"> Biotech</label>
          <label style="display:flex;align-items:center;gap:8px;font-size:13px;color:#111827;padding:3px 0;cursor:pointer"><input type="checkbox" class="scan-profile-cb" value="owasp_agentic" onchange="updateScanProfileBtn()"> OWASP Agentic AI</label>
          <label style="display:flex;align-items:center;gap:8px;font-size:13px;color:#111827;padding:3px 0;cursor:pointer"><input type="checkbox" class="scan-profile-cb" value="eu_ai_act" onchange="updateScanProfileBtn()"> EU AI Act</label>
          <label style="display:flex;align-items:center;gap:8px;font-size:13px;color:#111827;padding:3px 0;cursor:pointer"><input type="checkbox" class="scan-profile-cb" value="kubernetes" onchange="updateScanProfileBtn()"> Kubernetes</label>
          <label style="display:flex;align-items:center;gap:8px;font-size:13px;color:#111827;padding:3px 0;cursor:pointer"><input type="checkbox" class="scan-profile-cb" value="docker" onchange="updateScanProfileBtn()"> Docker</label>
        </div>
      </div>
      <select id="scan-all-stagger" class="form-select" style="font-size:12px;padding:3px 6px;height:28px" title="Scan stagger — spread scans over time to avoid network spikes">
        <option value="normal">Normal (25/30s)</option>
        <option value="slow">Slow (10/60s)</option>
        <option value="instant">Instant</option>
      </select>
      <button id="btn-scan-all" class="scan-btn" onclick="scanAllDevices(this)"
              style="color:#F97316;border-color:#E5E7EB;font-size:12px">&#9654;&#9654; Scan All</button>
      <button class="scan-btn" onclick="updateAllDevices()"
              style="color:#CA8A04;border-color:#E5E7EB;font-size:12px">Update All Agents</button>
      <button id="btn-discover-all" class="scan-btn" onclick="discoverAll(this)"
              style="color:#a371f7;border-color:#E5E7EB;font-size:12px">&#128270; Find Shadow AI</button>
      <button id="btn-discover-mcp" class="scan-btn" onclick="discoverMcp(this)"
              style="color:#4F46E5;border-color:#E5E7EB;font-size:12px">&#128279; Scan MCP Servers</button>
    </div>
  </div>
  <div class="refresh-note" id="refresh-note">Auto-refreshes every 60s</div>
  <table class="dev-table">
    <thead><tr>
      <th>Hostname</th><th>Platform</th>
      <th class="c-red">High</th><th class="c-yellow">Medium</th><th class="c-green">Low</th>
      <th>Profile</th><th>Last seen</th><th>Risk</th><th></th>
    </tr></thead>
    <tbody id="device-tbody">{rows}</tbody>
  </table>
  <div id="device-pagination" style="display:none;align-items:center;justify-content:space-between;padding:10px 2px 4px;font-size:13px;color:#6B7280;flex-wrap:wrap;gap:8px">
    <div style="display:flex;align-items:center;gap:8px">
      <span>Show</span>
      <select id="page-size-sel" onchange="changePageSize(+this.value)"
              style="background:#ffffff;border:1px solid #E5E7EB;color:#374151;border-radius:4px;padding:2px 8px;font-size:12px;cursor:pointer">
        <option value="10" selected>10</option>
        <option value="25">25</option>
        <option value="50">50</option>
        <option value="100">100</option>
      </select>
      <span id="page-info" style="color:#6B7280"></span>
    </div>
    <div id="page-btns" style="display:flex;gap:4px;align-items:center;flex-wrap:wrap"></div>
  </div>

  </div>

  <div class="page" id="page-shadow">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:8px">
    <div>
      <div class="sec-hdr" style="margin:0;padding:0;display:flex;align-items:center;gap:10px">Shadow AI
    <a href="/api/fleet/shadow/csv" download style="font-size:12px;color:#16A34A;text-decoration:none;border:1px solid #238636;border-radius:4px;padding:3px 10px;font-weight:400;margin-left:auto">&#8659; Export CSV</a>
  </div>
      <div style="font-size:12px;color:#6B7280;margin-top:4px">Unmanaged AI devices and services detected on your network</div>
    </div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
      <input id="discover-subnets-shadow" type="text" placeholder="Subnets (auto-detect if blank)"
        style="width:240px;background:#F9FAFB;border:1px solid #E5E7EB;border-radius:4px;color:#111827;font-size:12px;font-family:monospace;padding:5px 10px;outline:none" />
      <button id="btn-discover-all" class="scan-btn" onclick="discoverAll(this)"
              style="color:#a371f7;border-color:#6e40c9;font-size:12px">&#128270; Run Shadow AI Scan</button>
    </div>
  </div>
  {_build_shadow_section(shadow, ts_now)}
  </div>

  <div class="page" id="page-alerts">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:8px">
    <div>
      <div class="sec-hdr" style="margin:0;padding:0">Alerts</div>
      <div style="font-size:12px;color:#9CA3AF;margin-top:2px">Active critical/high issues across your fleet, plus event history for new discoveries.</div>
    </div>
    <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
      <button id="alerts-refresh-btn" class="scan-btn" onclick="refreshAlertsPage(this)" style="font-size:12px;color:#4F46E5;border-color:#E5E7EB">&#8635; Refresh</button>
    </div>
  </div>

  <div style="margin-bottom:20px">
    <div style="font-size:12px;font-weight:600;color:#374151;text-transform:uppercase;letter-spacing:.05em;margin-bottom:8px">Active Issues</div>
    <div id="active-issues-feed" style="display:flex;flex-direction:column;gap:6px">
      <div style="color:#9CA3AF;font-size:13px;padding:12px 0">Loading…</div>
    </div>
  </div>

  <div style="border-top:1px solid #F3F4F6;padding-top:16px">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;flex-wrap:wrap;gap:6px">
      <div style="font-size:12px;font-weight:600;color:#374151;text-transform:uppercase;letter-spacing:.05em">Alert History</div>
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <label style="font-size:12px;color:#6B7280;display:flex;align-items:center;gap:6px;cursor:pointer">
          <input type="checkbox" id="alerts-unreviewed-only" onchange="loadAlertEvents()"> Unreviewed only
        </label>
        <button class="scan-btn" onclick="markAllAlertsReviewed()" style="font-size:12px;color:#6B7280;border-color:#E5E7EB">Mark all reviewed</button>
      </div>
    </div>
    <div id="alerts-feed" style="display:flex;flex-direction:column;gap:8px"></div>
  </div>
  </div>

  <div class="page" id="page-mcp">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:8px">
    <div>
      <div class="sec-hdr" style="margin:0;padding:0">MCP &amp; Agent Governance</div>
      <div style="font-size:12px;color:#6B7280;margin-top:4px">AI agent tool servers discovered on your network — auth status and exposure</div>
    </div>
    <button id="btn-discover-mcp" class="scan-btn" onclick="discoverMcp(this)"
            style="color:#4F46E5;border-color:#1f6feb;font-size:12px">&#128279; Scan for MCP Servers</button>
  </div>
  {_build_mcp_section(mcp, ts_now)}
  </div>

  <div class="page" id="page-riskregister">
  <div class="sec-hdr" style="margin-top:0;padding-top:0">
    Open Findings Risk Register
    <span style="font-size:12px;font-weight:400;color:#6B7280;margin-left:8px">Deduplicated across all devices · updated each scan</span>
    <a href="/api/fleet/risk-register/csv" download style="margin-left:auto;font-size:12px;color:#16A34A;text-decoration:none;border:1px solid #238636;border-radius:4px;padding:3px 10px">&#8659; Export CSV</a>
  </div>
  <div id="rr-filters" style="display:flex;gap:6px;margin-bottom:10px;flex-wrap:wrap">
    <button class="rr-fil rr-active" onclick="rrFilter('all',this)">All</button>
    <button class="rr-fil" onclick="rrFilter('CRITICAL',this)">Critical</button>
    <button class="rr-fil" onclick="rrFilter('HIGH',this)">High</button>
    <button class="rr-fil" onclick="rrFilter('MEDIUM',this)">Medium</button>
    <button class="rr-fil" onclick="rrFilter('LOW',this)">Low</button>
    <button class="rr-fil" onclick="rrFilter('accepted',this)" style="margin-left:auto">Accepted Risk</button>
    <button class="rr-fil" onclick="rrFilter('false_positive',this)" style="color:#6B7280">&#128683; False Positives</button>
  </div>
  <div id="rr-body">
    <div style="color:#6B7280;font-size:13px;padding:16px 0">Loading risk register…</div>
  </div>
  </div>

  <div class="page" id="page-inventory">
  <div class="sec-hdr" style="margin-top:0;padding-top:0;display:flex;align-items:center;gap:10px">
    AI Asset Inventory
    <span style="font-size:12px;font-weight:400;color:#6B7280;margin-left:8px">Formal record of all AI in the environment · approve or flag each asset</span>
    <a href="/api/fleet/shadow/csv" download style="font-size:12px;color:#16A34A;text-decoration:none;border:1px solid #238636;border-radius:4px;padding:3px 10px;margin-left:auto">&#8659; Export CSV</a>
  </div>
  <div id="inv-counts" style="display:flex;gap:12px;margin-bottom:8px;flex-wrap:wrap"></div>
  <div id="inv-reviewer-bar" style="margin-bottom:10px;font-size:12px;color:#6B7280"></div>
  <div id="inv-filters" style="display:flex;gap:6px;margin-bottom:10px;flex-wrap:wrap">
    <button class="rr-fil rr-active" onclick="invFilter('all',this)">All</button>
    <button class="rr-fil" onclick="invFilter('unapproved',this)">Unapproved</button>
    <button class="rr-fil" onclick="invFilter('under_review',this)">Under Review</button>
    <button class="rr-fil" onclick="invFilter('approved',this)">Approved</button>
    <button class="rr-fil" onclick="invFilter('false_positive',this)" style="margin-left:auto;color:#6B7280">&#128683; False Positives</button>
  </div>
  <div id="inv-body">
    <div style="color:#6B7280;font-size:13px;padding:16px 0">Loading inventory…</div>
  </div>
  </div>

  <div class="page" id="page-spend">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:8px">
    <div>
      <div class="sec-hdr" style="margin:0;padding:0">AI Spend</div>
      <div style="font-size:12px;color:#6B7280;margin-top:4px">Token usage and estimated cost across your AI providers · updated on fetch</div>
    </div>
    <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
      <select id="spend-days" class="form-select" style="font-size:12px;padding:4px 8px" onchange="loadSpend()">
        <option value="7">Last 7 days</option>
        <option value="30" selected>Last 30 days</option>
        <option value="90">Last 90 days</option>
        <option value="365">Last 12 months</option>
      </select>
      <button id="spend-refresh-btn" class="scan-btn" onclick="loadSpend(this)" style="font-size:12px;color:#4F46E5;border-color:#E5E7EB">&#8635; Refresh</button>
      <button id="spend-fetch-btn" class="scan-btn" onclick="triggerSpendFetch(this)" style="font-size:12px;color:#16A34A;border-color:#238636">&#128230; Fetch Latest</button>
    </div>
  </div>

  <div id="spend-summary-cards" style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:16px"></div>
  <script>window._spendIsMsp = {('true' if current_user_is_msp else 'false')};</script>

  <div style="margin-bottom:20px">
    <div style="font-size:12px;font-weight:600;color:#374151;text-transform:uppercase;letter-spacing:.05em;margin-bottom:8px">Spend by Provider</div>
    <div id="spend-by-provider" style="display:flex;flex-direction:column;gap:6px">
      <div style="color:#9CA3AF;font-size:13px;padding:12px 0">Loading…</div>
    </div>
  </div>

  <div style="margin-bottom:20px">
    <div style="font-size:12px;font-weight:600;color:#374151;text-transform:uppercase;letter-spacing:.05em;margin-bottom:8px">Spend by Model</div>
    <table class="dev-table" style="width:100%">
      <thead><tr><th>Provider</th><th>Model</th><th style="text-align:right">Input tokens</th><th style="text-align:right">Output tokens</th><th style="text-align:right">Total tokens</th><th style="text-align:right">Cost (USD)</th></tr></thead>
      <tbody id="spend-by-model-body"><tr><td colspan="6" style="color:#9CA3AF;font-size:13px;padding:12px 0">Loading…</td></tr></tbody>
    </table>
  </div>

  <div style="margin-bottom:20px">
    <div style="font-size:12px;font-weight:600;color:#374151;text-transform:uppercase;letter-spacing:.05em;margin-bottom:8px">Daily Spend Trend</div>
    <div id="spend-daily" style="display:flex;flex-direction:column;gap:4px">
      <div style="color:#9CA3AF;font-size:13px;padding:12px 0">Loading…</div>
    </div>
  </div>

  {('<div id="spend-msp-section" style="display:none;margin-bottom:20px;border-top:1px solid #F3F4F6;padding-top:16px">' if current_user_is_msp else '')}
  {('    <div style="font-size:12px;font-weight:600;color:#374151;text-transform:uppercase;letter-spacing:.05em;margin-bottom:8px">Spend by Client Org <span style="font-weight:400;color:#9CA3AF;text-transform:none;letter-spacing:0;margin-left:6px">(MSP view — not visible to client viewers)</span></div>' if current_user_is_msp else '')}
  {('    <table class="dev-table" style="width:100%"><thead><tr><th>Client Org</th><th style="text-align:right">Providers</th><th style="text-align:right">Models</th><th style="text-align:right">Total tokens</th><th style="text-align:right">Cost (USD)</th></tr></thead><tbody id="spend-by-client-org-body"><tr><td colspan="5" style="color:#9CA3AF;font-size:13px;padding:12px 0">Loading…</td></tr></tbody></table>' if current_user_is_msp else '')}
  {('</div>' if current_user_is_msp else '')}

  <div id="spend-keys-section" style="display:none;margin-bottom:20px;border-top:1px solid #F3F4F6;padding-top:16px">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;flex-wrap:wrap;gap:6px">
      <div style="font-size:12px;font-weight:600;color:#374151;text-transform:uppercase;letter-spacing:.05em">API Keys <span style="font-weight:400;color:#9CA3AF;text-transform:none;letter-spacing:0;margin-left:6px">(redacted — full keys are never shown or stored in the config)</span></div>
      <button class="scan-btn" onclick="showAddKeyForm()" style="font-size:12px;color:#4F46E5;border-color:#E5E7EB">+ Add / Rotate Key</button>
    </div>
    <table class="dev-table" style="width:100%">
      <thead><tr><th>Provider</th>{'<th>Client Org</th>' if current_user_is_msp else ''}<th>Label</th><th>Key (redacted)</th><th style="text-align:right">Spend (USD)</th><th></th></tr></thead>
      <tbody id="spend-keys-body"><tr><td colspan="6" style="color:#9CA3AF;font-size:13px;padding:12px 0">Loading…</td></tr></tbody>
    </table>

    <div id="spend-add-key-form" style="display:none;margin-top:12px;padding:12px;background:#F9FAFB;border:1px solid #E5E7EB;border-radius:6px">
      <div style="font-size:12px;font-weight:600;margin-bottom:8px">Add / Rotate API Key</div>
      <div style="display:flex;flex-direction:column;gap:6px">
        <select id="spend-key-provider" class="form-select" style="font-size:12px;padding:4px" onchange="updateSpendKeyHelp()">
          <option value="openai">OpenAI</option>
          <option value="anthropic">Anthropic</option>
          <option value="gemini">Gemini</option>
          <option value="ollama">Ollama</option>
        </select>
        <div id="spend-key-help" style="font-size:11px;color:#6B7280;background:#F9FAFB;border:1px solid #E5E7EB;border-radius:4px;padding:8px 10px;line-height:1.5"></div>
        {('<input id="spend-key-org" class="form-input" placeholder="Client org ID (leave blank for unscoped)" style="font-size:12px;padding:6px">' if current_user_is_msp else '')}
        <input id="spend-key-label" class="form-input" placeholder="Label (e.g. 'Production key')" style="font-size:12px;padding:6px">
        <input id="spend-key-value" type="password" class="form-input" placeholder="API key (stored hashed; never shown again)" style="font-size:12px;padding:6px">
        <div style="display:flex;gap:6px">
          <button class="scan-btn" onclick="submitAddKey()" style="font-size:12px;color:#16A34A;border-color:#238636">Save</button>
          <button class="scan-btn" onclick="hideAddKeyForm()" style="font-size:12px;color:#6B7280;border-color:#E5E7EB">Cancel</button>
        </div>
      </div>
    </div>
  </div>
  </div>

  <div class="page" id="page-schedules">
  <div class="sec-hdr" style="margin-top:0;padding-top:0">
    Scan Schedule
    <span style="font-size:12px;font-weight:400;color:#6B7280;margin-left:8px">Automated recurring scans dispatched to all enrolled agents</span>
  </div>
  <div id="sched-list" style="margin-bottom:12px">
    <div style="color:#6B7280;font-size:13px">Loading schedules…</div>
  </div>
  <details style="margin-bottom:24px">
    <summary style="cursor:pointer;font-size:13px;color:#4F46E5;user-select:none">+ Add schedule</summary>
    <div style="background:#ffffff;border:1px solid #F3F4F6;border-radius:6px;padding:16px;margin-top:8px;display:flex;flex-wrap:wrap;gap:12px;align-items:flex-end">
      <div style="display:flex;flex-direction:column;gap:4px">
        <label style="font-size:11px;color:#6B7280">Label</label>
        <input id="sched-label" type="text" placeholder="e.g. Nightly FedRAMP" style="background:#F9FAFB;border:1px solid #E5E7EB;border-radius:4px;color:#111827;font-size:12px;padding:4px 8px;width:160px">
      </div>
      <div style="display:flex;flex-direction:column;gap:4px">
        <label style="font-size:11px;color:#6B7280">Profile</label>
        <select id="sched-profile" style="background:#F9FAFB;border:1px solid #E5E7EB;border-radius:4px;color:#111827;font-size:12px;padding:4px 8px">
          <option value="default">Base Scan</option>
          <option value="fedramp">FedRAMP</option>
          <option value="fedramp_20x">FedRAMP 20x</option>
          <option value="cmmc">CMMC 2.0</option>
          <option value="financial">Financial</option>
          <option value="healthcare">Healthcare</option>
          <option value="biotech">Biotech</option>
          <option value="owasp_agentic">OWASP Agentic</option>
          <option value="eu_ai_act">EU AI Act</option>
        </select>
      </div>
      <div style="display:flex;flex-direction:column;gap:4px">
        <label style="font-size:11px;color:#6B7280">Cadence</label>
        <select id="sched-cadence" onchange="schedCadenceChange()" style="background:#F9FAFB;border:1px solid #E5E7EB;border-radius:4px;color:#111827;font-size:12px;padding:4px 8px">
          <option value="hourly">Hourly</option>
          <option value="interval">Every N hours</option>
          <option value="daily" selected>Daily</option>
          <option value="weekly">Weekly</option>
          <option value="monthly">Monthly</option>
        </select>
      </div>
      <div style="display:flex;flex-direction:column;gap:4px" id="sched-interval-wrap" style="display:none">
        <label style="font-size:11px;color:#6B7280">Every</label>
        <select id="sched-interval-hours" style="background:#F9FAFB;border:1px solid #E5E7EB;border-radius:4px;color:#111827;font-size:12px;padding:4px 8px">
          <option value="2">2 hours</option>
          <option value="4">4 hours</option>
          <option value="6">6 hours</option>
          <option value="8">8 hours</option>
          <option value="12">12 hours</option>
        </select>
      </div>
      <div style="display:flex;flex-direction:column;gap:4px" id="sched-weekday-wrap" style="display:none">
        <label style="font-size:11px;color:#6B7280">Day</label>
        <select id="sched-weekday" style="background:#F9FAFB;border:1px solid #E5E7EB;border-radius:4px;color:#111827;font-size:12px;padding:4px 8px">
          <option value="0">Monday</option><option value="1">Tuesday</option><option value="2">Wednesday</option>
          <option value="3">Thursday</option><option value="4">Friday</option><option value="5">Saturday</option><option value="6">Sunday</option>
        </select>
      </div>
      <div style="display:flex;flex-direction:column;gap:4px" id="sched-monthday-wrap" style="display:none">
        <label style="font-size:11px;color:#6B7280">Day of month</label>
        <select id="sched-monthday" style="background:#F9FAFB;border:1px solid #E5E7EB;border-radius:4px;color:#111827;font-size:12px;padding:4px 8px">
          {' '.join(f'<option value="{d}">{d}</option>' for d in range(1,29))}
        </select>
      </div>
      <div style="display:flex;flex-direction:column;gap:4px" id="sched-hour-wrap">
        <label style="font-size:11px;color:#6B7280">Time (UTC)</label>
        <select id="sched-hour" style="background:#F9FAFB;border:1px solid #E5E7EB;border-radius:4px;color:#111827;font-size:12px;padding:4px 8px">
          {' '.join(f'<option value="{h}"{" selected" if h==2 else ""}>{h:02d}:00 UTC</option>' for h in range(24))}
        </select>
      </div>
      <button class="scan-btn" onclick="addSchedule()" style="color:#16A34A;border-color:#238636">Save Schedule</button>
    </div>
  </details>
  </div>

  <div class="page" id="page-discovery">
  <div class="sec-hdr" style="margin-top:0;padding-top:0">
    AI Service Discovery
    <button id="discover-btn" class="scan-btn" style="margin-left:12px" onclick="runDiscovery()">Scan Network</button>
  </div>
  <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px;flex-wrap:wrap">
    <label style="font-size:12px;color:#6B7280;white-space:nowrap">Subnets to scan:</label>
    <input id="discover-subnets" type="text" placeholder="auto-detect  (e.g. 10.0.1.0/24, 192.168.2.0/24)"
      style="flex:1;min-width:260px;max-width:540px;background:#F9FAFB;border:1px solid #E5E7EB;border-radius:4px;
             color:#111827;font-size:12px;font-family:monospace;padding:5px 10px;outline:none" />
    <span style="font-size:11px;color:#9CA3AF">Leave blank to scan the local subnet automatically</span>
  </div>
  <div id="discover-panel" class="content-panel" style="background:#ffffff;border:1px solid #F3F4F6;border-radius:8px;padding:18px;min-height:60px;margin-bottom:28px">
    <div class="empty" style="padding:12px">Click Scan Network to probe the local subnet for AI services.</div>
  </div>
  </div>

  <div class="page" id="page-findings">
  <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;margin-bottom:16px">
    <div class="sec-hdr" style="margin:0;padding:0">Device Findings</div>
    <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
      <label style="font-size:12px;color:#6B7280">Device:</label>
      <select id="findings-device-sel"
              onchange="if(this.value) selectDevice(this.value)"
              style="background:#ffffff;border:1px solid #E5E7EB;border-radius:4px;
                     color:#374151;font-size:13px;padding:4px 10px;min-width:220px;cursor:pointer">
        <option value="">— select a device —</option>
      </select>
    </div>
  </div>
  <div id="detail-panel">
    <div class="empty" id="findings-empty-state" style="padding:64px;text-align:center">
      <div style="font-size:15px;color:#9CA3AF;margin-bottom:8px">No device selected</div>
      <div style="font-size:12px;color:#9CA3AF">Choose a device from the dropdown above, or click any row on the Home page</div>
    </div>
  </div>
  </div>

  <div class="page" id="page-settings">
  <div class="sec-hdr" style="margin-top:0;padding-top:0;display:flex;align-items:center;justify-content:space-between">
    <span>Settings</span>
    <a href="/download/shortcut" class="scan-btn"
       style="text-decoration:none;font-size:12px;color:#4F46E5;border-color:#E5E7EB;padding:3px 10px">
      &#8659; Desktop Shortcut
    </a>
  </div>
  <div class="content-panel" style="background:#ffffff;border:1px solid #F3F4F6;border-radius:8px;padding:20px;margin-bottom:16px">
    <div class="panel-sub-hdr" style="font-size:12px;color:#6B7280;font-weight:600;text-transform:uppercase;letter-spacing:.06em;margin-bottom:14px">Configuration</div>
    <div id="cfg-saved" style="display:none;color:#16A34A;font-size:12px;margin-bottom:10px">&#10003; Saved — takes effect on next scan</div>
    <div style="display:grid;grid-template-columns:160px 1fr;gap:10px 16px;align-items:center;max-width:640px">
      <label style="font-size:13px;color:#6B7280;align-self:start;padding-top:4px">Default Device Scan</label>
      <div>
        <select id="cfg-baseline-profile" class="form-select" style="max-width:360px">
          <option value="default">Base Scan</option><option value="iso42001">ISO 42001 (AI Management System)</option><option value="atlas">MITRE ATLAS (Adversarial ML)</option><option value="financial">Financial Services</option><option value="fedramp">FedRAMP / NIST 800-53</option><option value="fedramp_20x">FedRAMP 20x (KSI-Aligned)</option><option value="cmmc">CMMC 2.0</option><option value="biotech">Biotech (FDA 21 CFR Part 11 / HIPAA / GxP)</option><option value="healthcare">Healthcare (HIPAA / HITECH / FDA SaMD)</option><option value="lifesciences">Life Sciences</option><option value="owasp_agentic">OWASP Agentic AI Top 10</option><option value="eu_ai_act">EU AI Act (High-Risk Systems)</option><option value="professional_services">Professional Services (NIST AI RMF / AICPA)</option>
        </select>
        <div style="font-size:11px;color:#9CA3AF;margin-top:5px">Applied to new agents, scheduled scans, and Scan All. Docker and Kubernetes scans remain separate.</div>
      </div>
      <label style="font-size:13px;color:#6B7280">Scan Interval</label>
      <div style="display:flex;align-items:center;gap:8px">
        <input id="cfg-interval" class="form-input" type="number" min="60" placeholder="3600" style="width:120px">
        <span style="font-size:12px;color:#9CA3AF">seconds &nbsp;(3600 = hourly · 86400 = daily)</span>
      </div>
      <label style="font-size:13px;color:#6B7280">Extra Subnets</label>
      <div style="display:flex;align-items:center;gap:8px">
        <input id="cfg-subnets" class="form-input" type="text" placeholder="192.168.50.0/24, 10.0.2.0/24" style="width:320px">
        <span style="font-size:12px;color:#9CA3AF">additional ranges for Shadow AI scans</span>
      </div>
    </div>
    <div style="margin-top:16px">
      <button class="scan-btn" onclick="saveConfig()" style="color:#16A34A;border-color:#E5E7EB">Save</button>
    </div>
  </div>

  <div class="content-panel" style="background:#ffffff;border:1px solid #F3F4F6;border-radius:8px;padding:20px;margin-bottom:16px">
    <div class="panel-sub-hdr" style="font-size:12px;color:#6B7280;font-weight:600;text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px">Report Branding</div>
    <div style="font-size:12px;color:#9CA3AF;margin-bottom:14px">White-label the EU AI Act Readiness Report with your company name, logo, and footer. Clients will see your branding instead of Arckon&#39;s.</div>
    <div id="branding-saved" style="display:none;color:#16A34A;font-size:12px;margin-bottom:10px">&#10003; Branding saved</div>
    <div style="display:grid;grid-template-columns:160px 1fr;gap:10px 16px;align-items:center;max-width:640px">
      <label style="font-size:13px;color:#6B7280">Company Name</label>
      <input id="brand-msp-name" class="form-input" type="text" placeholder="Your MSP or Company Name" style="max-width:340px">
      <label style="font-size:13px;color:#6B7280">Logo URL</label>
      <div>
        <input id="brand-logo-url" class="form-input" type="url" placeholder="https://yourcompany.com/logo.png" style="max-width:400px">
        <div style="font-size:11px;color:#9CA3AF;margin-top:4px">PNG or SVG, max 160×40 px in the report header. Host on any public URL.</div>
      </div>
      <label style="font-size:13px;color:#6B7280">Report Footer</label>
      <div>
        <input id="brand-footer-text" class="form-input" type="text" placeholder="Prepared by Your Company · yourcompany.com" style="max-width:400px">
        <div style="font-size:11px;color:#9CA3AF;margin-top:4px">&#8220;Powered by Arckon&#8221; is appended automatically.</div>
      </div>
    </div>
    <div style="margin-top:16px;display:flex;align-items:center;gap:12px">
      <button class="scan-btn" onclick="saveBranding()" style="color:#16A34A;border-color:#E5E7EB">Save Branding</button>
      <a id="brand-preview-link" href="/api/fleet/eu-ai-act-report" target="_blank"
         style="font-size:12px;color:#4F46E5;text-decoration:none">&#8599; Preview Report</a>
    </div>
  </div>

  <div class="content-panel" style="background:#ffffff;border:1px solid #F3F4F6;border-radius:8px;padding:20px;margin-bottom:16px">
    <div class="panel-sub-hdr" style="font-size:12px;color:#6B7280;font-weight:600;text-transform:uppercase;letter-spacing:.06em;margin-bottom:4px">Alert Notifications</div>
    <div style="font-size:12px;color:#9CA3AF;margin-bottom:14px">Notify your team on Slack or email when new critical findings or shadow AI are detected. Zero cost — uses Slack&#39;s free incoming webhooks and your existing email.</div>
    <div id="alert-saved" style="display:none;color:#16A34A;font-size:12px;margin-bottom:10px">&#10003; Alert settings saved</div>
    <div id="alert-test-result" style="display:none;font-size:12px;margin-bottom:10px"></div>

    <div style="display:grid;grid-template-columns:160px 1fr;gap:10px 16px;align-items:start;max-width:680px">

      <label style="font-size:13px;color:#6B7280;padding-top:4px">Slack Webhook</label>
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <input id="alert-slack" type="url" class="form-input" placeholder="https://hooks.slack.com/services/..."
               style="flex:1;min-width:280px;font-family:monospace;font-size:12px">
        <button class="scan-btn" onclick="testAlert('slack')" style="font-size:11px;padding:3px 10px;color:#4F46E5;border-color:#E5E7EB">Test</button>
      </div>

      <div style="font-size:11px;color:#9CA3AF;padding-top:2px">How to get one: Slack → Your workspace → Apps → Incoming Webhooks</div>
      <div></div>

      <label style="font-size:13px;color:#6B7280;padding-top:4px">Webhook URL</label>
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <input id="alert-webhook" type="url" class="form-input" placeholder="https://your-endpoint.com/alerts"
               style="flex:1;min-width:280px;font-family:monospace;font-size:12px">
        <button class="scan-btn" onclick="testAlert('webhook')" style="font-size:11px;padding:3px 10px;color:#4F46E5;border-color:#E5E7EB">Test</button>
      </div>

      <label style="font-size:13px;color:#6B7280;padding-top:4px">Google Chat Webhook</label>
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <input id="alert-gchat" type="url" class="form-input" placeholder="https://chat.googleapis.com/v1/spaces/..."
               style="flex:1;min-width:280px;font-family:monospace;font-size:12px">
        <button class="scan-btn" onclick="testAlert('gchat')" style="font-size:11px;padding:3px 10px;color:#4F46E5;border-color:#E5E7EB">Test</button>
      </div>

      <div style="font-size:11px;color:#9CA3AF;padding-top:2px">Space → Apps &amp; integrations → Webhooks → Add webhook</div>
      <div></div>

      <label style="font-size:13px;color:#6B7280;padding-top:4px">Teams Webhook</label>
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <input id="alert-teams" type="url" class="form-input" placeholder="https://yourorg.webhook.office.com/webhookb2/..."
               style="flex:1;min-width:280px;font-family:monospace;font-size:12px">
        <button class="scan-btn" onclick="testAlert('teams')" style="font-size:11px;padding:3px 10px;color:#4F46E5;border-color:#E5E7EB">Test</button>
      </div>

      <div style="font-size:11px;color:#9CA3AF;padding-top:2px">Channel → Connectors → Incoming Webhook → configure → copy URL</div>
      <div></div>

      <div style="font-size:11px;color:#9CA3AF;grid-column:1/-1;border-top:1px solid #F3F4F6;margin:6px 0;padding-top:10px">Email (SMTP) — Gmail: use an App Password from myaccount.google.com/apppasswords</div>

      <label style="font-size:13px;color:#6B7280">SMTP Host</label>
      <div style="display:flex;gap:8px;align-items:center">
        <input id="alert-smtp-host" type="text" class="form-input" placeholder="smtp.gmail.com" style="width:220px;font-family:monospace;font-size:12px">
        <label style="font-size:12px;color:#6B7280">Port</label>
        <input id="alert-smtp-port" type="number" class="form-input" placeholder="587" style="width:70px;font-family:monospace;font-size:12px">
      </div>

      <label style="font-size:13px;color:#6B7280">SMTP Username</label>
      <input id="alert-smtp-user" type="text" class="form-input" placeholder="you@gmail.com" style="width:280px;font-family:monospace;font-size:12px">

      <label style="font-size:13px;color:#6B7280">SMTP Password</label>
      <input id="alert-smtp-pass" type="password" class="form-input" placeholder="App password" style="width:280px;font-family:monospace;font-size:12px">

      <label style="font-size:13px;color:#6B7280">From Address</label>
      <input id="alert-email-from" type="email" class="form-input" placeholder="sentinel@yourdomain.com" style="width:280px;font-family:monospace;font-size:12px">

      <label style="font-size:13px;color:#6B7280">Send Alerts To</label>
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <input id="alert-email-to" type="email" class="form-input" placeholder="security-team@yourdomain.com" style="width:280px;font-family:monospace;font-size:12px">
        <button class="scan-btn" onclick="testAlert('email')" style="font-size:11px;padding:3px 10px;color:#4F46E5;border-color:#E5E7EB">Test</button>
      </div>

      <div style="font-size:11px;color:#9CA3AF;grid-column:1/-1;border-top:1px solid #F3F4F6;margin:6px 0;padding-top:10px">Trigger Events</div>

      <label style="font-size:13px;color:#6B7280">Alert when</label>
      <div style="display:flex;flex-direction:column;gap:6px">
        <label style="font-size:13px;color:#111827;display:flex;align-items:center;gap:8px;cursor:pointer">
          <input type="checkbox" id="trig-crit"> New <span style="color:#DC2626;font-weight:700">CRITICAL</span> finding detected on any device
        </label>
        <label style="font-size:13px;color:#111827;display:flex;align-items:center;gap:8px;cursor:pointer">
          <input type="checkbox" id="trig-high"> New <span style="color:#CA8A04;font-weight:700">HIGH</span> finding detected on any device
        </label>
        <label style="font-size:13px;color:#111827;display:flex;align-items:center;gap:8px;cursor:pointer">
          <input type="checkbox" id="trig-shadow"> New <span style="color:#4F46E5;font-weight:700">Shadow AI</span> asset discovered
        </label>
        <label style="font-size:13px;color:#111827;display:flex;align-items:center;gap:8px;cursor:pointer;margin-left:24px">
          <input type="checkbox" id="trig-unapproved-only"> Only alert on <span style="color:#f78166;font-weight:700">unapproved</span> services (skip globally approved)
        </label>
      </div>

    </div>
    <div style="margin-top:16px">
      <button class="scan-btn" onclick="saveAlertConfig()" style="color:#16A34A;border-color:#E5E7EB">Save Alert Settings</button>
    </div>
  </div>

  {_live_scan_settings_html()}

  </div>

  <div class="page" id="page-siem">
  <div class="sec-hdr" style="margin-top:0;padding-top:0">SIEM &amp; Tool Integrations</div>
  <p style="color:#6B7280;font-size:14px;margin-top:-12px;margin-bottom:24px">
    Connect Arckon to your security stack. Findings are forwarded automatically when a scan completes.
    Configure each integration below, then click Test to verify connectivity.
  </p>

  <div style="font-size:11px;font-weight:700;letter-spacing:.8px;text-transform:uppercase;color:#6B7280;margin-bottom:12px">PSA &amp; Ticketing</div>
  <p style="color:#6B7280;font-size:13px;margin-top:-8px;margin-bottom:16px">Auto-create service tickets when new CRITICAL or HIGH findings are detected. Enable one PSA to activate.</p>
  <div style="display:flex;align-items:center;gap:10px;margin-bottom:16px">
    <label style="font-size:13px;color:#374151;font-weight:600">Configuring for:</label>
    <select id="psa-client-org-select" class="form-input" style="max-width:280px" onchange="loadPsaConfig()">
      <option value="">Default (all clients without their own override)</option>
    </select>
  </div>
  <div id="psa-save-banner" style="display:none;background:#D1FAE5;color:#065F46;border:1px solid #6EE7B7;border-radius:6px;padding:10px 16px;margin-bottom:16px;font-size:13px">&#10003; PSA settings saved</div>
  <div id="psa-cards" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(480px,1fr));gap:20px;margin-bottom:32px"></div>

  <div style="font-size:11px;font-weight:700;letter-spacing:.8px;text-transform:uppercase;color:#6B7280;margin-bottom:12px">Wiki &amp; Docs</div>
  <p style="color:#6B7280;font-size:13px;margin-top:-8px;margin-bottom:16px">Create a page for every new CRITICAL or HIGH finding in your team's wiki or notes system, with the same details and remediation steps sent to chat and ticketing.</p>
  <div id="wiki-save-banner" style="display:none;background:#D1FAE5;color:#065F46;border:1px solid #6EE7B7;border-radius:6px;padding:10px 16px;margin-bottom:16px;font-size:13px">&#10003; Wiki settings saved</div>
  <div id="wiki-cards" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(480px,1fr));gap:20px;margin-bottom:32px"></div>

  <div style="font-size:11px;font-weight:700;letter-spacing:.8px;text-transform:uppercase;color:#6B7280;margin-bottom:12px">SIEM &amp; Log Management</div>
  <div id="siem-save-banner" style="display:none;background:#D1FAE5;color:#065F46;border:1px solid #6EE7B7;border-radius:6px;padding:10px 16px;margin-bottom:16px;font-size:13px">&#10003; Settings saved</div>
  <div id="siem-cards" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(480px,1fr));gap:20px"></div>
  </div>

  <div class="page" id="page-reports">
  <div class="sec-hdr" style="margin-top:0;padding-top:0">Reports</div>

  <div style="background:#ffffff;border:1px solid #F3F4F6;border-radius:8px;padding:18px 22px;margin-bottom:24px">
    <div style="font-size:11px;font-weight:700;letter-spacing:.8px;text-transform:uppercase;color:#6B7280;margin-bottom:12px">Compliance Profile Filter</div>
    <div style="display:flex;flex-wrap:wrap;gap:8px 20px;margin-bottom:4px">
      <label style="font-size:13px;color:#374151;display:flex;align-items:center;gap:6px;cursor:pointer"><input type="checkbox" class="rpt-profile" value="default"> Base Scan</label>
      <label style="font-size:13px;color:#374151;display:flex;align-items:center;gap:6px;cursor:pointer"><input type="checkbox" class="rpt-profile" value="fedramp"> FedRAMP / NIST 800-53</label>
      <label style="font-size:13px;color:#374151;display:flex;align-items:center;gap:6px;cursor:pointer"><input type="checkbox" class="rpt-profile" value="fedramp_20x"> FedRAMP 20x</label>
      <label style="font-size:13px;color:#374151;display:flex;align-items:center;gap:6px;cursor:pointer"><input type="checkbox" class="rpt-profile" value="cmmc"> CMMC 2.0</label>
      <label style="font-size:13px;color:#374151;display:flex;align-items:center;gap:6px;cursor:pointer"><input type="checkbox" class="rpt-profile" value="financial"> Financial Services</label>
      <label style="font-size:13px;color:#374151;display:flex;align-items:center;gap:6px;cursor:pointer"><input type="checkbox" class="rpt-profile" value="biotech"> Biotech</label>
      <label style="font-size:13px;color:#374151;display:flex;align-items:center;gap:6px;cursor:pointer"><input type="checkbox" class="rpt-profile" value="healthcare"> Healthcare</label>
      <label style="font-size:13px;color:#374151;display:flex;align-items:center;gap:6px;cursor:pointer"><input type="checkbox" class="rpt-profile" value="owasp_agentic"> OWASP Agentic AI</label>
      <label style="font-size:13px;color:#374151;display:flex;align-items:center;gap:6px;cursor:pointer"><input type="checkbox" class="rpt-profile" value="eu_ai_act"> EU AI Act</label>
      <label style="font-size:13px;color:#374151;display:flex;align-items:center;gap:6px;cursor:pointer"><input type="checkbox" class="rpt-profile" value="professional_services"> Professional Services</label>
      <label style="font-size:13px;color:#374151;display:flex;align-items:center;gap:6px;cursor:pointer"><input type="checkbox" class="rpt-profile" value="kubernetes"> Kubernetes</label>
      <label style="font-size:13px;color:#374151;display:flex;align-items:center;gap:6px;cursor:pointer"><input type="checkbox" class="rpt-profile" value="docker"> Docker</label>
    </div>
    <div style="font-size:11px;color:#9CA3AF;margin-top:8px">Select one or more profiles to filter report content. Leave all unchecked for the full base scan.</div>
  </div>

  <div style="font-size:11px;font-weight:700;letter-spacing:.8px;text-transform:uppercase;color:#6B7280;margin-bottom:12px">Fleet Reports</div>
  <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:16px;margin-bottom:28px">

    <div style="background:#ffffff;border:1px solid #F3F4F6;border-radius:8px;padding:20px">
      <div style="font-size:15px;font-weight:700;color:#111827;margin-bottom:6px">&#128200; Executive Summary</div>
      <div style="font-size:12px;color:#6B7280;line-height:1.6;margin-bottom:16px">High-level posture for leadership. Fleet score, top risks, business context. No individual findings or technical detail.</div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button class="scan-btn" onclick="rptDownloadPdf('executive',this)" style="color:#16A34A;border-color:#238636;font-size:12px">&#8659; Download PDF</button>
        <button class="scan-btn" onclick="rptPreview('executive')" style="color:#6B7280;font-size:12px">&#128065; Preview</button>
      </div>
    </div>

    <div style="background:#ffffff;border:1px solid #F3F4F6;border-radius:8px;padding:20px">
      <div style="font-size:15px;font-weight:700;color:#111827;margin-bottom:6px">&#128203; CISO Report</div>
      <div style="font-size:12px;color:#6B7280;line-height:1.6;margin-bottom:16px">Per-device FAIL and WARN findings grouped by severity. Risk exposure and compliance posture. No remediation steps.</div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button class="scan-btn" onclick="rptDownloadPdf('ciso',this)" style="color:#16A34A;border-color:#238636;font-size:12px">&#8659; Download PDF</button>
        <button class="scan-btn" onclick="rptPreview('ciso')" style="color:#6B7280;font-size:12px">&#128065; Preview</button>
      </div>
    </div>

    <div style="background:#ffffff;border:1px solid #F3F4F6;border-radius:8px;padding:20px">
      <div style="font-size:15px;font-weight:700;color:#111827;margin-bottom:6px">&#128295; Technical Report</div>
      <div style="font-size:12px;color:#6B7280;line-height:1.6;margin-bottom:16px">All findings including pass/fail/warn with full details and step-by-step remediation for each check. For security engineers.</div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        {_btn_technical_pdf}
      </div>
    </div>
  </div>

  <div style="font-size:11px;font-weight:700;letter-spacing:.8px;text-transform:uppercase;color:#6B7280;margin-bottom:12px">Regulatory Reports</div>
  <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:16px;margin-bottom:28px">

    <div style="background:#ffffff;border:1px solid #F3F4F6;border-radius:8px;padding:20px">
      <div style="font-size:15px;font-weight:700;color:#111827;margin-bottom:6px">&#127466;&#127482; EU AI Act Readiness</div>
      <div style="font-size:12px;color:#6B7280;line-height:1.6;margin-bottom:12px">Compliance readiness report mapping scan findings to EU AI Act articles (Art. 9–53). Export as PDF or CSV — generated server-side, not a browser print (Safari's print-to-PDF was producing blank pages).</div>
      <input id="euai-org-name" class="form-input" type="text" placeholder="Organization name for this report"
             style="font-size:12px;margin-bottom:10px;max-width:280px"
             onchange="localStorage.setItem('euai_org_name', this.value)">
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button class="scan-btn" onclick="openEuaiReport('html')" style="color:#4F46E5;border-color:#C7D2FE;font-size:12px">&#128065; Preview</button>
        <button class="scan-btn" onclick="openEuaiReport('pdf')" style="color:#16A34A;border-color:#238636;font-size:12px">&#8659; Download PDF</button>
        <button class="scan-btn" onclick="openEuaiReport('csv')" style="color:#CA8A04;border-color:#FDE68A;font-size:12px">&#8659; Download CSV</button>
      </div>
    </div>

    <div style="background:#ffffff;border:1px solid #F3F4F6;border-radius:8px;padding:20px">
      <div style="font-size:15px;font-weight:700;color:#111827;margin-bottom:6px">&#129302; AI Bill of Materials</div>
       <div style="font-size:12px;color:#6B7280;line-height:1.6;margin-bottom:12px">Complete inventory of AI models, packages, developer tools, and SaaS services detected across the fleet. JSON supports automation, CSV supports audits and spreadsheets, and PDF is suitable for review and sharing.</div>
      <input id="aibom-org-name" class="form-input" type="text" placeholder="Organization name for this report"
             style="font-size:12px;margin-bottom:10px;max-width:280px"
             onchange="localStorage.setItem('aibom_org_name', this.value)">
      <div style="display:flex;gap:8px;flex-wrap:wrap">
         <button class="scan-btn" onclick="openAibomReport('html')" style="color:#4F46E5;border-color:#C7D2FE;font-size:12px">&#128065; Preview</button>
         <button class="scan-btn" onclick="openAibomReport('json')" style="color:#16A34A;border-color:#238636;font-size:12px">&#8659; Download JSON</button>
         <button class="scan-btn" onclick="openAibomReport('pdf')" style="color:#16A34A;border-color:#238636;font-size:12px">&#8659; Download PDF</button>
         <button class="scan-btn" onclick="openAibomReport('csv')" style="color:#CA8A04;border-color:#FDE68A;font-size:12px">&#8659; Download CSV</button>
      </div>
    </div>

  </div>

  <div style="font-size:11px;font-weight:700;letter-spacing:.8px;text-transform:uppercase;color:#6B7280;margin-bottom:12px">MCP &amp; Agent Governance Reports</div>
  <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:16px;margin-bottom:28px">

    <div style="background:#ffffff;border:1px solid #F3F4F6;border-radius:8px;padding:20px">
      <div style="font-size:15px;font-weight:700;color:#111827;margin-bottom:6px">&#128279; Executive — Agent Risk</div>
      <div style="font-size:12px;color:#6B7280;line-height:1.6;margin-bottom:16px">Business risk summary of AI agent tool exposure. No server inventory or technical detail. Safe for board-level distribution.</div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button class="scan-btn" onclick="rptDownloadMcpPdf('executive',this)" style="color:#16A34A;border-color:#238636;font-size:12px">&#8659; Download PDF</button>
        <button class="scan-btn" onclick="rptPreviewMcp('executive')" style="color:#6B7280;font-size:12px">&#128065; Preview</button>
      </div>
    </div>

    <div style="background:#ffffff;border:1px solid #F3F4F6;border-radius:8px;padding:20px">
      <div style="font-size:15px;font-weight:700;color:#111827;margin-bottom:6px">&#128279; CISO — Agent Governance</div>
      <div style="font-size:12px;color:#6B7280;line-height:1.6;margin-bottom:16px">Full MCP server inventory, auth status, OWASP Agentic AI risks, and EU AI Act exposure mapping. No remediation steps.</div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        <button class="scan-btn" onclick="rptDownloadMcpPdf('ciso',this)" style="color:#16A34A;border-color:#238636;font-size:12px">&#8659; Download PDF</button>
        <button class="scan-btn" onclick="rptPreviewMcp('ciso')" style="color:#6B7280;font-size:12px">&#128065; Preview</button>
      </div>
    </div>

    <div style="background:#ffffff;border:1px solid #F3F4F6;border-radius:8px;padding:20px">
      <div style="font-size:15px;font-weight:700;color:#111827;margin-bottom:6px">&#128279; Technical — Per-Server Detail</div>
      <div style="font-size:12px;color:#6B7280;line-height:1.6;margin-bottom:16px">Per-server auth status, exposed tools, high-risk tool flags, and remediation steps for each unauthenticated server.</div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        {_btn_mcp_technical}
      </div>
    </div>
  </div>

  <div style="font-size:11px;font-weight:700;letter-spacing:.8px;text-transform:uppercase;color:#6B7280;margin-bottom:12px">Evidence &amp; Compliance</div>
  <div style="background:#ffffff;border:1px solid #F3F4F6;border-radius:8px;padding:20px;max-width:520px">
    <div style="font-size:15px;font-weight:700;color:#111827;margin-bottom:6px">&#128230; Evidence Package</div>
    <div style="font-size:12px;color:#6B7280;line-height:1.6;margin-bottom:6px">Complete audit bundle for compliance review: cover letter, findings CSV, signed fleet PDF, per-device JSON reports, and cryptographic manifest.</div>
    <div style="font-size:12px;color:#6B7280;margin-bottom:16px">Contents are cryptographically signed with HMAC-SHA256 — tamper-evident for auditor submission.</div>
    {'<button id="btn-evidence-export-rpt" class="scan-btn" onclick="downloadEvidencePackage(this)" style="color:#a371f7;border-color:#6e40c9;font-size:12px">&#8659; Download ZIP</button>' if _has_evidence_package() else '<button class="scan-btn" disabled style="color:#6B7280;border-color:#E5E7EB;font-size:12px;cursor:not-allowed;opacity:.55">&#128274; Plus Plan Required</button><div style="font-size:11px;color:#f0a500;margin-top:8px">{"&#9888; Available in evaluation — upgrade to Plus for production use." if _is_demo() else "&#9888; Evidence Package is a Plus plan feature. Contact sales@markai.io to upgrade."}</div>'}
  </div>
  </div>

  </div>

  {'<div class="page" id="page-probe" style="position:fixed;top:0;left:240px;right:0;bottom:0;z-index:50"><iframe id="probe-iframe" data-loaded="0" style="width:100%;height:100%;border:none;display:block"></iframe></div>' if _has_live_scan() else ''}

  {'<div class="page" id="page-reseller" style="position:fixed;top:0;left:240px;right:0;bottom:0;z-index:50"><iframe id="reseller-iframe" data-loaded="0" style="width:100%;height:100%;border:none;display:block"></iframe></div>' if current_user_is_reseller else ''}

  <div class="page" id="page-users" style="position:fixed;top:0;left:240px;right:0;bottom:0;z-index:50;background:#F9FAFB;overflow-y:auto;padding:28px 36px">
  <div class="sec-hdr" style="margin-top:0;padding-top:0">Users</div>
  <div class="content-panel" style="background:#ffffff;border:1px solid #F3F4F6;border-radius:8px;padding:20px;margin-bottom:16px">
    <div class="panel-sub-hdr" style="font-size:12px;color:#6B7280;font-weight:600;text-transform:uppercase;letter-spacing:.06em;margin-bottom:14px">Team members</div>
    <p style="font-size:13px;color:#6B7280;margin:0 0 14px">Each user has their own email and password. Approvals and actions are attributed to the logged-in account — names cannot be changed after the fact.</p>
    <div id="users-list" style="margin-bottom:20px"></div>
    <div style="border-top:1px solid #F3F4F6;padding-top:16px;margin-top:4px">
      <div style="font-size:12px;color:#374151;font-weight:600;margin-bottom:10px">Add user</div>
      <div style="display:grid;grid-template-columns:1fr 1fr auto;gap:8px;align-items:end;max-width:560px">
        <div>
          <label style="font-size:12px;color:#6B7280;display:block;margin-bottom:4px">Email</label>
          <input id="new-user-email" type="email" placeholder="user@company.com" class="form-input" style="width:100%;box-sizing:border-box">
        </div>
        <div>
          <label style="font-size:12px;color:#6B7280;display:block;margin-bottom:4px">Password</label>
          <input id="new-user-pw" type="password" placeholder="Min 8 characters" class="form-input" style="width:100%;box-sizing:border-box">
        </div>
        <button class="scan-btn" onclick="addUser()" style="color:#16A34A;border-color:#E5E7EB;white-space:nowrap">Add user</button>
      </div>
      <div id="users-msg" style="font-size:12px;margin-top:8px"></div>
    </div>
  </div>
  <div class="content-panel" style="background:#ffffff;border:1px solid #F3F4F6;border-radius:8px;padding:20px;margin-bottom:16px">
    <div class="panel-sub-hdr" style="font-size:12px;color:#6B7280;font-weight:600;text-transform:uppercase;letter-spacing:.06em;margin-bottom:14px">Agent token</div>
    <p style="font-size:13px;color:#6B7280;margin:0 0 14px">Paste this token into your agent&apos;s config file (<code style="font-size:12px;background:#F3F4F6;padding:1px 4px;border-radius:3px">SENTINEL_TOKEN</code>). Keep it secret — anyone with this token can submit reports to your account.</p>
    <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
      <input id="agent-token-display" type="password" readonly
             style="flex:1;min-width:240px;max-width:480px;font-family:monospace;font-size:13px;
                    background:#F9FAFB;border:1px solid #E5E7EB;border-radius:6px;padding:8px 12px;color:#111827"
             value="" placeholder="Loading…">
      <button class="scan-btn" onclick="toggleTokenVisibility()" id="token-show-btn"
              style="white-space:nowrap">Show</button>
      <button class="scan-btn" onclick="copyToken()"
              style="white-space:nowrap;color:#4F46E5;border-color:#E5E7EB">Copy</button>
    </div>
    <div id="token-company" style="font-size:12px;color:#9CA3AF;margin-top:8px"></div>
  </div>
  </div>

</div>

<script>
// Force reload when restored from bfcache so nginx re-checks auth
window.addEventListener('pageshow', function(e) {{
  if (e.persisted) window.location.reload();
}});
// ── Theme ──
function _applyTheme(light) {{
  document.documentElement.classList.toggle('light', light);
  document.body.classList.toggle('light', light);
  document.body.style.background = light ? '#f6f8fa' : '#F9FAFB';
  document.body.style.color = light ? '#24292f' : '#374151';
  const btn = document.getElementById('theme-toggle');
  if (btn) {{
    btn.textContent = light ? '⬛ Dark' : '☀ Light';
    btn.style.background = light ? '#f6f8fa' : '#ffffff';
    btn.style.color = light ? '#24292f' : '#6B7280';
  }}
  const tb = document.querySelector('.toolbar');
  if (tb) {{
    tb.style.background = light ? '#f6f8fa' : '#ffffff';
    tb.querySelectorAll('button:not(#theme-toggle)').forEach(n => {{
      n.style.background   = light ? '#eef1f4' : '#F3F4F6';
      n.style.color        = light ? '#24292f' : '#374151';
      n.style.borderColor  = light ? '#c8ccd0' : '#E5E7EB';
    }});
    tb.querySelectorAll('span, label').forEach(n => {{
      n.style.color = light ? '#57606a' : null;
    }});
  }}
  // content panels (Settings, System, Discovery)
  document.querySelectorAll('.content-panel').forEach(n => {{
    n.style.background  = light ? '#f6f8fa' : '#ffffff';
    n.style.borderColor = light ? '#d0d7de' : '#F3F4F6';
  }});
  // sub-headers inside panels (Configuration, System labels)
  document.querySelectorAll('.panel-sub-hdr').forEach(n => {{
    n.style.color = light ? '#57606a' : '#6B7280';
  }});
  // form inputs (scan interval, extra subnets)
  document.querySelectorAll('.form-input').forEach(n => {{
    n.style.background  = light ? '#ffffff' : '#F9FAFB';
    n.style.color       = light ? '#24292f' : '#374151';
    n.style.borderColor = light ? '#d0d7de' : '#E5E7EB';
  }});
  // subnet discovery text input
  const _sni = document.getElementById('discover-subnets');
  if (_sni) {{
    _sni.style.background  = light ? '#ffffff' : '#F9FAFB';
    _sni.style.color       = light ? '#24292f' : '#111827';
    _sni.style.borderColor = light ? '#d0d7de' : '#E5E7EB';
  }}
  // system log panel
  const _sl = document.getElementById('sys-log');
  if (_sl) {{
    _sl.style.background  = light ? '#f6f8fa' : '#F9FAFB';
    _sl.style.borderColor = light ? '#d0d7de' : '#E5E7EB';
    _sl.style.color       = light ? '#57606a' : '#6B7280';
  }}
  // compliance profile checkbox labels
  document.querySelectorAll('#cfg-profile-group label').forEach(n => {{
    n.style.color = light ? '#24292f' : '#111827';
  }});
}}
function toggleTheme() {{
  const light = !document.documentElement.classList.contains('light');
  localStorage.setItem('sentinel_theme', light ? 'light' : 'dark');
  _applyTheme(light);
}}
_applyTheme(localStorage.getItem('sentinel_theme') === 'light');
window.addEventListener('storage', function(e) {{
  if (e.key === 'sentinel_theme') _applyTheme(e.newValue === 'light');
}});

function navTo(page) {{
  document.querySelectorAll('.page').forEach(function(n) {{ n.classList.remove('active'); }});
  document.querySelectorAll('.sb-item').forEach(function(n) {{ n.classList.remove('sb-active'); }});
  const p = document.getElementById('page-' + page);
  if (p) p.classList.add('active');
  const b = document.getElementById('nav-' + page);
  if (b) b.classList.add('sb-active');
  document.getElementById('main').scrollTop = 0;
  history.replaceState(null, '', '#' + page);
  if (page === 'settings') {{ loadLiveScanConfig(); loadBranding(); }}
  if (page === 'siem') {{ loadSiemConfig(); loadPsaClientOrgs(); loadPsaConfig(); }}
  if (page === 'users') {{ loadUsers(); loadCustomerInfo(); }}
  if (page === 'alerts') {{ loadActiveIssues(); loadAlertEvents(); }}
  if (page === 'spend') {{ loadSpend(); }}
  if (page === 'probe') {{
    const fr = document.getElementById('probe-iframe');
    if (fr && fr.getAttribute('data-loaded') === '0') {{
      fr.src = '/probe';
      fr.setAttribute('data-loaded', '1');
    }}
  }}
  if (page === 'reseller') {{
    const fr = document.getElementById('reseller-iframe');
    if (fr && fr.getAttribute('data-loaded') === '0') {{
      fr.src = '/reseller';
      fr.setAttribute('data-loaded', '1');
    }}
  }}
}}
(function() {{
  const hash = window.location.hash.replace('#', '');
  const valid = ['overview','shadow','alerts','mcp','riskregister','inventory','spend','schedules',
                 'discovery','findings','reports','siem','settings','users','probe','reseller'];
  if (hash && valid.includes(hash)) {{ navTo(hash); }}
}})();

function _syncFindingsSelector() {{
  const sel = document.getElementById('findings-device-sel');
  if (!sel) return;
  const current = sel.value;
  sel.innerHTML = '<option value="">— select a device —</option>';
  _allDevices.forEach(function(d) {{
    const age  = d.last_seen ? Math.floor(Date.now()/1000) - d.last_seen : null;
    const when = age === null ? 'never' : age < 120 ? 'just now' : age < 3600 ? Math.floor(age/60)+'m ago' : age < 86400 ? Math.floor(age/3600)+'h ago' : Math.floor(age/86400)+'d ago';
    const fail = d.fail_count || 0;
    const warn = d.warn_count || 0;
    const label = (d.hostname || d.device_id) + ' — ' + (fail ? fail+' fail' : warn ? warn+' warn' : 'clean') + ' · ' + when;
    const opt = document.createElement('option');
    opt.value = d.device_id;
    opt.textContent = label;
    if (d.device_id === current) opt.selected = true;
    sel.appendChild(opt);
  }});
}}

let _countdown = 60;
let _allDevices = [];
let _activeFilter = new URLSearchParams(location.search).get('filter') || null;
let _pageSize = 10;
let _currentPage = 1;
const _note = document.getElementById('refresh-note');
setInterval(() => {{
  _countdown--;
  if (_countdown <= 0) {{ _countdown = 60; refreshDevices(); refreshShadow(); refreshMcp(); loadK8sStatus(); }}
  _note.textContent = 'Devices refresh in ' + _countdown + 's';
}}, 1000);
refreshDevices();
refreshShadow();
refreshMcp();
loadK8sStatus();
loadRiskRegister();
loadInventory();
loadSchedules();

async function checkMaintenanceNotice() {{
  try {{
    const r = await fetch('/api/maintenance-notice');
    const data = await r.json();
    const banner = document.getElementById('maintenance-banner');
    if (!banner) return;
    const notice = data.notice;
    if (!notice) {{ banner.style.display = 'none'; return; }}
    const when = new Date(notice.scheduled_at).toLocaleString();
    const icon = notice.in_progress ? '&#9888;' : '&#128337;';
    const lead = notice.in_progress ? 'Maintenance in progress: ' : `Scheduled maintenance ${{when}}: `;
    banner.innerHTML = icon + ' ' + lead + notice.message;
    banner.style.display = 'block';
  }} catch (_) {{}}
}}
checkMaintenanceNotice();
setInterval(checkMaintenanceNotice, 120000);

async function endImpersonation() {{
  try {{
    const r = await fetch('/api/reseller/impersonate/end', {{method: 'POST'}});
    const data = await r.json();
    window.location = data.redirect_url || '/';
  }} catch (e) {{
    window.location = '/';
  }}
}}

(function() {{
  const saved = localStorage.getItem('euai_org_name');
  const input = document.getElementById('euai-org-name');
  if (saved && input) input.value = saved;
}})();

function openEuaiReport(fmt) {{
  const input = document.getElementById('euai-org-name');
  const org = input ? input.value.trim() : '';
  const url = '/api/fleet/eu-ai-act-report?org=' + encodeURIComponent(org) + '&fmt=' + fmt;
  if (fmt === 'html') {{
    window.open(url, '_blank');
  }} else {{
    window.location.href = url;
  }}
}}

function openAibomReport(fmt) {{
  const input = document.getElementById('aibom-org-name');
  const org = input ? input.value.trim() : '';
  if (fmt === 'html') {{
     window.open('/api/fleet/aibom?org=' + encodeURIComponent(org), '_blank');
  }} else {{
     // Keep the dashboard interactive while a server-side export is generated.
     window.open('/api/fleet/aibom.' + fmt + '?org=' + encodeURIComponent(org), '_blank');
  }}
}}

;(function() {{
  const saved = localStorage.getItem('aibom_org_name');
  const input = document.getElementById('aibom-org-name');
  if (saved && input) input.value = saved;
}})();

function _age(ts) {{
  if (!ts) return 'never';
  const s = Math.floor(Date.now()/1000) - ts;
  if (s < 120) return s + 's ago';
  if (s < 3600) return Math.floor(s/60) + 'm ago';
  if (s < 86400) return Math.floor(s/3600) + 'h ago';
  return Math.floor(s/86400) + 'd ago';
}}

function _riskCls(fail, warn, pas) {{
  if (fail === 0 && warn === 0 && (pas === 0 || pas === undefined)) return 'r-nodata';
  return fail > 0 ? 'r-fail' : warn > 0 ? 'r-warn' : 'r-pass';
}}

function _visibleDevices() {{
  if (!_activeFilter) return _allDevices;
  if (_activeFilter === 'fail') return _allDevices.filter(d => (d.fail_count||0) > 0);
  if (_activeFilter === 'warn') return _allDevices.filter(d => (d.warn_count||0) > 0);
  if (_activeFilter === 'pass') return _allDevices.filter(d => (d.fail_count||0) === 0 && (d.warn_count||0) === 0);
  return _allDevices;
}}

function _syncFilterUI() {{
  const colorMap = {{fail:'sf-active-red', warn:'sf-active-yellow', pass:'sf-active-green'}};
  const labelMap = {{fail:'High Risk Devices', warn:'Medium Risk Devices', pass:'Info Devices'}};
  ['fail','warn','pass'].forEach(t => {{
    const el = document.getElementById('sf-' + t);
    if (!el) return;
    el.className = 'scard';
    if (_activeFilter === t) el.classList.add(colorMap[t]);
  }});
  const allEl = document.getElementById('sf-all');
  if (allEl) allEl.className = _activeFilter ? 'scard' : 'scard sf-active';
  const banner = document.getElementById('filter-banner');
  const bannerText = document.getElementById('filter-banner-text');
  if (banner) {{
    if (_activeFilter) {{
      bannerText.textContent = 'Showing: ' + (labelMap[_activeFilter] || _activeFilter);
      bannerText.style.color = _activeFilter === 'fail' ? '#DC2626' : _activeFilter === 'warn' ? '#CA8A04' : '#4F46E5';
      banner.style.display = 'flex';
      document.title = 'Sentinel — ' + (labelMap[_activeFilter] || _activeFilter);
    }} else {{
      banner.style.display = 'none';
    }}
  }}
  const badge = document.getElementById('filter-badge');
  if (badge) badge.style.display = 'none';
}}

function filterBy(type) {{
  _activeFilter = type;
  _currentPage = 1;
  _syncFilterUI();
  renderDevicePage();
}}

async function refreshDevices() {{
  try {{
    const resp = await fetch('/api/devices');
    if (!resp.ok) return;
    const data = await resp.json();
    const devs = data.devices || [];
    document.getElementById('sc-count').textContent = devs.length;
    _allDevices = devs;
    _syncFilterUI();
    _syncFindingsSelector();
    const maxPage = Math.max(1, Math.ceil(_visibleDevices().length / _pageSize));
    if (_currentPage > maxPage) _currentPage = maxPage;
    renderDevicePage();
  }} catch (_) {{ /* silently ignore refresh errors */ }}
}}

function _deviceRow(d) {{
  const did    = d.device_id || '';
  const fail   = d.fail_count || 0;
  const warn   = d.warn_count || 0;
  const pas    = d.pass_count || 0;
  const noData = (fail === 0 && warn === 0 && pas === 0);
  const rc     = _riskCls(fail, warn, pas);
  const age    = _age(d.last_seen);
  const hostname = d.hostname || 'unknown';
  const profile  = d.profile || (hostname.startsWith('k8s:') ? 'kubernetes' : hostname.startsWith('docker:') ? 'docker' : '');
  const displayName = hostname.startsWith('docker:') ? hostname.slice(7)
                    : hostname.startsWith('k8s:')    ? hostname.slice(4)
                    : hostname;
  const typeBadge = hostname.startsWith('docker:')
    ? '<span style="font-size:10px;background:#DBEAFE;color:#1D4ED8;border-radius:3px;padding:1px 5px;margin-left:6px;font-weight:600;vertical-align:middle">DOCKER</span>'
    : hostname.startsWith('k8s:')
    ? '<span style="font-size:10px;background:#D1FAE5;color:#065F46;border-radius:3px;padding:1px 5px;margin-left:6px;font-weight:600;vertical-align:middle">K8S</span>'
    : '';
  return `<tr class="dev-row" onclick="selectDevice('${{esc(did)}}')" >
    <td class="dev-host">${{esc(displayName)}}${{typeBadge}}</td>
    <td>${{esc(d.platform||'')}}</td>
    <td class="c-red">${{noData ? '—' : fail}}</td>
    <td class="c-yellow">${{noData ? '—' : warn}}</td>
    <td class="c-green">${{noData ? '—' : pas}}</td>
    <td>${{esc(profile)}}</td>
    <td>${{age}}</td>
    <td><span class="risk-dot ${{rc}}" title="${{noData ? 'No scan data yet' : ''}}"></span></td>
    <td onclick="event.stopPropagation()" style="white-space:nowrap">
      <button class="scan-btn" id="sb-${{esc(did)}}" onclick="openScanModal('${{esc(did)}}',this)">Scan ▾</button>
      <button class="scan-btn" id="ub-${{esc(did)}}" onclick="updateDevice('${{esc(did)}}')"
              style="margin-left:4px;color:#CA8A04;border-color:#E5E7EB">Update</button>
      <a href="/fleet/device/${{esc(did)}}/dashboard" target="_blank"
         style="margin-left:8px;background:#ffffff;border:1px solid #E5E7EB;color:#6B7280;
                border-radius:4px;padding:3px 10px;font-size:12px;text-decoration:none;display:inline-block"
         onmouseover="this.style.borderColor='#4F46E5';this.style.color='#374151'"
         onmouseout="this.style.borderColor='#E5E7EB';this.style.color='#6B7280'">Full Report</a>
      <button class="scan-btn" onclick="removeDevice('${{esc(did)}}','${{esc(d.hostname||'')}}')"
              style="margin-left:4px;color:#DC2626;border-color:#E5E7EB;font-size:11px">Remove</button>
    </td>
  </tr>`;
}}

function _groupHeader(label, icon, count) {{
  return `<tr><td colspan="9" style="background:#F9FAFB;border-top:1px solid #E5E7EB;border-bottom:1px solid #E5E7EB;
    padding:6px 12px;font-size:11px;font-weight:700;color:#6B7280;text-transform:uppercase;letter-spacing:.06em">
    ${{icon}} ${{label}} <span style="font-weight:400;color:#9CA3AF;margin-left:4px">${{count}}</span>
  </td></tr>`;
}}

function renderDevicePage() {{
  const tbody   = document.getElementById('device-tbody');
  const pgEl    = document.getElementById('device-pagination');
  const visible = _visibleDevices();

  if (!_allDevices.length) {{
    tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;padding:32px;color:#9CA3AF">No agents have reported yet.</td></tr>';
    pgEl.style.display = 'none';
    return;
  }}
  if (!visible.length) {{
    const msg = _activeFilter === 'fail' ? 'No high risk devices.' : _activeFilter === 'warn' ? 'No medium risk devices.' : 'No info items.';
    tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;padding:32px;color:#9CA3AF">' + msg + '</td></tr>';
    pgEl.style.display = 'none';
    return;
  }}

  const endpoints = visible.filter(d => !((d.hostname||'').startsWith('k8s:') || (d.hostname||'').startsWith('docker:')));
  const dockers   = visible.filter(d =>  (d.hostname||'').startsWith('docker:'));
  const k8s       = visible.filter(d =>  (d.hostname||'').startsWith('k8s:'));
  const multiGroup = (endpoints.length > 0) + (dockers.length > 0) + (k8s.length > 0) > 1;

  let html = '';
  if (endpoints.length) {{
    if (multiGroup) html += _groupHeader('Endpoints', '&#128187;', endpoints.length);
    html += endpoints.map(_deviceRow).join('');
  }}
  if (dockers.length) {{
    if (multiGroup) html += _groupHeader('Docker', '&#128022;', dockers.length);
    html += dockers.map(_deviceRow).join('');
  }}
  if (k8s.length) {{
    if (multiGroup) html += _groupHeader('Kubernetes', '&#9096;', k8s.length);
    html += k8s.map(_deviceRow).join('');
  }}

  tbody.innerHTML = html;
  pgEl.style.display = 'none';
}}

function renderPagination() {{
  const visible = _visibleDevices();
  const total = visible.length;
  const pages = Math.max(1, Math.ceil(total / _pageSize));
  const pgEl  = document.getElementById('device-pagination');
  pgEl.style.display = total > _pageSize ? 'flex' : 'none';
  const start = (_currentPage - 1) * _pageSize + 1;
  const end   = Math.min(_currentPage * _pageSize, total);
  const suffix = _activeFilter ? ' (filtered)' : '';
  document.getElementById('page-info').textContent = start + '–' + end + ' of ' + total + ' device' + (total !== 1 ? 's' : '') + suffix;
  const btns = document.getElementById('page-btns');
  const btnStyle = 'font-size:12px;padding:2px 8px;min-width:28px;';
  let html = `<button class="scan-btn" onclick="goToPage(${{_currentPage-1}})" ${{_currentPage===1?'disabled':''}} style="${{btnStyle}}">&#8249;</button>`;
  const nums = _pageNums(pages, _currentPage);
  let prev = null;
  for (const p of nums) {{
    if (prev !== null && p > prev + 1) html += `<span style="color:#9CA3AF;padding:0 2px;line-height:24px">&#8230;</span>`;
    const active = p === _currentPage ? 'color:#4F46E5;border-color:#4F46E5;' : '';
    html += `<button class="scan-btn" onclick="goToPage(${{p}})" style="${{btnStyle}}${{active}}">${{p}}</button>`;
    prev = p;
  }}
  html += `<button class="scan-btn" onclick="goToPage(${{_currentPage+1}})" ${{_currentPage===pages?'disabled':''}} style="${{btnStyle}}">&#8250;</button>`;
  btns.innerHTML = html;
}}

function _pageNums(pages, cur) {{
  if (pages <= 7) return Array.from({{length: pages}}, (_, i) => i + 1);
  const s = new Set([1, pages, cur]);
  for (let d = 1; d <= 2; d++) {{
    if (cur - d >= 1) s.add(cur - d);
    if (cur + d <= pages) s.add(cur + d);
  }}
  return [...s].sort((a, b) => a - b);
}}

function changePageSize(size) {{
  _pageSize = size;
  _currentPage = 1;
  renderDevicePage();
}}

function goToPage(p) {{
  const pages = Math.ceil(_visibleDevices().length / _pageSize);
  if (p < 1 || p > pages) return;
  _currentPage = p;
  renderDevicePage();
}}

function esc(s) {{
  if (!s) return '';
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}}

async function removeDevice(did, hostname) {{
  if (!confirm(`Remove "${{hostname || did}}" from the fleet?\n\nThis deletes all scan history for this device and cannot be undone.`)) return;
  try {{
    const resp = await fetch('/api/fleet/remove/' + encodeURIComponent(did), {{method: 'POST'}});
    const data = await resp.json();
    if (resp.ok) {{
      _allDevices = _allDevices.filter(d => d.device_id !== did);
      const maxPage = Math.max(1, Math.ceil(_allDevices.length / _pageSize));
      if (_currentPage > maxPage) _currentPage = maxPage;
      renderDevicePage();
      document.getElementById('sc-count').textContent = _allDevices.length;
    }} else {{
      alert('Remove failed: ' + (data.error || resp.status));
    }}
  }} catch (e) {{ alert('Remove failed: ' + e); }}
}}

async function runDiscovery() {{
  const btn = document.getElementById('discover-btn');
  const panel = document.getElementById('discover-panel');
  const subnetInput = (document.getElementById('discover-subnets').value || '').trim();
  btn.disabled = true;
  btn.textContent = 'Queuing…';

  // Step 1: queue discovery on all registered agents
  let agentCount = 0;
  try {{
    const qr = await fetch('/api/fleet/discover/all', {{method: 'POST'}});
    const qd = await qr.json();
    agentCount = qd.count || 0;
  }} catch (_) {{}}

  if (agentCount === 0) {{
    panel.innerHTML = '<div class="empty" style="padding:12px;color:#CA8A04">⚠ No agents registered — nothing to scan. Deploy an agent first.</div>';
    btn.disabled = false;
    btn.textContent = 'Scan Network';
    return;
  }}

  // Step 2: poll /api/discover every 5s until results stabilise or 60s timeout
  const POLL_INTERVAL = 5000;
  const TIMEOUT_MS    = 60000;
  const started       = Date.now();
  let lastCount       = -1;
  let stableRounds    = 0;

  function countdown() {{
    const elapsed = Math.round((Date.now() - started) / 1000);
    const left    = Math.max(0, Math.round((TIMEOUT_MS - (Date.now() - started)) / 1000));
    btn.textContent = `Scanning… ${{left}}s`;
    panel.innerHTML = `<div class="empty" style="padding:12px">Queued ${{agentCount}} agent${{agentCount !== 1 ? 's' : ''}} — waiting for scan results${{elapsed > 5 ? ' (' + elapsed + 's)' : ''}}…</div>`;
  }}
  countdown();

  const url = subnetInput ? `/api/discover?subnets=${{encodeURIComponent(subnetInput)}}` : '/api/discover';

  async function poll() {{
    try {{
      const resp = await fetch(url);
      const data = await resp.json();
      if (!resp.ok) throw new Error(data.error || 'HTTP ' + resp.status);
      const svcs = data.services || [];
    if (svcs.length === 0) {{
      panel.innerHTML = '<div class="empty" style="padding:12px">No AI services detected (network, processes, or environment).</div>';
    }} else {{
      const modelBadges = (models, service) => {{
        if (!models || !models.length) {{
          const svc = (service || '').toLowerCase();
          if (svc.includes('sentinel') || svc.includes('hash'))
            return '<span style="color:#9CA3AF;font-size:11px">n/a — monitoring tool</span>';
          if (svc.includes('jupyter') || svc.includes('streamlit') || svc.includes('gradio'))
            return '<span style="color:#9CA3AF;font-size:11px">n/a — notebook/UI server</span>';
          if (svc.includes('unknown'))
            return '<span style="color:#CA8A04;font-size:11px">⚠ unable to identify — check device</span>';
          return '<span style="color:#6B7280;font-size:11px;font-style:italic">no models loaded</span>';
        }}
        const badges = models.slice(0, 6).map(m =>
          `<span style="background:#F3F4F6;border-radius:3px;padding:1px 6px;font-size:11px;font-family:monospace;white-space:nowrap">${{esc(m)}}</span>`
        ).join(' ');
        return badges + (models.length > 6 ? ` <span style="color:#6B7280;font-size:11px">+${{models.length - 6}} more</span>` : '');
      }};

      // Group network probes by host IP
      const byHost = {{}};
      for (const s of svcs) {{
        if (s.source === 'network_probe') {{
          byHost[s.host] = (byHost[s.host] || []).concat(s);
        }}
      }}
      const procs = svcs.filter(s => s.source === 'process_scan');
      const envs  = svcs.filter(s => s.source === 'env_var');

      let html = '';
      const hostCount = Object.keys(byHost).length;

      // ── Per-host cards ────────────────────────────────────────────────────
      for (const host of Object.keys(byHost).sort()) {{
        const hostSvcs = byHost[host];
        html += `<div style="margin-bottom:14px;border:1px solid #F3F4F6;border-radius:6px;overflow:hidden">
          <div style="background:#ffffff;padding:7px 12px;display:flex;align-items:center;gap:10px;border-bottom:1px solid #F3F4F6">
            <span style="font-family:monospace;font-size:13px;font-weight:600;color:#111827">${{esc(host)}}</span>
            <span style="font-size:11px;color:#6B7280">${{hostSvcs.length}} service${{hostSvcs.length !== 1 ? 's' : ''}} found</span>
          </div>
          <table style="width:100%;border-collapse:collapse">
            <thead><tr style="font-size:10px;color:#6B7280;text-transform:uppercase;letter-spacing:.4px;background:#F9FAFB">
              <th style="text-align:left;padding:5px 12px;width:22%">Service</th>
              <th style="text-align:left;padding:5px 8px;width:6%">Port</th>
              <th style="text-align:left;padding:5px 8px">Models Detected</th>
              <th style="text-align:left;padding:5px 8px;width:22%">URL</th>
            </tr></thead>
            <tbody>`;
        for (const s of hostSvcs) {{
          const httpStatus = s.status ? ` <span style="color:#9CA3AF;font-size:10px">(HTTP ${{s.status}})</span>` : '';
          html += `<tr style="border-top:1px solid #F3F4F6">
            <td style="padding:7px 12px;font-weight:600;color:#111827;white-space:nowrap">${{esc(s.service)}}</td>
            <td style="padding:7px 8px;color:#6B7280;font-family:monospace;font-size:12px">${{s.port}}</td>
            <td style="padding:7px 8px">${{modelBadges(s.models, s.service)}}</td>
            <td style="padding:7px 8px;font-size:11px"><a href="${{esc(s.url)}}" target="_blank" style="color:#4F46E5;text-decoration:none;font-family:monospace">${{esc(s.url)}}</a>${{httpStatus}}</td>
          </tr>`;
        }}
        html += '</tbody></table></div>';
      }}

      // ── Local machine: running processes ──────────────────────────────────
      if (procs.length) {{
        html += `<div style="margin-bottom:14px;border:1px solid #F3F4F6;border-radius:6px;overflow:hidden">
          <div style="background:#ffffff;padding:7px 12px;display:flex;align-items:center;gap:10px;border-bottom:1px solid #F3F4F6">
            <span style="font-size:12px;font-weight:600;color:#CA8A04">⚙ Running Processes</span>
            <span style="font-size:11px;color:#6B7280">detected on this machine</span>
          </div>
          <table style="width:100%;border-collapse:collapse">
            <thead><tr style="font-size:10px;color:#6B7280;text-transform:uppercase;letter-spacing:.4px;background:#F9FAFB">
              <th style="text-align:left;padding:5px 12px">Service</th>
              <th style="text-align:left;padding:5px 8px">Process Signature</th>
            </tr></thead>
            <tbody>`;
        for (const p of procs) {{
          html += `<tr style="border-top:1px solid #F3F4F6">
            <td style="padding:7px 12px;font-weight:600;color:#111827">${{esc(p.service)}}</td>
            <td style="padding:7px 8px;font-family:monospace;font-size:11px;color:#6B7280"><code style="background:#F3F4F6;padding:1px 5px;border-radius:2px">${{esc(p.process_sig || '')}}</code></td>
          </tr>`;
        }}
        html += '</tbody></table></div>';
      }}

      // ── Local machine: API keys in environment ────────────────────────────
      if (envs.length) {{
        html += `<div style="margin-bottom:14px;border:1px solid #F3F4F6;border-radius:6px;overflow:hidden">
          <div style="background:#ffffff;padding:7px 12px;display:flex;align-items:center;gap:10px;border-bottom:1px solid #F3F4F6">
            <span style="font-size:12px;font-weight:600;color:#bc8cff">🔑 Cloud API Keys</span>
            <span style="font-size:11px;color:#6B7280">found in environment on this machine</span>
          </div>
          <table style="width:100%;border-collapse:collapse">
            <thead><tr style="font-size:10px;color:#6B7280;text-transform:uppercase;letter-spacing:.4px;background:#F9FAFB">
              <th style="text-align:left;padding:5px 12px">Provider</th>
              <th style="text-align:left;padding:5px 8px">Environment Variable</th>
            </tr></thead>
            <tbody>`;
        for (const e of envs) {{
          html += `<tr style="border-top:1px solid #F3F4F6">
            <td style="padding:7px 12px;font-weight:600;color:#111827">${{esc(e.service)}}</td>
            <td style="padding:7px 8px;font-family:monospace;font-size:11px;color:#6B7280"><code style="background:#F3F4F6;padding:1px 5px;border-radius:2px">${{esc(e.env_var || '')}}</code></td>
          </tr>`;
        }}
        html += '</tbody></table></div>';
      }}

      const totalHosts = hostCount;
      const totalSvcs  = svcs.filter(s => s.source === 'network_probe').length;
      panel.innerHTML = html + `<div style="font-size:11px;color:#9CA3AF;margin-top:2px;display:flex;align-items:center;gap:12px">
        <span>${{totalHosts}} host${{totalHosts !== 1 ? 's' : ''}} · ${{totalSvcs}} network service${{totalSvcs !== 1 ? 's' : ''}}${{procs.length ? ' · ' + procs.length + ' process' + (procs.length !== 1 ? 'es' : '') : ''}}${{envs.length ? ' · ' + envs.length + ' API key' + (envs.length !== 1 ? 's' : '') : ''}} · scanned just now</span>
        <button onclick="this.closest('div').parentElement.innerHTML='<div class=\\'empty\\'style=\\'padding:12px\\'>Click Scan Network to detect AI services.</div>'" style="background:none;border:1px solid #E5E7EB;color:#6B7280;border-radius:3px;padding:2px 8px;font-size:11px;cursor:pointer">Clear</button>
      </div>`;
      btn.disabled = false;
      btn.textContent = 'Scan Network';
      return; // done
    }}

    // no results yet — keep polling if not timed out
    if (svcs.length !== lastCount) {{
      lastCount    = svcs.length;
      stableRounds = 0;
    }} else {{
      stableRounds++;
    }}

    const timedOut = (Date.now() - started) >= TIMEOUT_MS;
    const stable   = stableRounds >= 2 && svcs.length > 0;

    if (timedOut || stable) {{
      if (svcs.length === 0) {{
        panel.innerHTML = '<div class="empty" style="padding:12px">No AI services detected. The agent scanned the subnet but found nothing new.</div>';
      }}
      btn.disabled = false;
      btn.textContent = 'Scan Network';
      return;
    }}

    countdown();
    setTimeout(poll, POLL_INTERVAL);
  }} catch (e) {{
    panel.innerHTML = '<div class="empty" style="padding:12px;color:#DC2626">Discovery failed: ' + esc(String(e)) + '</div>';
    btn.disabled = false;
    btn.textContent = 'Scan Network';
  }}
  }}

  setTimeout(poll, POLL_INTERVAL);
}}

const _SCAN_PROFILES = [
  {{id:'default',       label:'Base Scan',           desc:'Essential AI security checks — plain language, highest-impact controls first. Best starting point for any organization before moving to a compliance-specific profile.'}},
  {{id:'iso42001',      label:'ISO 42001',           desc:'ISO/IEC 42001:2023 — the international AI Management System standard. Covers governance, lifecycle, supply chain, risk assessment, and monitoring across all industries.'}},
  {{id:'atlas',         label:'MITRE ATLAS',         desc:'MITRE ATLAS adversarial ML threat framework — prompt injection, jailbreak, supply chain compromise, inference API abuse, model exfiltration, and cost harvesting attacks.'}},
  {{id:'fedramp',       label:'FedRAMP',             desc:'FedRAMP Moderate — NIST 800-53 control mappings. Required for federal cloud systems and agency deployments.'}},
  {{id:'fedramp_20x',   label:'FedRAMP 20x',         desc:'FedRAMP 20x Key Security Indicators (KSI) — the next-generation, continuously-validated cloud authorization model from GSA. Currently in pilot; use for readiness, not authorization.'}},
  {{id:'cmmc',          label:'CMMC 2.0',            desc:'Cybersecurity Maturity Model Certification — required for DoD contractors handling CUI.'}},
  {{id:'financial',     label:'Financial Services',  desc:'Financial sector AI controls — SOC 2, FFIEC, SR 11-7 model risk guidance.'}},
  {{id:'biotech',       label:'Biotech',             desc:'FDA 21 CFR Part 11, HIPAA, ICH E6(R2), GxP — for pharma and biotech AI systems.'}},
  {{id:'healthcare',    label:'Healthcare',          desc:'HIPAA, HITECH, FDA SaMD guidance — for clinical AI, EHR systems, and patient data protection.'}},
  {{id:'owasp_agentic', label:'OWASP Agentic',       desc:'OWASP Top 10 for Agentic AI (2026) — tool hijacking, prompt injection, excessive agency, rogue agents.'}},
  {{id:'eu_ai_act',     label:'EU AI Act',           desc:'EU AI Act Articles 9-15 — mandatory for high-risk AI systems in Europe. Enforcement begins August 2026.'}},
];

function openScanModal(id, triggerBtn) {{
  // Remove any existing modal
  const old = document.getElementById('scan-modal-overlay');
  if (old) {{ old.remove(); if (old.dataset.deviceId === id) return; }}

  const overlay = document.createElement('div');
  overlay.id = 'scan-modal-overlay';
  overlay.dataset.deviceId = id;
  overlay.style.cssText = 'position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,.55);display:flex;align-items:center;justify-content:center';

  const modal = document.createElement('div');
  modal.style.cssText = 'background:#ffffff;border:1px solid #E5E7EB;border-radius:8px;padding:20px 24px;min-width:280px;max-width:380px;max-height:85vh;display:flex;flex-direction:column;box-shadow:0 8px 32px rgba(0,0,0,.6)';

  const hostname = triggerBtn.closest('tr')?.querySelector('.dev-host')?.textContent || id.slice(0,12);

  modal.innerHTML = `
    <div style="font-size:13px;font-weight:600;color:#111827;margin-bottom:4px;flex-shrink:0">Select Profiles to Scan</div>
    <div style="font-size:11px;color:#6B7280;margin-bottom:14px;flex-shrink:0">${{esc(hostname)}}</div>
    <div id="smp-list" style="display:flex;flex-direction:column;gap:8px;margin-bottom:16px;overflow-y:auto;max-height:55vh;padding-right:4px">
      ${{_SCAN_PROFILES.map(p => `
        <label style="display:flex;align-items:flex-start;gap:10px;cursor:pointer;padding:7px 10px;border:1px solid #F3F4F6;border-radius:5px;transition:border-color .15s"
               onmouseover="this.style.borderColor='#E5E7EB'" onmouseout="this.style.borderColor='#F3F4F6'">
          <input type="checkbox" value="${{p.id}}" style="margin-top:2px;accent-color:#4F46E5;cursor:pointer">
          <span>
            <span style="font-size:12px;font-weight:600;color:#111827;display:block">${{p.label}}</span>
            <span style="font-size:11px;color:#6B7280">${{p.desc}}</span>
          </span>
        </label>`).join('')}}
    </div>
    <div style="display:flex;gap:8px;justify-content:flex-end">
      <button id="smp-cancel" style="background:none;border:1px solid #E5E7EB;color:#6B7280;border-radius:4px;padding:5px 14px;font-size:12px;cursor:pointer">Cancel</button>
      <button id="smp-run" style="background:#1f6feb;border:1px solid #1f6feb;color:#fff;border-radius:4px;padding:5px 14px;font-size:12px;cursor:pointer;font-weight:600" disabled>Run Scans</button>
    </div>`;

  overlay.appendChild(modal);
  document.body.appendChild(overlay);

  const runBtn = modal.querySelector('#smp-run');
  const cancelBtn = modal.querySelector('#smp-cancel');
  const checkboxes = modal.querySelectorAll('input[type=checkbox]');

  const updateRunBtn = () => {{
    const n = [...checkboxes].filter(c => c.checked).length;
    runBtn.disabled = n === 0;
    runBtn.textContent = n > 0 ? `Run ${{n}} Scan${{n > 1 ? 's' : ''}}` : 'Run Scans';
  }};
  checkboxes.forEach(c => c.addEventListener('change', updateRunBtn));

  cancelBtn.onclick = () => overlay.remove();
  overlay.addEventListener('click', e => {{ if (e.target === overlay) overlay.remove(); }});

  runBtn.onclick = async () => {{
    const profiles = [...checkboxes].filter(c => c.checked).map(c => c.value);
    overlay.remove();
    const btn = document.getElementById('sb-' + id);
    if (btn) {{ btn.disabled = true; btn.textContent = 'Queued…'; }}
    try {{
      const resp = await fetch('/api/fleet/scan/' + id, {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify({{profiles}}),
      }});
      const data = await resp.json();
      if (resp.ok) {{
        if (btn) btn.textContent = `Queued (${{profiles.length}}) ✓`;
        setTimeout(() => {{ if (btn) {{ btn.disabled = false; btn.textContent = 'Scan ▾'; }} }}, 6000);
      }} else {{
        if (btn) {{ btn.disabled = false; btn.textContent = 'Scan ▾'; }}
        alert(data.error || 'Failed to queue scan');
      }}
    }} catch (e) {{
      if (btn) {{ btn.disabled = false; btn.textContent = 'Scan ▾'; }}
    }}
  }};
}}

async function updateDevice(id) {{
  const btn = document.getElementById('ub-' + id);
  if (btn) {{ btn.disabled = true; btn.textContent = 'Queued…'; }}
  try {{
    const resp = await fetch('/api/fleet/update/' + id, {{method: 'POST'}});
    const data = await resp.json();
    if (resp.ok) {{
      if (btn) btn.textContent = 'Queued ✓';
      setTimeout(() => {{ if (btn) {{ btn.disabled = false; btn.textContent = 'Update'; }} }}, 8000);
    }} else {{
      if (btn) {{ btn.disabled = false; btn.textContent = 'Error'; }}
      alert(data.error || 'Failed to queue update');
    }}
  }} catch (e) {{
    if (btn) {{ btn.disabled = false; btn.textContent = 'Update'; }}
  }}
}}

function toggleScanProfileMenu(e) {{
  e.stopPropagation();
  const m = document.getElementById('scan-profile-menu');
  if (m) m.style.display = m.style.display === 'none' ? 'block' : 'none';
}}
function updateScanProfileBtn() {{
  const checked = [...document.querySelectorAll('.scan-profile-cb:checked')].map(c => c.value);
  const btn = document.getElementById('scan-profile-btn');
  if (!btn) return;
  if (checked.length === 0)      btn.innerHTML = 'Customer default &#9660;';
  else if (checked.length === 1) btn.innerHTML = (PROFILE_LABELS[checked[0]] || checked[0]) + ' &#9660;';
  else                           btn.innerHTML = checked.length + ' profiles &#9660;';
}}
document.addEventListener('click', function(e) {{
  if (!e.target.closest('#scan-profile-menu') && !e.target.closest('#scan-profile-btn')) {{
    const m = document.getElementById('scan-profile-menu');
    if (m) m.style.display = 'none';
  }}
}});

async function scanAllDevices(btn) {{
  const profiles = [...document.querySelectorAll('.scan-profile-cb:checked')].map(c => c.value);
  const stagger  = document.getElementById('scan-all-stagger')?.value || 'normal';
  btn.disabled   = true;
  btn.textContent = 'Queuing…';
  try {{
    const resp = await fetch('/api/fleet/scan/all', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{profiles, stagger}})
    }});
    const data = await resp.json();
    if (resp.ok) {{
      const label = stagger === 'instant' ? 'all at once' :
                    stagger === 'slow'    ? `10 per 60s` : `25 per 30s`;
      btn.textContent = `Dispatching ${{data.total}} (${{label}})`;
      // A command is normally claimed within 15 seconds; refresh promptly so
      // the operator sees the resulting profile/report without reloading.
      [15000, 30000, 60000].forEach(delay => setTimeout(refreshDevices, delay));
      setTimeout(() => {{ btn.disabled = false; btn.textContent = '►► Scan All'; }}, 10000);
    }} else {{
      btn.disabled = false;
      btn.textContent = '►► Scan All';
      alert(data.error || 'Scan All failed');
    }}
  }} catch (e) {{
    btn.disabled = false;
    btn.textContent = '►► Scan All';
  }}
}}

async function updateAllDevices() {{
  const btn = event.currentTarget;
  btn.disabled = true;
  btn.textContent = 'Queuing…';
  try {{
    const resp = await fetch('/api/fleet/update/all', {{method: 'POST'}});
    const data = await resp.json();
    if (resp.ok) {{
      btn.textContent = `Queued (${{data.count}})`;
      setTimeout(() => {{ btn.disabled = false; btn.textContent = 'Update All Agents'; }}, 8000);
    }} else {{
      btn.disabled = false;
      btn.textContent = 'Update All Agents';
      alert(data.error || 'Failed to queue updates');
    }}
  }} catch (e) {{
    btn.disabled = false;
    btn.textContent = 'Update All Agents';
  }}
}}

async function discoverAll(btn) {{
  btn.disabled = true;
  btn.innerHTML = 'Queuing…';
  try {{
    const resp = await fetch('/api/fleet/discover/all', {{method: 'POST'}});
    const data = await resp.json();
    if (resp.ok) {{
      btn.innerHTML = `Queued (${{data.count}}) — agents scanning…`;
      setTimeout(() => {{
        btn.disabled = false;
        btn.disabled = false;
        btn.innerHTML = '&#128270; Run Shadow AI Scan';
        refreshShadow();
      }}, 45000);
    }} else {{
      btn.disabled = false;
      btn.innerHTML = '&#128270; Run Shadow AI Scan';
      alert(data.error || 'Failed to queue discovery');
    }}
  }} catch (e) {{
    btn.disabled = false;
    btn.innerHTML = '&#128270; Run Shadow AI Scan';
  }}
}}

async function discoverNetworkAssets(all, btn) {{
  const device = document.getElementById('network-asset-device')?.value;
  if (!all && !device) {{ alert('Select an agent first.'); return; }}
  const label = btn.textContent;
  btn.disabled = true; btn.textContent = 'Queuing…';
  try {{
    const path = all ? '/api/fleet/network-assets/discover/all' :
      '/api/fleet/network-assets/discover/' + encodeURIComponent(device);
    const resp = await fetch(path, {{method: 'POST'}});
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || 'request failed');
    btn.textContent = 'Queued (' + (data.count || 1) + ')';
    setTimeout(() => location.reload(), 30000);
  }} catch (e) {{ alert('Passive collection failed: ' + e.message); btn.textContent = label; }}
  finally {{ setTimeout(() => {{ btn.disabled = false; btn.textContent = label; }}, 3000); }}
}}

async function dismissShadow(id) {{
  if (!confirm('Dismiss this finding? It will reappear if rediscovered.')) return;
  const resp = await fetch('/api/fleet/shadow/dismiss/' + id, {{method: 'POST'}});
  if (resp.ok) {{ refreshShadow(); }}
}}

async function dismissAllShadow() {{
  if (!confirm('Dismiss all Shadow AI findings? They will reappear if rediscovered on the next scan.')) return;
  const resp = await fetch('/api/fleet/shadow/dismiss/all', {{method: 'POST'}});
  if (resp.ok) {{ refreshShadow(); }}
}}

async function dismissShadowGroup(idsStr) {{
  const ids = idsStr.split(',').map(s => s.trim()).filter(Boolean);
  await Promise.all(ids.map(id => fetch('/api/fleet/shadow/dismiss/' + id, {{method:'POST'}})));
  refreshShadow();
}}

const _SHADOW_SRC = {{
  network:   {{icon:'&#127760;', color:'#a371f7', label:'Network'}},
  cloud_api: {{icon:'&#9729;',   color:'#4F46E5', label:'Cloud API'}},
  process:   {{icon:'&#9881;',   color:'#f0883e', label:'Process'}},
  docker:    {{icon:'&#128051;', color:'#16A34A', label:'Container'}},
  saas_ai:   {{icon:'&#128101;', color:'#f78166', label:'SaaS AI'}},
}};

async function loadK8sStatus() {{
  const panel = document.getElementById('k8s-status-panel');
  if (!panel) return;
  try {{
    const resp = await fetch('/api/fleet/k8s-status');
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    const data = await resp.json();
    if (!data.connected) {{
      panel.innerHTML = `
        <div style="display:flex;align-items:center;gap:12px;padding:4px 0">
          <span style="font-size:22px;opacity:.5">⊞</span>
          <div>
            <div style="font-size:13px;font-weight:600;color:#374151">No cluster connected</div>
            <div style="font-size:12px;color:#9CA3AF;margin-top:2px">
              Install the Arckon agent on a machine with <code style="font-size:11px;background:#F3F4F6;padding:1px 5px;border-radius:3px">kubectl</code> configured.
              The agent detects and scans the cluster automatically.
            </div>
          </div>
        </div>`;
      return;
    }}
    const rows = (data.clusters || []).map(c => {{
      const risk = c.fail > 0 ? '#EF4444' : (c.warn > 0 ? '#F59E0B' : '#10B981');
      return `<div style="display:flex;align-items:center;gap:14px;padding:6px 0;border-bottom:1px solid #F3F4F6">
        <span style="font-size:16px">⊞</span>
        <div style="flex:1;min-width:0">
          <div style="font-size:13px;font-weight:600;color:#111827;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${{esc(c.label)}}</div>
          <div style="font-size:11px;color:#9CA3AF;margin-top:1px">last seen ${{c.last_seen ? new Date(c.last_seen*1000).toLocaleString() : 'never'}}</div>
        </div>
        <div style="display:flex;gap:10px;font-size:12px;font-weight:600;white-space:nowrap">
          <span style="color:#EF4444">${{c.fail}} fail</span>
          <span style="color:#F59E0B">${{c.warn}} warn</span>
          <span style="color:#10B981">${{c.pass}} pass</span>
        </div>
        <span style="width:8px;height:8px;border-radius:50%;background:${{risk}};flex-shrink:0"></span>
      </div>`;
    }}).join('');
    panel.innerHTML = rows || '<div style="font-size:12px;color:#9CA3AF">No cluster data yet.</div>';
  }} catch(e) {{
    panel.innerHTML = '<div style="font-size:12px;color:#9CA3AF">Could not load cluster status.</div>';
  }}
}}

async function refreshShadow() {{
  try {{
    const resp = await fetch('/api/fleet/shadow');
    if (!resp.ok) return;
    const data = await resp.json();
    const sc = document.getElementById('sc-shadow');
    if (sc) sc.textContent = data.count || 0;
    const container = document.getElementById('shadow-cards');
    if (!container) return;
    const devs = data.devices || [];
    if (!devs.length) {{
      container.innerHTML = '<div class="empty" style="padding:20px;text-align:center;color:#9CA3AF">No Shadow AI detected yet. Click <strong style="color:#a371f7">Find Shadow AI</strong> above to scan your network through all installed agents.</div>';
      return;
    }}
    const _modelTags = (models) => {{
      const shown = (models||[]).slice(0,5);
      const extra = (models||[]).length > 5 ? ` <span style="font-size:11px;color:#6B7280">+${{(models||[]).length-5}} more</span>` : '';
      return shown.map(m => `<span style="background:#F9FAFB;border:1px solid #E5E7EB;border-radius:3px;padding:1px 8px;font-size:11px;font-family:monospace;color:#374151">${{esc(m)}}</span>`).join(' ') + extra;
    }};

    const dockerItems = devs.filter(d => d.source === 'docker');
    const otherItems  = devs.filter(d => d.source !== 'docker');

    // Group non-docker items by service name to avoid showing 20+ cards for the same service
    const _svcGroups = {{}};
    for (const d of otherItems) {{
      const key = (d.source || 'network') + '||' + (d.service || d.host);
      if (!_svcGroups[key]) _svcGroups[key] = [];
      _svcGroups[key].push(d);
    }}
    const otherHtml = Object.values(_svcGroups).map(grp => {{
      const d = grp[0];
      const src = _SHADOW_SRC[d.source] || _SHADOW_SRC.network;
      const age = _age(d.last_seen);
      const cnt = grp.length;
      const endpointNote = cnt > 1
        ? `<span style="font-size:11px;color:#9CA3AF;margin-left:6px">(${{cnt}} endpoints)</span>`
        : '';
      const locationHtml = `<span style="font-weight:700;color:#111827;font-size:14px">${{esc(d.service)}}</span>${{endpointNote}}`;
      const subHtml = d.source === 'network'
        ? `<div style="font-size:12px;color:${{src.color}};margin-bottom:8px">${{cnt > 1 ? cnt+' network endpoints' : esc(d.host)+(d.port?':'+d.port:'')}}</div>`
        : d.detail ? `<div style="font-size:12px;color:#6B7280;margin-bottom:8px">${{esc(d.detail)}}</div>` : '';
      const allModels = [...new Set(grp.flatMap(x => x.models||[]))];
      const modelSection = allModels.length
        ? `<div style="display:flex;flex-wrap:wrap;gap:5px;align-items:center">${{_modelTags(allModels)}}</div>`
        : `<div style="font-size:11px;color:#9CA3AF">No model details available</div>`;
      const allIds = grp.map(x => x.id).join(',');
      return `<div class="shadow-card" style="border-left-color:${{src.color}}">
        <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px">
          <div style="flex:1;min-width:0">
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
              <span style="font-size:16px">${{src.icon}}</span>
              ${{locationHtml}}
              <span style="font-size:10px;font-weight:700;padding:1px 7px;border-radius:3px;background:#1a1f2e;color:${{src.color}};border:1px solid ${{src.color}};text-transform:uppercase">${{src.label}}</span>
            </div>
            ${{subHtml}}
            ${{modelSection}}
          </div>
          <div style="text-align:right;flex-shrink:0;min-width:130px">
            <div style="font-size:11px;color:#9CA3AF;margin-bottom:8px">Detected ${{age}}</div>
            ${{d.source === 'saas_ai' ? `<button class="scan-btn" onclick="shadowApproveGlobally('${{esc(d.service)}}',this)" style="font-size:11px;color:#a371f7;border-color:#6e40c9;margin-bottom:4px;display:block;width:100%">&#9733; Approve globally</button>` : ''}}
            <button class="scan-btn" onclick="navTo('inventory')" style="font-size:11px;color:#4F46E5;border-color:#4F46E5;margin-bottom:4px;display:block;width:100%">&#128196; View in Inventory</button>
            <button class="scan-btn" onclick="dismissShadowGroup('${{allIds}}')" style="font-size:11px;color:#6e7681;border-color:#30363d;display:block;width:100%">Dismiss (temp)</button>
          </div>
        </div>
      </div>`;
    }}).join('');

    // Group docker items by the host machine that found them
    const dockerGroups = {{}};
    for (const d of dockerItems) {{
      const key = d.reporter_hostname || 'unknown';
      (dockerGroups[key] = dockerGroups[key] || []).push(d);
    }}

    const dockerHtml = Object.entries(dockerGroups).map(([reporter, items]) => {{
      const latestTs = Math.max(...items.map(i => i.last_seen || 0));
      const cntLabel = `${{items.length}} container${{items.length !== 1 ? 's' : ''}}`;
      const rowsHtml = items.map(d => {{
        const portHtml   = d.port   ? `<span style="font-size:11px;color:#9CA3AF;font-family:monospace">:${{d.port}}</span>` : '';
        const detailHtml = d.detail ? `<span style="font-size:11px;color:#6B7280;font-family:monospace">${{esc(d.detail)}}</span>` : '';
        const modelSection = (d.models||[]).length
          ? `<div style="display:flex;flex-wrap:wrap;gap:4px;align-items:center">${{_modelTags(d.models)}}</div>`
          : `<div style="font-size:11px;color:#9CA3AF">No model details available</div>`;
        return `<div style="background:#F9FAFB;border:1px solid #F3F4F6;border-radius:6px;padding:10px 14px;margin-bottom:8px">
          <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:8px">
            <div style="flex:1;min-width:0">
              <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-bottom:5px">
                <span style="font-size:13px;color:#111827;font-weight:600">${{esc(d.service)}}</span>
                ${{detailHtml}}${{portHtml}}
              </div>
              ${{modelSection}}
            </div>
            <div style="text-align:right;flex-shrink:0;min-width:80px">
              <div style="font-size:11px;color:#9CA3AF;margin-bottom:6px">${{_age(d.last_seen)}}</div>
              <button class="scan-btn" onclick="dismissShadow(${{d.id}})" style="font-size:11px;color:#6B7280;border-color:#E5E7EB">Dismiss</button>
            </div>
          </div>
        </div>`;
      }}).join('');
      return `<div class="shadow-card" style="border-left-color:#16A34A;padding:0;overflow:hidden">
        <div style="display:flex;align-items:center;gap:8px;padding:12px 14px 10px;background:#0f1f14;border-bottom:1px solid #1a3020;margin-bottom:10px">
          <span style="font-size:18px">&#128051;</span>
          <span style="font-weight:700;color:#111827;font-size:14px">${{esc(reporter)}}</span>
          <span style="font-size:10px;font-weight:700;padding:1px 7px;border-radius:3px;background:#DCFCE7;color:#16A34A;border:1px solid #3fb950;text-transform:uppercase">Docker Host</span>
          <span style="font-size:11px;color:#9CA3AF;margin-left:auto">${{cntLabel}} &nbsp;&middot;&nbsp; last seen ${{_age(latestTs)}}</span>
        </div>
        <div style="padding:0 14px 12px">${{rowsHtml}}</div>
      </div>`;
    }}).join('');

    container.innerHTML = otherHtml + dockerHtml;
  }} catch (_) {{ /* ignore */ }}
}}

async function discoverMcp(btn) {{
  btn.innerHTML = '&#8987; Scanning...';
  btn.disabled = true;
  try {{
    const resp = await fetch('/api/fleet/mcp/discover/all', {{method:'POST'}});
    if (resp.ok) {{
      const d = await resp.json();
      btn.innerHTML = `&#128279; Queued ${{d.count || 0}} agent${{d.count !== 1 ? 's' : ''}}`;
      setTimeout(() => {{ refreshMcp(); btn.innerHTML = '&#128279; Scan MCP Servers'; btn.disabled = false; }}, 45000);
    }} else {{
      btn.innerHTML = '&#128279; Scan MCP Servers';
      btn.disabled = false;
    }}
  }} catch(_) {{ btn.innerHTML = '&#128279; Scan MCP Servers'; btn.disabled = false; }}
}}

async function dismissMcp(id) {{
  if (!confirm('Dismiss this MCP server? It will reappear if rediscovered.')) return;
  const resp = await fetch('/api/fleet/mcp/dismiss/' + id, {{method: 'POST'}});
  if (resp.ok) {{ refreshMcp(); }}
}}

async function dismissAllMcp() {{
  if (!confirm('Dismiss all MCP server findings? They will reappear if rediscovered on the next scan.')) return;
  const resp = await fetch('/api/fleet/mcp/dismiss/all', {{method: 'POST'}});
  if (resp.ok) {{ refreshMcp(); }}
}}

const _MCP_AUTH = {{
  none:     {{color:'#DC2626', label:'No Auth',  risk: true}},
  unknown:  {{color:'#e3b341', label:'Auth?',    risk: false}},
  required: {{color:'#16A34A', label:'Auth OK',  risk: false}},
}};

async function refreshMcp() {{
  try {{
    const resp = await fetch('/api/fleet/mcp');
    if (!resp.ok) return;
    const data = await resp.json();
    const sc = document.getElementById('sc-mcp');
    if (sc) sc.textContent = data.count || 0;
    const container = document.getElementById('mcp-cards');
    if (!container) return;
    const servers = data.servers || [];
    if (!servers.length) {{
      container.innerHTML = '<div class="empty" style="padding:20px;text-align:center;color:#9CA3AF">No MCP servers detected yet. Click <strong style="color:#4F46E5">Scan MCP Servers</strong> above to scan your network through all installed agents.</div>';
      return;
    }}
    container.innerHTML = servers.map(s => {{
      const auth = _MCP_AUTH[s.auth_status] || _MCP_AUTH.unknown;
      const isProcess = s.source === 'process';
      const locationHtml = isProcess
        ? `<span style="font-weight:700;color:#111827;font-size:14px">MCP Server Process</span>`
        : `<span style="font-weight:700;color:#111827;font-size:14px">${{esc(s.host)}}:${{s.port}}</span>`;
      const subHtml = isProcess
        ? (s.process_info ? `<div style="font-size:11px;color:#6B7280;font-family:monospace;margin-bottom:6px">${{esc(s.process_info.substring(0,80))}}</div>` : '')
        : `<div style="font-size:12px;color:#4F46E5;margin-bottom:6px">${{esc(s.server_name || 'MCP Server')}}</div>`;
      const tools = (s.tools||[]).slice(0,6);
      const toolTags = tools.map(t => `<span style="background:#F9FAFB;border:1px solid #E5E7EB;border-radius:3px;padding:1px 8px;font-size:11px;font-family:monospace;color:#374151">${{esc(t)}}</span>`).join(' ');
      const toolExtra = (s.tools||[]).length > 6 ? `<span style="font-size:11px;color:#6B7280">+${{(s.tools||[]).length-6}} more</span>` : '';
      const toolSection = (s.tools||[]).length
        ? `<div style="display:flex;flex-wrap:wrap;gap:5px;align-items:center">${{toolTags}}${{toolExtra}}</div>`
        : `<div style="font-size:11px;color:#9CA3AF">No tools enumerated</div>`;
      const riskNote = auth.risk
        ? `<div style="font-size:11px;color:#DC2626;margin-top:4px;font-weight:600">&#9888; Unauthenticated — any AI agent can connect to this server</div>` : '';
      return `<div class="shadow-card" style="border-left-color:${{auth.color}}">
        <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px">
          <div style="flex:1;min-width:0">
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
              <span style="font-size:16px">&#128279;</span>
              ${{locationHtml}}
              <span style="font-size:10px;font-weight:700;padding:1px 7px;border-radius:3px;background:#1a1f2e;color:${{auth.color}};border:1px solid ${{auth.color}};text-transform:uppercase">${{auth.label}}</span>
              <span style="font-size:10px;padding:1px 7px;border-radius:3px;background:#F9FAFB;color:#6B7280;border:1px solid #E5E7EB;text-transform:uppercase">${{isProcess ? 'Process' : 'Network'}}</span>
            </div>
            ${{subHtml}}
            ${{toolSection}}
            ${{riskNote}}
          </div>
          <div style="text-align:right;flex-shrink:0">
            <div style="font-size:11px;color:#9CA3AF;margin-bottom:3px">Found ${{_age(s.last_seen)}}</div>
            <div style="font-size:11px;color:#6B7280;margin-bottom:8px">via ${{esc(s.reporter_hostname)}}</div>
            <button class="scan-btn" onclick="dismissMcp(${{s.id}})" style="font-size:11px;color:#6B7280;border-color:#E5E7EB">Dismiss</button>
          </div>
        </div>
      </div>`;
    }}).join('');
  }} catch (_) {{ /* ignore */ }}
}}

async function selectDevice(id) {{
  navTo('findings');
  const sel = document.getElementById('findings-device-sel');
  if (sel && sel.value !== id) sel.value = id;
  const panel = document.getElementById('detail-panel');
  panel.style.padding = '0';
  panel.style.minHeight = 'unset';
  panel.innerHTML = `
    <div style="display:flex;align-items:center;justify-content:space-between;
                padding:0 16px 0 0;background:#ffffff;border-radius:8px 8px 0 0;
                border-bottom:1px solid #E5E7EB">
      <div style="display:flex;align-items:center;gap:0">
        <button id="tab-btn-dash" onclick="showDashTab('${{id}}')"
          style="background:none;border:none;border-bottom:2px solid #58a6ff;color:#111827;
                 font-size:13px;font-weight:600;padding:10px 16px 8px;cursor:pointer">Dashboard</button>
        <button id="tab-btn-trend" onclick="showTrendTab('${{id}}')"
          style="background:none;border:none;border-bottom:2px solid transparent;color:#6B7280;
                 font-size:13px;font-weight:400;padding:10px 16px 8px;cursor:pointer">Trend</button>
      </div>
      <div style="display:flex;gap:8px;align-items:center">
        <span id="dash-title" style="font-size:12px;color:#6B7280"></span>
        <a id="dash-ext" href="/fleet/device/${{id}}/dashboard" target="_blank"
           style="font-size:11px;color:#4F46E5;text-decoration:none">open in new tab ↗</a>
        <a href="/fleet/device/${{id}}/report.pdf"
           style="font-size:11px;color:#16A34A;text-decoration:none">&#8659; Download PDF</a>
        <button onclick="closeDevice()"
                style="background:none;border:1px solid #E5E7EB;color:#6B7280;
                       border-radius:4px;padding:2px 9px;font-size:12px;cursor:pointer">✕</button>
      </div>
    </div>
    <div id="device-dash-pane">
      <iframe src="/fleet/device/${{id}}/dashboard"
              style="width:100%;height:calc(100vh - 280px);min-height:580px;
                     border:none;display:block;border-radius:0 0 8px 8px">
      </iframe>
    </div>
    <div id="device-trend-pane" style="display:none;padding:20px 16px;min-height:300px">
      <div id="trend-chart" style="color:#6B7280;font-size:13px">Loading trend data…</div>
    </div>`;
  try {{
    const r = await fetch('/api/devices/' + id);
    if (r.ok) {{
      const d = await r.json();
      const el = document.getElementById('dash-title');
      if (el) {{
        const s = d.summary || {{}};
        el.textContent = (d._hostname || id) + ' — ' + (s.fail||0) + ' fail · ' + (s.warn||0) + ' warn · ' + (s.pass||0) + ' pass';
      }}
    }}
  }} catch (_) {{}}
}}

function showDashTab(id) {{
  const dp = document.getElementById('device-dash-pane');
  const tp = document.getElementById('device-trend-pane');
  if (dp) dp.style.display = '';
  if (tp) tp.style.display = 'none';
  const b1 = document.getElementById('tab-btn-dash'), b2 = document.getElementById('tab-btn-trend');
  if (b1) {{ b1.style.borderBottomColor = '#4F46E5'; b1.style.color = '#111827'; b1.style.fontWeight = '600'; }}
  if (b2) {{ b2.style.borderBottomColor = 'transparent'; b2.style.color = '#6B7280'; b2.style.fontWeight = '400'; }}
}}

async function showTrendTab(id) {{
  const dp = document.getElementById('device-dash-pane');
  const tp = document.getElementById('device-trend-pane');
  if (dp) dp.style.display = 'none';
  if (tp) tp.style.display = '';
  const b1 = document.getElementById('tab-btn-dash'), b2 = document.getElementById('tab-btn-trend');
  if (b1) {{ b1.style.borderBottomColor = 'transparent'; b1.style.color = '#6B7280'; b1.style.fontWeight = '400'; }}
  if (b2) {{ b2.style.borderBottomColor = '#4F46E5'; b2.style.color = '#111827'; b2.style.fontWeight = '600'; }}
  const chart = document.getElementById('trend-chart');
  if (!chart) return;
  chart.textContent = 'Loading…';
  try {{
    const r = await fetch('/fleet/device/' + id + '/timeseries.json');
    const data = await r.json();
    chart.innerHTML = renderTrendChart(data.points || []);
  }} catch (e) {{
    chart.innerHTML = '<div style="color:#DC2626;padding:20px">Failed to load trend data: ' + e + '</div>';
  }}
}}

function renderTrendChart(points) {{
  if (!points.length) {{
    return '<div style="padding:48px;text-align:center;color:#9CA3AF">No historical data yet.<br>'
      + '<small style="color:#9CA3AF">The trend view populates after the device completes multiple scans.</small></div>';
  }}
  const W = 680, H = 220, padL = 50, padR = 20, padT = 22, padB = 44;
  const cW = W - padL - padR, cH = H - padT - padB;
  const n = points.length;
  const maxVal = Math.max(1, ...points.map(function(p) {{ return Math.max(p.fail||0, p.warn||0, p.pass||0); }}));
  function xp(i) {{ return padL + (n === 1 ? cW/2 : i/(n-1)*cW); }}
  function yp(v) {{ return padT + (1 - v/maxVal)*cH; }}
  function mkline(ser, col) {{
    const pts = points.map(function(p,i) {{ return xp(i)+','+yp(p[ser]||0); }}).join(' ');
    return '<polyline points="'+pts+'" fill="none" stroke="'+col+'" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>';
  }}
  function mkdots(ser, col) {{
    return points.map(function(p,i) {{
      return '<circle cx="'+xp(i)+'" cy="'+yp(p[ser]||0)+'" r="3.5" fill="'+col+'" stroke="#F9FAFB" stroke-width="1"/>';
    }}).join('');
  }}
  let grid = '';
  for (let k = 0; k <= 4; k++) {{
    const yy = padT + (k/4)*cH;
    const v = Math.round(maxVal*(1 - k/4));
    grid += '<line x1="'+padL+'" y1="'+yy+'" x2="'+(padL+cW)+'" y2="'+yy+'" stroke="#E5E7EB" stroke-width="1"/>'
          + '<text x="'+(padL-6)+'" y="'+(yy+4)+'" text-anchor="end" font-size="10" fill="#6B7280">'+v+'</text>';
  }}
  let xlabels = '';
  const step = Math.max(1, Math.floor((n-1)/5));
  for (let i = 0; i < n; i++) {{
    if (i % step !== 0 && i !== n-1) continue;
    const d = new Date(points[i].t * 1000);
    const lbl = String(d.getMonth()+1).padStart(2,'0')+'-'+String(d.getDate()).padStart(2,'0');
    xlabels += '<text x="'+xp(i)+'" y="'+(padT+cH+16)+'" text-anchor="middle" font-size="10" fill="#6B7280">'+lbl+'</text>';
  }}
  return '<div style="overflow-x:auto">'
    + '<svg viewBox="0 0 '+W+' '+H+'" style="width:100%;max-width:'+W+'px;display:block" xmlns="http://www.w3.org/2000/svg">'
    + grid
    + '<line x1="'+padL+'" y1="'+padT+'" x2="'+padL+'" y2="'+(padT+cH)+'" stroke="#E5E7EB" stroke-width="1"/>'
    + '<line x1="'+padL+'" y1="'+(padT+cH)+'" x2="'+(padL+cW)+'" y2="'+(padT+cH)+'" stroke="#E5E7EB" stroke-width="1"/>'
    + mkline('fail','#DC2626') + mkline('warn','#CA8A04') + mkline('pass','#16A34A')
    + mkdots('fail','#DC2626') + mkdots('warn','#CA8A04') + mkdots('pass','#16A34A')
    + xlabels
    + '<circle cx="'+(padL+10)+'" cy="12" r="4" fill="#f85149"/><text x="'+(padL+18)+'" y="16" font-size="11" fill="#6B7280">HIGH</text>'
    + '<circle cx="'+(padL+58)+'" cy="12" r="4" fill="#d29922"/><text x="'+(padL+66)+'" y="16" font-size="11" fill="#6B7280">MEDIUM</text>'
    + '<circle cx="'+(padL+106)+'" cy="12" r="4" fill="#4F46E5"/><text x="'+(padL+114)+'" y="16" font-size="11" fill="#6B7280">INFO</text>'
    + '</svg></div>';
}}

function closeDevice() {{
  const panel = document.getElementById('detail-panel');
  panel.style.padding = '';
  panel.style.minHeight = '';
  panel.innerHTML = '<div class="empty">← Click a device row to view its dashboard</div>';
}}

function _sysLog(msg, color) {{
  const el = document.getElementById('sys-log');
  if (!el) return;
  el.style.display = 'block';
  el.style.color = color || '#6B7280';
  el.textContent = msg;
}}

function _rptProfileParam() {{
  const checked = [...document.querySelectorAll('.rpt-profile:checked')].map(c => c.value);
  return checked.length ? '&profile=' + checked.join(',') : '';
}}
function openReport(tier) {{
  window.open('/api/fleet/report?tier=' + tier + '&fmt=html' + _rptProfileParam(), '_blank');
}}
function rptPreview(tier) {{
  window.open('/api/fleet/report?tier=' + tier + '&fmt=html' + _rptProfileParam(), '_blank');
}}
function rptPreviewMcp(tier) {{
  window.open('/api/fleet/mcp/report?tier=' + tier, '_blank');
}}
async function rptDownloadPdf(tier, btn) {{
  const orig = btn.textContent;
  btn.disabled = true; btn.textContent = 'Generating…';
  try {{
    const r = await fetch('/api/fleet/report?tier=' + tier + '&fmt=pdf' + _rptProfileParam());
    if (!r.ok) {{ alert('Report failed: ' + await r.text().catch(() => r.status)); return; }}
    const blob = await r.blob();
    if (!blob.size) {{ alert('Server returned an empty PDF — check server log.'); return; }}
    const a = Object.assign(document.createElement('a'), {{
      href: URL.createObjectURL(blob),
      download: 'sentinel_fleet_' + tier + '.pdf'
    }});
    document.body.appendChild(a); a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(a.href);
  }} catch(e) {{ alert('Download error: ' + e); }}
  finally {{ btn.disabled = false; btn.textContent = orig; }}
}}
async function rptDownloadMcpPdf(tier, btn) {{
  const orig = btn.textContent;
  btn.disabled = true; btn.textContent = 'Generating…';
  try {{
    const r = await fetch('/api/fleet/mcp/report?tier=' + tier + '&fmt=pdf');
    if (!r.ok) {{ alert('Report failed: ' + await r.text().catch(() => r.status)); return; }}
    const blob = await r.blob();
    if (!blob.size) {{ alert('Server returned an empty PDF — check server log.'); return; }}
    const a = Object.assign(document.createElement('a'), {{
      href: URL.createObjectURL(blob),
      download: 'sentinel_mcp_' + tier + '.pdf'
    }});
    document.body.appendChild(a); a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(a.href);
  }} catch(e) {{ alert('Download error: ' + e); }}
  finally {{ btn.disabled = false; btn.textContent = orig; }}
}}

async function downloadFleetReport(tier, btn) {{
  const orig = btn.textContent;
  btn.disabled = true;
  btn.textContent = 'Generating…';
  try {{
    const r = await fetch('/api/fleet/report?tier=' + tier + '&fmt=pdf');
    if (!r.ok) {{
      const msg = await r.text().catch(() => r.status);
      alert('Report failed: ' + msg);
      return;
    }}
    const blob = await r.blob();
    if (blob.size === 0) {{
      alert('Server returned an empty PDF. Check .sentinel.log for details.');
      return;
    }}
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = 'sentinel_fleet_' + tier + '.pdf';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }} catch(e) {{
    alert('Download error: ' + e);
  }} finally {{
    btn.disabled  = false;
    btn.textContent = orig;
  }}
}}

// ── AI Spend ─────────────────────────────────────────────────────────────
async function loadSpend(btn) {{
  const daysSel = document.getElementById('spend-days');
  const days = daysSel ? daysSel.value : 30;
  const orig = btn ? btn.textContent : '';
  if (btn) {{ btn.disabled = true; btn.textContent = 'Loading…'; }}
  try {{
    const [sumRes, modelRes, provRes, dailyRes] = await Promise.all([
      fetch('/api/spend/summary?days=' + days),
      fetch('/api/spend/by-model?days=' + days),
      fetch('/api/spend/by-provider?days=' + days),
      fetch('/api/spend/daily?days=' + days),
    ]);
    if (!sumRes.ok) throw new Error('spend summary failed');
    const sum = await sumRes.json();
    const models = (await modelRes.json()).items || [];
    const providers = (await provRes.json()).items || [];
    const daily = (await dailyRes.json()).items || [];

    // Summary cards
    const cards = document.getElementById('spend-summary-cards');
    cards.innerHTML = [
      _spendCard('Total cost', '$' + (sum.total_cost_usd || 0).toFixed(2), '#DC2626'),
      _spendCard('Total tokens', (sum.total_tokens || 0).toLocaleString(), '#4F46E5'),
      _spendCard('Input tokens', (sum.input_tokens || 0).toLocaleString(), '#6B7280'),
      _spendCard('Output tokens', (sum.output_tokens || 0).toLocaleString(), '#6B7280'),
    ].join('');

    // By provider
    const provDiv = document.getElementById('spend-by-provider');
    if (!providers.length) {{
      provDiv.innerHTML = '<div style="color:#9CA3AF;font-size:13px;padding:12px 0">No spend data yet. Click Fetch Latest to pull from your configured providers.</div>';
    }} else {{
      provDiv.innerHTML = providers.map(p =>
        _spendBar(p.provider, p.cost_usd, p.total_tokens, providers[0].cost_usd || 1)
      ).join('');
    }}

    // By model table
    const modelBody = document.getElementById('spend-by-model-body');
    if (!models.length) {{
      modelBody.innerHTML = '<tr><td colspan="6" style="color:#9CA3AF;font-size:13px;padding:12px 0">No model data yet.</td></tr>';
    }} else {{
      modelBody.innerHTML = models.map(m =>
        '<tr><td>' + (m.provider||'') + '</td><td>' + (m.model||'') + '</td>' +
        '<td style="text-align:right">' + (m.input_tokens||0).toLocaleString() + '</td>' +
        '<td style="text-align:right">' + (m.output_tokens||0).toLocaleString() + '</td>' +
        '<td style="text-align:right">' + (m.total_tokens||0).toLocaleString() + '</td>' +
        '<td style="text-align:right;font-weight:600">$' + (m.cost_usd||0).toFixed(2) + '</td></tr>'
      ).join('');
    }}

    // Daily trend
    const dailyDiv = document.getElementById('spend-daily');
    if (!daily.length) {{
      dailyDiv.innerHTML = '<div style="color:#9CA3AF;font-size:13px;padding:12px 0">No daily data yet.</div>';
    }} else {{
      const maxCost = Math.max(...daily.map(d => d.cost_usd || 0), 0.01);
      dailyDiv.innerHTML = daily.map(d =>
        _spendBar(d.period_date, d.cost_usd, d.total_tokens, maxCost, true)
      ).join('');
    }}

    // MSP-only sections: try to load by-client-org and by-api-key. These
    // 403 for client_viewers, which is the intended scoping — we hide them.
    loadSpendMspSections(days);
  }} catch(e) {{
    document.getElementById('spend-by-provider').innerHTML =
      '<div style="color:#DC2626;font-size:13px;padding:12px 0">Error loading spend: ' + e + '</div>';
  }} finally {{
    if (btn) {{ btn.disabled = false; btn.textContent = orig; }}
  }}
}}

async function loadSpendMspSections(days) {{
  // by-client-org
  try {{
    const r = await fetch('/api/spend/by-client-org?days=' + days);
    if (r.ok) {{
      const items = (await r.json()).items || [];
      document.getElementById('spend-msp-section').style.display = 'block';
      const body = document.getElementById('spend-by-client-org-body');
      if (!items.length) {{
        body.innerHTML = '<tr><td colspan="5" style="color:#9CA3AF;font-size:13px;padding:12px 0">No client org data yet.</td></tr>';
      }} else {{
        body.innerHTML = items.map(o =>
          '<tr><td>' + (o.client_org_id || '(unscoped)') + '</td>' +
          '<td style="text-align:right">' + (o.provider_count||0) + '</td>' +
          '<td style="text-align:right">' + (o.model_count||0) + '</td>' +
          '<td style="text-align:right">' + (o.total_tokens||0).toLocaleString() + '</td>' +
          '<td style="text-align:right;font-weight:600">$' + (o.cost_usd||0).toFixed(2) + '</td></tr>'
        ).join('');
      }}
    }}
  }} catch(e) {{ /* 403 for client_viewers — expected, leave hidden */ }}

  // by-api-key (keys list + spend)
  try {{
    const kr = await fetch('/api/spend/keys');
    if (kr.ok) {{
      const keys = (await kr.json()).items || [];
      document.getElementById('spend-keys-section').style.display = 'block';
      const body = document.getElementById('spend-keys-body');
      const isMsp = window._spendIsMsp === true;
      const colspan = isMsp ? 6 : 5;
      if (!keys.length) {{
        body.innerHTML = '<tr><td colspan="' + colspan + '" style="color:#9CA3AF;font-size:13px;padding:12px 0">No API keys configured. Click Add / Rotate Key to add one.</td></tr>';
      }} else {{
        body.innerHTML = keys.map(k => {{
          let row = '<tr><td>' + (k.provider||'') + '</td>';
          if (isMsp) row += '<td>' + (k.client_org_id || '(unscoped)') + '</td>';
          row += '<td>' + (k.label||'') + '</td>' +
            '<td><code style="font-size:11px;background:#F3F4F6;padding:1px 4px;border-radius:3px">…' + (k.key_last4||'') + '</code></td>' +
            '<td style="text-align:right">$' + (k.spend_usd||0).toFixed(2) + '</td>' +
            '<td style="text-align:right"><button class="scan-btn" data-provider="' + encodeURIComponent(k.provider||'') + '" data-key-id="' + encodeURIComponent(k.key_id||'') + '" onclick="removeKey(decodeURIComponent(this.dataset.provider),decodeURIComponent(this.dataset.keyId))" style="font-size:11px;color:#DC2626;border-color:#FECACA">Remove</button></td></tr>';
          return row;
        }}).join('');
      }}
    }}
  }} catch(e) {{ /* 403 for client_viewers — expected */ }}
}}

function _spendCard(label, value, color) {{
  return '<div class="inv-count-card"><div class="inv-count-n" style="color:' + color + '">' + value + '</div>' +
         '<div style="color:#6B7280">' + label + '</div></div>';
}}

function _spendBar(label, cost, tokens, maxCost, isDaily) {{
  const pct = Math.max(2, Math.min(100, (cost / (maxCost || 1)) * 100));
  return '<div style="display:flex;align-items:center;gap:8px;font-size:12px">' +
    '<div style="min-width:120px;color:#374151">' + label + '</div>' +
    '<div style="flex:1;background:#F3F4F6;border-radius:4px;height:18px;position:relative;overflow:hidden">' +
      '<div style="width:' + pct + '%;height:100%;background:#4F46E5;border-radius:4px"></div>' +
    '</div>' +
    '<div style="min-width:110px;text-align:right;font-weight:600;color:#374151">$' + (cost||0).toFixed(2) +
      ' <span style="color:#9CA3AF;font-weight:400">· ' + (tokens||0).toLocaleString() + ' tok</span></div>' +
  '</div>';
}}

async function triggerSpendFetch(btn) {{
  const orig = btn.textContent;
  btn.disabled = true; btn.textContent = 'Fetching…';
  try {{
    const r = await fetch('/api/spend/fetch', {{
      method: 'POST', headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{days: 7, force: true}})
    }});
    const res = await r.json();
    if (res.skipped) {{
      alert('Already fetched today. Click Fetch Latest again with force to override (this is intentional to avoid hammering provider APIs).');
    }} else {{
      alert('Fetched ' + (res.fetched || 0) + ' record(s) from: ' + ((res.providers||[]).join(', ') || 'none'));
    }}
    loadSpend();
  }} catch(e) {{
    alert('Fetch failed: ' + e);
  }} finally {{
    btn.disabled = false; btn.textContent = orig;
  }}
}}

function showAddKeyForm() {{
  document.getElementById('spend-add-key-form').style.display = 'block';
  updateSpendKeyHelp();
}}
function hideAddKeyForm() {{
  document.getElementById('spend-add-key-form').style.display = 'none';
  document.getElementById('spend-key-value').value = '';
}}

const _SPEND_KEY_HELP = {{
  'openai': '<b>OpenAI API key</b><br>' +
    '1. Sign in at <a href="https://platform.openai.com/" target="_blank">platform.openai.com</a><br>' +
    '2. Go to <b>API Keys</b> (left menu) → <b>Create new secret key</b><br>' +
    '3. Copy the <code>sk-...</code> key immediately — OpenAI won\u2019t show it again<br>' +
    '4. The key needs <b>Usage read</b> scope for spend tracking<br>' +
    '<span style="color:#9CA3AF">Cost shown here is estimated from token counts × published per-model pricing.</span>',
  'anthropic': '<b>Anthropic Admin API key</b><br>' +
    '1. Sign in at <a href="https://console.anthropic.com/" target="_blank">console.anthropic.com</a> and open <b>Settings → Organization</b><br>' +
    '2. Create an <b>Admin API key</b> with Usage and Cost access<br>' +
    '3. Paste the <code>sk-ant-admin01-...</code> key here; normal Claude API keys cannot read organization spend<br>' +
    '<span style="color:#9CA3AF">Arckon records Anthropic\u2019s billed USD cost and token usage. Individual accounts cannot use this API.</span>',
  'gemini': '<b>Google Gemini API key</b><br>' +
    '1. Go to <a href="https://aistudio.google.com/app/apikey" target="_blank">aistudio.google.com/app/apikey</a><br>' +
    '2. Click <b>Create API key</b> and copy it<br>' +
    '3. The public Gemini API does not expose per-account spend; this connector currently returns $0<br>' +
    '<span style="color:#9CA3AF">For real cost data, use Google Cloud Billing export or Cloud Monitoring (separate setup).</span>',
  'ollama': '<b>Ollama (self-hosted or Ollama Cloud)</b><br>' +
    'Ollama Cloud does not provide an account-wide usage or billing API, so a key cannot import historical spend.<br>' +
    'Arckon can capture <code>prompt_eval_count</code> and <code>eval_count</code> from each generate/chat response after call telemetry is integrated.<br>' +
    '<span style="color:#9CA3AF">Self-hosted API spend is $0; Cloud costs require configured model rates and are estimates, not provider-billed totals.</span>',
}};

function updateSpendKeyHelp() {{
  const p = document.getElementById('spend-key-provider').value;
  const el = document.getElementById('spend-key-help');
  if (el) el.innerHTML = _SPEND_KEY_HELP[p] || '';
}}

async function submitAddKey() {{
  const provider = document.getElementById('spend-key-provider').value;
  const orgEl = document.getElementById('spend-key-org');
  const client_org_id = orgEl ? orgEl.value.trim() : '';
  const label = document.getElementById('spend-key-label').value.trim();
  const api_key = document.getElementById('spend-key-value').value;
  if (!api_key || api_key.length < 8) {{ alert('API key is too short.'); return; }}
  try {{
    const r = await fetch('/api/spend/keys', {{
      method: 'POST', headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{provider, client_org_id, label, api_key, persist: true}})
    }});
    const res = await r.json();
    if (!r.ok) {{ alert('Error: ' + (res.error || 'failed')); return; }}
    hideAddKeyForm();
    loadSpend();
  }} catch(e) {{ alert('Save failed: ' + e); }}
}}

async function removeKey(provider, key_id) {{
  if (!confirm('Remove this API key? Its secret file will be deleted.')) return;
  try {{
    const r = await fetch('/api/spend/keys/remove', {{
      method: 'POST', headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{provider, key_id}})
    }});
    if (!r.ok) {{ alert('Remove failed'); return; }}
    loadSpend();
  }} catch(e) {{ alert('Remove failed: ' + e); }}
}}

let _invData = [];
let _invStatus = 'all';

var _sessionEmail = null;

async function _loadSessionUser() {{
  if (_sessionEmail !== null) return _sessionEmail;
  try {{
    const r = await fetch('/api/auth/me');
    const d = await r.json();
    _sessionEmail = d.email || '';
  }} catch(e) {{
    _sessionEmail = '';
  }}
  return _sessionEmail;
}}

function _fmtTs(epoch) {{
  if (!epoch) return '';
  const d = new Date(epoch * 1000);
  return d.toISOString().replace('T',' ').slice(0,16) + ' UTC';
}}

async function loadInventory() {{
  let inv;
  try {{
    const invRes = await fetch('/api/fleet/inventory');
    if (!invRes.ok) {{
      let detail = '';
      try {{ const j = await invRes.json(); detail = j.error || ''; }} catch(_) {{}}
      throw new Error('HTTP ' + invRes.status + (detail ? ': ' + detail : '') + '. Session may have expired — try refreshing.');
    }}
    const ct = invRes.headers.get('Content-Type') || '';
    if (!ct.includes('application/json')) {{
      throw new Error('HTTP ' + invRes.status + ' — got ' + (ct.split(';')[0].trim() || 'non-JSON') + ' instead of JSON. Session may have expired.');
    }}
    inv = await invRes.json();
  }} catch(e) {{
    console.error('loadInventory:', e);
    document.getElementById('inv-body').innerHTML = '<div style="color:#DC2626;font-size:13px;padding:8px 0">Failed to load inventory: ' + esc(e.message) + '</div>';
    return;
  }}
  _invData = inv.items || [];
  const email = inv.current_user || '';
  const c = inv.counts || {{}};
  document.getElementById('inv-counts').innerHTML =
    `<div class="inv-count-card"><div class="inv-count-n" style="color:#DC2626">${{c.unapproved||0}}</div><div style="color:#6B7280">Unapproved</div></div>` +
    `<div class="inv-count-card"><div class="inv-count-n" style="color:#CA8A04">${{c.under_review||0}}</div><div style="color:#6B7280">Under Review</div></div>` +
    `<div class="inv-count-card"><div class="inv-count-n" style="color:#16A34A">${{c.approved||0}}</div><div style="color:#6B7280">Approved</div></div>`;
  document.getElementById('inv-reviewer-bar').innerHTML = email
    ? `Approving as: <strong style="color:#111827">${{esc(email)}}</strong>`
    : `<span style="color:#CA8A04">⚠ Not signed in</span>`;
  renderInventory();
}}

function invFilter(status, btn) {{
  _invStatus = status;
  document.querySelectorAll('#inv-filters .rr-fil').forEach(b => b.classList.remove('rr-active'));
  btn.classList.add('rr-active');
  renderInventory();
}}

function renderInventory() {{
  const isFPView = _invStatus === 'false_positive';
  const activeItems = _invData.filter(i => !i.false_positive);
  const fpItems     = _invData.filter(i =>  i.false_positive);
  let rows;
  if (isFPView)                rows = fpItems;
  else if (_invStatus === 'all') rows = activeItems;
  else                         rows = activeItems.filter(i => i.approval_status === _invStatus);

  // Deduplicate only like-for-like observations. Multiple CDN addresses for one
  // service stay summarized, but network, local, and DNS observations never mix.
  const _invGroups = {{}};
  for (const item of rows) {{
    const key = (item.source||'') + '||' + (item.service||'') + '||' + (item.reporter_hostname||'');
    if (!_invGroups[key]) _invGroups[key] = [];
    _invGroups[key].push(item);
  }}
  const _statusPriority = {{unapproved:0, under_review:1, approved:2}};
  rows = Object.values(_invGroups).map(items => {{
    items.sort((a,b) => (_statusPriority[a.approval_status]||0) - (_statusPriority[b.approval_status]||0));
    return Object.assign({{}}, items[0], {{_endpointCount: items.length, _endpoints: items}});
  }});

  const el = document.getElementById('inv-body');
  if (!rows.length) {{
    const fallback = isFPView ? 'No false positives recorded.'
      : (_invData.length ? 'No assets at this status.' : 'No AI assets discovered yet. Run Shadow AI discovery first.');
    el.innerHTML = '<div style="color:#6B7280;font-size:13px;padding:16px 0">' + fallback + '</div>';
    if (!isFPView && fpItems.length) el.innerHTML += `<div style="font-size:11px;color:#9CA3AF;margin-top:8px">&#128683; ${{fpItems.length}} false positive${{fpItems.length!==1?'s':''}} hidden — <button class="inv-action" onclick="invFilter('false_positive',document.querySelector('#inv-filters .rr-fil:last-child'))">View</button></div>`;
    return;
  }}
  const SRC_ICON = {{network:'🌐',cloud:'☁️',dns:'🔍',process:'⚙️',container:'🐳'}};
  const trs = rows.map(item => {{
    const icon = SRC_ICON[item.source] || '🤖';
    const models = (item.models||[]).slice(0,3).join(', ') || '—';
    const isLocalHost = /^[0-9a-f]{{16}}$/i.test(item.host);
    // For local discoveries (process/DNS) host is the agent's own device ID — show hostname.
    // For network discoveries host is the remote IP — show IP with agent as secondary label.
    const isNetwork = !isLocalHost && item.host && item.host !== item.reporter_hostname;
    const cnt = item._endpointCount || 1;
    const formatEndpoint = (host, port) => {{
      const displayHost = host && host.includes(':') ? '[' + host + ']' : host;
      return displayHost + (port ? ':' + port : '');
    }};
    const hostDisplay = isLocalHost
      ? (item.reporter_hostname || 'local')
      : (cnt > 1 ? cnt + ' network endpoints' : formatEndpoint(item.host, item.port));
    const endpointDetails = cnt > 1 && isNetwork
      ? `<details style="margin-top:4px;font-size:10px;color:#6B7280"><summary style="cursor:pointer">View observed endpoints</summary><div style="margin-top:3px;word-break:break-all">${{item._endpoints.map(endpoint => esc(formatEndpoint(endpoint.host, endpoint.port))).join('<br>')}}</div></details>`
      : '';
    const agentLabel = isNetwork
      ? `<div style="font-size:10px;color:#9CA3AF;margin-top:1px">via ${{esc(item.reporter_hostname||'')}} agent</div>`
      : '';
    const st = item.approval_status || 'unapproved';
    const isFP = !!item.false_positive;
    let badge, actions, attribution;
    if (isFP) {{
      badge = '<span style="font-size:11px;background:#F3F4F6;color:#6B7280;border:1px solid #D1D5DB;border-radius:3px;padding:1px 6px;font-weight:600">&#128683; False Positive</span>';
      actions = `<button class="inv-action" onclick="invClearFP(${{item.id}},this)" style="color:#6B7280">Clear FP</button>`;
    }} else if (st === 'approved') {{
      badge = '<span class="inv-badge-approved">Approved</span>';
      actions = `<button class="inv-action" onclick="invSetStatus(${{item.id}},'under_review',this)">→ Review</button>
                 <button class="inv-action" onclick="invSetStatus(${{item.id}},'unapproved',this)">Unapprove</button>
                 <button class="inv-action" onclick="invMarkFP(${{item.id}},this)" style="color:#6B7280">&#128683; False Positive</button>`;
    }} else if (st === 'under_review') {{
      badge = '<span class="inv-badge-review">Under Review</span>';
      actions = `<button class="inv-action" onclick="invSetStatus(${{item.id}},'approved',this)">Approve</button>
                 <button class="inv-action" onclick="invSetStatus(${{item.id}},'unapproved',this)">Unapprove</button>
                 <button class="inv-action" onclick="invMarkFP(${{item.id}},this)" style="color:#6B7280">&#128683; False Positive</button>`;
    }} else {{
      badge = '<span class="inv-badge-unapp">Unapproved</span>';
      actions = `<button class="inv-action" onclick="invSetStatus(${{item.id}},'approved',this)">Approve</button>
                 <button class="inv-action" onclick="invSetStatus(${{item.id}},'under_review',this)">Flag for Review</button>
                 <button class="inv-action" onclick="invMarkFP(${{item.id}},this)" style="color:#6B7280">&#128683; False Positive</button>`;
    }}
    if (item.approved_by && item.approved_at) {{
      const noteTip = item.notes ? esc(item.notes)+' · ' : '';
      attribution = `<span style="font-size:10px;color:#6B7280" title="${{noteTip}}Full history: click History">${{esc(item.approved_by)}} · ${{_fmtTs(item.approved_at)}}${{item.notes ? ' 📝' : ''}}</span>`;
    }} else if (item.approved_by) {{
      attribution = `<span style="font-size:10px;color:#6B7280" title="${{esc(item.notes||'')}}">${{esc(item.approved_by)}}${{item.notes ? ' 📝' : ''}}</span>`;
    }} else {{
      attribution = '<span style="font-size:10px;color:#D1D5DB">—</span>';
    }}
    return `<tr style="${{isFP ? 'opacity:0.55' : ''}}">
      <td style="font-size:16px">${{icon}}</td>
      <td style="color:#111827;font-weight:600">${{esc(hostDisplay)}}${{agentLabel}}${{endpointDetails}}</td>
      <td style="color:#6B7280">${{esc(item.service||item.source)}}</td>
      <td style="color:#6B7280;font-size:12px">${{esc(models)}}</td>
      <td style="color:#6B7280;font-size:11px">${{esc(item.reporter_hostname||'')}}</td>
      <td>${{badge}}</td>
      <td>${{attribution}}</td>
      <td style="white-space:nowrap;display:flex;gap:4px;flex-wrap:wrap">
        ${{actions}}
        ${{!isFP ? `<button class="inv-action" data-service="${{esc(item.service)}}" onclick="invApproveGlobally(this.dataset.service,this)" style="color:#7c3aed" title="Approve this service on all devices, now and in future">&#9733; Approve globally</button>` : ''}}
        <button class="inv-action" onclick="invShowHistory(${{item.id}},this)" style="color:#6B7280">History</button>
      </td>
    </tr>`;
  }}).join('');
  const fpNote = (!isFPView && fpItems.length) ? `<div style="font-size:11px;color:#9CA3AF;margin-top:4px">&#128683; ${{fpItems.length}} false positive${{fpItems.length!==1?'s':''}} excluded — <button class="inv-action" onclick="invFilter('false_positive',document.querySelector('#inv-filters .rr-fil:last-child'))">View</button></div>` : '';
  el.innerHTML = `<table class="rr-table">
    <thead><tr><th></th><th>Device / IP</th><th>Service</th><th>Models</th><th>Detected by</th><th>Status</th><th>Reviewer · Notes</th><th>Actions</th></tr></thead>
    <tbody>${{trs}}</tbody>
  </table><div style="font-size:11px;color:#9CA3AF;margin-bottom:4px">${{rows.length}} asset${{rows.length!==1?'s':''}} · approval records are included in the Evidence Package export</div>${{fpNote}}
  <div id="inv-history-panel" style="display:none;margin-top:12px;background:#F9FAFB;border:1px solid #E5E7EB;border-radius:6px;padding:12px"></div>
  <div id="inv-fp-modal" style="display:none;margin-top:12px;background:#FEF9C3;border:1px solid #FDE047;border-radius:6px;padding:14px;max-width:520px">
    <div style="font-weight:600;font-size:13px;margin-bottom:8px">&#128683; Mark as False Positive</div>
    <div style="font-size:12px;color:#6B7280;margin-bottom:8px">Add a note explaining why this is a false positive. This creates an audit trail entry.</div>
    <textarea id="inv-fp-notes" rows="3" style="width:100%;font-size:12px;border:1px solid #D1D5DB;border-radius:4px;padding:6px;resize:vertical;box-sizing:border-box" placeholder="Describe why this is a false positive…"></textarea>
    <div style="display:flex;gap:8px;margin-top:8px">
      <button class="inv-action" id="inv-fp-confirm" style="background:#1F2937;color:#fff;border-color:#1F2937">Confirm False Positive</button>
      <button class="inv-action" onclick="invCloseFPModal()">Cancel</button>
    </div>
  </div>`;
  if (window._invFPPendingId) {{
    const btn = document.getElementById('inv-fp-confirm');
    if (btn) btn.onclick = () => invSubmitFP(window._invFPPendingId);
  }}
}}


async function invSetStatus(id, status, btn) {{
  const orig = btn.textContent;
  btn.disabled = true; btn.textContent = '…';
  try {{
    const slug = status==='under_review'?'review':status==='approved'?'approve':'unapprove';
    const r = await fetch('/api/fleet/inventory/' + slug + '/' + id, {{method:'POST'}});
    const d = await r.json();
    if (d.ok) {{ await loadInventory(); }} else {{ btn.disabled=false; btn.textContent=orig; }}
  }} catch(e) {{ btn.disabled=false; btn.textContent=orig; }}
}}

function invMarkFP(id, btn) {{
  window._invFPPendingId = id;
  const modal = document.getElementById('inv-fp-modal');
  if (!modal) {{ renderInventory(); return; }}
  modal.style.display = 'block';
  const confirmBtn = document.getElementById('inv-fp-confirm');
  if (confirmBtn) confirmBtn.onclick = () => invSubmitFP(id);
  const ta = document.getElementById('inv-fp-notes');
  if (ta) {{ ta.value = ''; ta.focus(); }}
}}

function invCloseFPModal() {{
  window._invFPPendingId = null;
  const modal = document.getElementById('inv-fp-modal');
  if (modal) modal.style.display = 'none';
}}

async function invSubmitFP(id) {{
  const notes = (document.getElementById('inv-fp-notes') || {{}}).value || '';
  const btn = document.getElementById('inv-fp-confirm');
  if (btn) {{ btn.disabled = true; btn.textContent = '…'; }}
  try {{
    const r = await fetch('/api/fleet/inventory/false-positive/' + id, {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{false_positive: true, notes}}),
    }});
    const d = await r.json();
    if (d.ok) {{ invCloseFPModal(); await loadInventory(); }}
    else {{ if (btn) {{ btn.disabled=false; btn.textContent='Confirm False Positive'; }} }}
  }} catch(e) {{ if (btn) {{ btn.disabled=false; btn.textContent='Confirm False Positive'; }} }}
}}

async function invClearFP(id, btn) {{
  const orig = btn.textContent;
  btn.disabled = true; btn.textContent = '…';
  try {{
    const r = await fetch('/api/fleet/inventory/false-positive/' + id, {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{false_positive: false, notes: ''}}),
    }});
    const d = await r.json();
    if (d.ok) {{ await loadInventory(); }} else {{ btn.disabled=false; btn.textContent=orig; }}
  }} catch(e) {{ btn.disabled=false; btn.textContent=orig; }}
}}

async function shadowApproveGlobally(service, btn) {{
  if (!confirm(`Approve "${{service}}" globally?\n\nThis will:\n• Mark all current detections as Approved on every device\n• Auto-approve any future detections on any device\n• Suppress alerts for this service\n\nYou can undo this from the Asset Inventory page.`)) return;
  const orig = btn.textContent;
  btn.disabled = true; btn.textContent = '…';
  try {{
    const r = await fetch('/api/fleet/inventory/approve-service', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{service, action: 'approve'}}),
    }});
    const d = await r.json();
    if (d.ok) {{
      btn.closest('.shadow-card').style.opacity = '0.4';
      btn.textContent = '✓ Approved';
    }} else {{
      btn.disabled = false; btn.textContent = orig;
      alert('Failed: ' + (d.error || 'unknown'));
    }}
  }} catch(e) {{ btn.disabled = false; btn.textContent = orig; }}
}}

async function invApproveGlobally(service, btn) {{
  if (!confirm(`Approve "${{service}}" globally?\n\nThis will:\n• Mark all current detections of this service as Approved\n• Auto-approve any future detections on any device\n• Suppress alerts for this service\n\nYou can undo this per-entry or via the API.`)) return;
  const orig = btn.textContent;
  btn.disabled = true; btn.textContent = '…';
  try {{
    const r = await fetch('/api/fleet/inventory/approve-service', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{service, action: 'approve'}}),
    }});
    const d = await r.json();
    if (d.ok) {{ await loadInventory(); }} else {{ btn.disabled=false; btn.textContent=orig; alert('Failed: ' + (d.error||'unknown')); }}
  }} catch(e) {{ btn.disabled=false; btn.textContent=orig; }}
}}

async function invShowHistory(id, btn) {{
  const panel = document.getElementById('inv-history-panel');
  if (panel && panel.dataset.openId === String(id) && panel.style.display !== 'none') {{
    panel.style.display = 'none';
    panel.dataset.openId = '';
    return;
  }}
  try {{
    const r = await fetch('/api/fleet/inventory/history/' + id);
    const d = await r.json();
    const rows = (d.history || []);
    if (!rows.length) {{
      panel.innerHTML = '<div style="font-size:12px;color:#6B7280">No approval history for this asset.</div>';
    }} else {{
      const STATUS_LABELS = {{approved:'Approved',under_review:'Under Review',unapproved:'Unapproved','':'—'}};
      const trs = rows.map(ev => {{
        const ts = _fmtTs(ev.changed_at);
        const from = STATUS_LABELS[ev.from_status] || ev.from_status;
        const to   = STATUS_LABELS[ev.to_status]   || ev.to_status;
        return `<tr>
          <td style="font-size:11px;color:#6B7280;white-space:nowrap">${{esc(ts)}}</td>
          <td style="font-size:12px;color:#111827;font-weight:600">${{esc(ev.changed_by||'Unknown')}}</td>
          <td style="font-size:11px;color:#6B7280">${{esc(from)}} → ${{esc(to)}}</td>
          <td style="font-size:10px;color:#9CA3AF">${{esc(ev.ip_address||'')}}</td>
        </tr>`;
      }}).join('');
      panel.innerHTML = `<div style="font-size:12px;font-weight:600;color:#374151;margin-bottom:6px">Approval History</div>
        <table class="rr-table"><thead><tr><th>Timestamp</th><th>Reviewer</th><th>Change</th><th>IP</th></tr></thead>
        <tbody>${{trs}}</tbody></table>`;
    }}
    panel.style.display = 'block';
    panel.dataset.openId = String(id);
    panel.scrollIntoView({{behavior:'smooth',block:'nearest'}});
  }} catch(e) {{
    if (panel) panel.innerHTML = '<div style="color:#DC2626;font-size:12px">Failed to load history.</div>';
  }}
}}

async function loadCustomerInfo() {{
  try {{
    const r = await fetch('/api/customers/me');
    if (!r.ok) return;
    const d = await r.json();
    const inp = document.getElementById('agent-token-display');
    const lbl = document.getElementById('token-company');
    if (inp) inp.value = d.agent_token || '';
    if (lbl) lbl.textContent = 'Company: ' + (d.name || '');
  }} catch(e) {{}}
}}

let _tokenVisible = false;
function toggleTokenVisibility() {{
  const inp = document.getElementById('agent-token-display');
  const btn = document.getElementById('token-show-btn');
  if (!inp) return;
  _tokenVisible = !_tokenVisible;
  inp.type = _tokenVisible ? 'text' : 'password';
  btn.textContent = _tokenVisible ? 'Hide' : 'Show';
}}

async function copyToken() {{
  const inp = document.getElementById('agent-token-display');
  if (!inp || !inp.value) return;
  try {{
    await navigator.clipboard.writeText(inp.value);
    const btn = event.target;
    const orig = btn.textContent;
    btn.textContent = 'Copied!';
    btn.style.color = '#16A34A';
    setTimeout(() => {{ btn.textContent = orig; btn.style.color = '#4F46E5'; }}, 1500);
  }} catch(e) {{ alert('Copy failed — use Show then copy manually.'); }}
}}

async function loadUsers() {{
  try {{
    const r = await fetch('/api/users');
    if (!r.ok) {{
      document.getElementById('users-list').innerHTML = '<div style="color:#DC2626;font-size:13px">Failed to load users (' + r.status + ').</div>';
      return;
    }}
    const d = await r.json();
    const users = d.users || [];
    const myEmail = d.current_user || await _loadSessionUser();
    const ROLE_BADGE = {{
      super_admin:    '<span style="font-size:10px;font-weight:600;color:#16A34A;background:#DCFCE7;padding:1px 6px;border-radius:4px">internal</span>',
      customer_admin: '<span style="font-size:10px;font-weight:600;color:#4F46E5;background:#EEF2FF;padding:1px 6px;border-radius:4px">admin</span>',
      admin:          '<span style="font-size:10px;font-weight:600;color:#4F46E5;background:#EEF2FF;padding:1px 6px;border-radius:4px">admin</span>',
      user:           '<span style="font-size:10px;font-weight:600;color:#CA8A04;background:#FEF9C3;padding:1px 6px;border-radius:4px">viewer</span>',
      client_viewer:  '<span style="font-size:10px;font-weight:600;color:#CA8A04;background:#FEF9C3;padding:1px 6px;border-radius:4px">client viewer</span>',
    }};
    const rows = users.map(u => {{
      const isMe = u.email === myEmail;
      const inactive = u.active === false || u.active === 0;
      const badge = ROLE_BADGE[u.role] || `<span style="font-size:10px;color:#6B7280">${{esc(u.role)}}</span>`;
      const uid = esc(u.id);
      const chgPwd = !inactive ? `<button class="inv-action" onclick="togglePwForm('${{uid}}')" style="color:#4F46E5;margin-right:4px">Chg Pwd</button>` : '';
      const remove = !isMe && !inactive ? `<button class="inv-action" onclick="deactivateUser('${{uid}}','${{esc(u.email)}}')" style="color:#DC2626">Remove</button>` : '';
      return `<div style="display:flex;align-items:center;gap:12px;padding:8px 0;border-bottom:1px solid #F3F4F6">
        <span style="font-size:13px;color:${{inactive?'#9CA3AF':'#111827'}};flex:1">
          ${{esc(u.email)}}
          ${{isMe ? '<span style="font-size:10px;color:#4F46E5;font-weight:600;margin-left:4px">(you)</span>' : ''}}
          ${{inactive ? '<span style="font-size:10px;color:#9CA3AF;margin-left:4px">(deactivated)</span>' : ''}}
        </span>
        <span style="min-width:70px">${{badge}}</span>
        ${{chgPwd}}${{remove}}
      </div>
      <div id="pw-form-${{uid}}" style="display:none;padding:10px 0 12px;border-bottom:1px solid #F3F4F6">
        <div style="display:flex;align-items:center;gap:8px;max-width:420px">
          <input type="password" id="pw-input-${{uid}}" placeholder="New password (min 8 chars)" style="flex:1;padding:7px 10px;border:1px solid #D1D5DB;border-radius:6px;font-size:13px">
          <button class="inv-action" onclick="savePassword('${{uid}}')" style="color:#16A34A">Save</button>
          <button class="inv-action" onclick="togglePwForm('${{uid}}')" style="color:#6B7280">Cancel</button>
        </div>
        <div id="pw-msg-${{uid}}" style="font-size:12px;margin-top:6px"></div>
      </div>`;
    }}).join('');
    document.getElementById('users-list').innerHTML = rows || '<div style="font-size:13px;color:#9CA3AF">No users yet.</div>';
  }} catch(e) {{
    document.getElementById('users-list').innerHTML = '<div style="color:#DC2626;font-size:13px">Failed to load users.</div>';
  }}
}}

async function addUser() {{
  const email = (document.getElementById('new-user-email').value || '').trim();
  const pw = document.getElementById('new-user-pw').value || '';
  const msg = document.getElementById('users-msg');
  if (!email || !pw) {{ msg.style.color='#DC2626'; msg.textContent='Email and password are required.'; return; }}
  if (pw.length < 8) {{ msg.style.color='#DC2626'; msg.textContent='Password must be at least 8 characters.'; return; }}
  try {{
    const r = await fetch('/api/users/add', {{
      method: 'POST',
      headers: {{'Content-Type':'application/json'}},
      body: JSON.stringify({{email, password: pw, role:'admin'}}),
    }});
    const d = await r.json();
    if (d.ok) {{
      msg.style.color='#16A34A'; msg.textContent='User added.';
      document.getElementById('new-user-email').value='';
      document.getElementById('new-user-pw').value='';
      await loadUsers();
    }} else {{
      msg.style.color='#DC2626'; msg.textContent = d.error || 'Failed to add user.';
    }}
  }} catch(e) {{ msg.style.color='#DC2626'; msg.textContent='Network error.'; }}
}}

async function deactivateUser(id, email) {{
  if (!confirm(`Remove ${{email}}? They will be signed out immediately and cannot log in.`)) return;
  try {{
    const r = await fetch('/api/users/deactivate/' + id, {{method:'POST'}});
    const d = await r.json();
    if (d.ok) {{ await loadUsers(); }}
    else {{ alert('Failed: ' + (d.error || 'unknown error')); }}
  }} catch(e) {{ alert('Network error.'); }}
}}

function togglePwForm(uid) {{
  const el = document.getElementById('pw-form-' + uid);
  if (!el) return;
  const showing = el.style.display !== 'none';
  el.style.display = showing ? 'none' : 'block';
  if (!showing) {{
    const inp = document.getElementById('pw-input-' + uid);
    if (inp) {{ inp.value = ''; inp.focus(); }}
    const msg = document.getElementById('pw-msg-' + uid);
    if (msg) msg.textContent = '';
    el.scrollIntoView({{behavior:'smooth', block:'nearest'}});
  }}
}}

async function savePassword(uid) {{
  const inp = document.getElementById('pw-input-' + uid);
  const msg = document.getElementById('pw-msg-' + uid);
  const pw = inp ? inp.value : '';
  if (!pw || pw.length < 8) {{
    if (msg) {{ msg.style.color='#DC2626'; msg.textContent='Password must be at least 8 characters.'; }}
    return;
  }}
  try {{
    const r = await fetch('/api/users/password/' + uid, {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{new_password: pw}}),
    }});
    const d = await r.json();
    if (d.ok) {{
      if (msg) {{ msg.style.color='#16A34A'; msg.textContent='Password updated.'; }}
      setTimeout(() => togglePwForm(uid), 1500);
    }} else {{
      if (msg) {{ msg.style.color='#DC2626'; msg.textContent = d.error || 'Failed to update password.'; }}
    }}
  }} catch(e) {{
    if (msg) {{ msg.style.color='#DC2626'; msg.textContent='Network error.'; }}
  }}
}}

const CADENCE_LABELS = {{daily:'Daily',weekly:'Weekly',monthly:'Monthly'}};
const WEEKDAY_LABELS = ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'];
const PROFILE_LABELS = {{default:'Base Scan',fedramp:'FedRAMP',fedramp_20x:'FedRAMP 20x',cmmc:'CMMC 2.0',financial:'Financial',
  healthcare:'Healthcare',biotech:'Biotech',owasp_agentic:'OWASP Agentic',eu_ai_act:'EU AI Act',
  professional_services:'Professional Services',kubernetes:'Kubernetes',docker:'Docker'}};

async function loadSchedules() {{
  try {{
    const r = await fetch('/api/schedules');
    const d = await r.json();
    renderSchedules(d.schedules || []);
  }} catch(e) {{
    document.getElementById('sched-list').innerHTML = '<div style="color:#DC2626;font-size:13px">Failed to load schedules.</div>';
  }}
}}

function renderSchedules(scheds) {{
  const el = document.getElementById('sched-list');
  if (!scheds.length) {{
    el.innerHTML = '<div style="color:#6B7280;font-size:13px;padding:8px 0">No schedules configured. Use "+ Add schedule" below to create one.</div>';
    return;
  }}
  const rows = scheds.map(s => {{
    const lbl = s.label || (PROFILE_LABELS[s.profile]||s.profile) + ' ' + (CADENCE_LABELS[s.cadence]||s.cadence);
    let when;
    if (s.cadence === 'hourly') {{
      when = 'every hour';
    }} else if (s.cadence === 'interval') {{
      when = 'every ' + (s.interval_hours || 1) + 'h';
    }} else {{
      when = `${{String(s.hour).padStart(2,'0')}}:00 UTC`;
      if (s.cadence==='weekly')  when = WEEKDAY_LABELS[s.weekday||0] + ' at ' + when;
      if (s.cadence==='monthly') when = 'Day ' + (s.monthday||1) + ' at ' + when;
    }}
    const enabled = s.enabled ? '🟢' : '⚫';
    const fired = s.last_fired ? new Date(s.last_fired*1000).toLocaleDateString() : 'Never';
    return `<div style="display:flex;align-items:center;gap:12px;padding:6px 0;border-bottom:1px solid #F3F4F6;font-size:13px;flex-wrap:wrap">
      <span style="min-width:16px">${{enabled}}</span>
      <span style="font-weight:600;color:#111827;min-width:160px">${{esc(lbl)}}</span>
      <span class="tag">${{CADENCE_LABELS[s.cadence]||s.cadence}}</span>
      <span class="tag">${{PROFILE_LABELS[s.profile]||s.profile}}</span>
      <span style="color:#6B7280;font-size:12px">${{when}}</span>
      <span style="color:#9CA3AF;font-size:11px;margin-left:auto">Last ran: ${{fired}}</span>
      <button class="inv-action" onclick="toggleSchedule(${{s.id}},this)">${{s.enabled?'Disable':'Enable'}}</button>
      <button class="inv-action" style="color:#DC2626" onclick="deleteSchedule(${{s.id}},this)">Delete</button>
    </div>`;
  }}).join('');
  el.innerHTML = rows;
}}

function schedCadenceChange() {{
  const c = document.getElementById('sched-cadence').value;
  const interval = c === 'hourly' || c === 'interval';
  document.getElementById('sched-interval-wrap').style.display  = c === 'interval' ? '' : 'none';
  document.getElementById('sched-weekday-wrap').style.display   = c === 'weekly'   ? '' : 'none';
  document.getElementById('sched-monthday-wrap').style.display  = c === 'monthly'  ? '' : 'none';
  document.getElementById('sched-hour-wrap').style.display      = interval         ? 'none' : '';
}}

async function addSchedule() {{
  const body = {{
    label:    document.getElementById('sched-label').value.trim(),
    profile:  document.getElementById('sched-profile').value,
    cadence:  document.getElementById('sched-cadence').value,
    hour:     parseInt(document.getElementById('sched-hour').value),
    device_id:'all',
  }};
  const c = body.cadence;
  if (c==='interval') body.interval_hours = parseInt(document.getElementById('sched-interval-hours').value);
  if (c==='weekly')   body.weekday        = parseInt(document.getElementById('sched-weekday').value);
  if (c==='monthly')  body.monthday       = parseInt(document.getElementById('sched-monthday').value);
  try {{
    const r = await fetch('/api/schedules', {{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify(body)}});
    const d = await r.json();
    if (d.ok) {{ document.getElementById('sched-label').value=''; await loadSchedules(); }}
    else alert('Error: ' + (d.error||'unknown'));
  }} catch(e) {{ alert('Error: ' + e); }}
}}

async function toggleSchedule(id, btn) {{
  btn.disabled = true;
  try {{
    await fetch('/api/schedules/'+id+'/toggle', {{method:'POST'}});
    await loadSchedules();
  }} finally {{ btn.disabled = false; }}
}}

async function deleteSchedule(id, btn) {{
  if (!confirm('Delete this schedule?')) return;
  btn.disabled = true;
  try {{
    await fetch('/api/schedules/'+id+'/delete', {{method:'POST'}});
    await loadSchedules();
  }} finally {{ btn.disabled = false; }}
}}

async function downloadEvidencePackage(btn) {{
  const orig = btn.textContent;
  btn.disabled = true;
  btn.textContent = 'Building…';
  try {{
    const p = _rptProfileParam().replace('&profile=','?profile=');
    const r = await fetch('/api/fleet/evidence-export' + p);
    if (!r.ok) {{ alert('Export failed: ' + await r.text().catch(() => r.status)); return; }}
    const blob = await r.blob();
    const disp = r.headers.get('Content-Disposition') || '';
    const fname = (disp.match(/filename="([^"]+)"/) || [])[1] || 'sentinel_evidence.zip';
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = fname;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }} catch(e) {{ alert('Download error: ' + e); }}
  finally {{ btn.disabled = false; btn.textContent = orig; }}
}}

let _rrData = [];
let _rrSev = 'all';

async function loadRiskRegister() {{
  try {{
    const r = await fetch('/api/fleet/risk-register');
    const d = await r.json();
    _rrData = d.entries || [];
    renderRiskRegister();
  }} catch(e) {{
    document.getElementById('rr-body').innerHTML = '<div style="color:#DC2626;font-size:13px;padding:8px 0">Failed to load risk register.</div>';
  }}
}}

function rrFilter(sev, btn) {{
  _rrSev = sev;
  document.querySelectorAll('#rr-filters .rr-fil').forEach(b => b.classList.remove('rr-active'));
  btn.classList.add('rr-active');
  renderRiskRegister();
}}

function rrToggleForm(checkId, action) {{
  const rowId = 'rr-form-' + checkId.replace(/[^a-z0-9]/gi,'_');
  const existing = document.getElementById(rowId);
  if (existing) {{ existing.remove(); return; }}
  const dataRow = document.querySelector(`tr[data-cid="${{checkId}}"]`);
  if (!dataRow) return;
  const e = _rrData.find(x => x.check_id === checkId) || {{}};
  const formRow = document.createElement('tr');
  formRow.id = rowId;
  formRow.className = 'rr-form-row';
  const assigneeField = action === 'assigned'
    ? `<div style="margin-bottom:8px"><label style="font-size:11px;color:#6B7280;display:block;margin-bottom:3px">Assign to</label>
       <input class="rr-input" id="rr-assignee-${{checkId.replace(/[^a-z0-9]/gi,'_')}}" placeholder="Name or email" value="${{esc(e.override_assignee||'')}}" style="width:220px"></div>`
    : '';
  const actionLabel = action === 'false_positive' ? 'Mark as False Positive'
                    : action === 'accepted' ? 'Accept Risk' : 'Assign Finding';
  const notePlaceholder = action === 'false_positive'
    ? 'Explain why this is a false positive (e.g. regex matched a filename, not a real key)…'
    : 'Reason, ticket #, etc.';
  formRow.innerHTML = `<td colspan="8" class="rr-form-row" style="padding:12px 16px">
    <div style="font-size:12px;font-weight:600;color:#374151;margin-bottom:10px">${{actionLabel}}: <code style="font-size:11px;color:#6B7280">${{esc(checkId)}}</code></div>
    <div style="display:flex;flex-wrap:wrap;gap:12px;align-items:flex-end">
      ${{assigneeField}}
      <div style="flex:1;min-width:200px"><label style="font-size:11px;color:#6B7280;display:block;margin-bottom:3px">Note ${{action === 'false_positive' ? '' : '<span style="color:#9CA3AF">(optional)</span>'}}</label>
       <input class="rr-input" id="rr-note-${{checkId.replace(/[^a-z0-9]/gi,'_')}}" placeholder="${{notePlaceholder}}" value="${{esc(e.override_note||'')}}"></div>
      <div><label style="font-size:11px;color:#6B7280;display:block;margin-bottom:3px">Expires <span style="color:#9CA3AF">(optional)</span></label>
       <input class="rr-input" id="rr-exp-${{checkId.replace(/[^a-z0-9]/gi,'_')}}" type="date" style="width:140px" value="${{e.override_expires ? new Date(e.override_expires*1000).toISOString().slice(0,10) : ''}}"></div>
      <div style="display:flex;gap:6px;padding-bottom:1px">
        <button class="rr-save-btn" onclick="rrSaveOverride('${{checkId}}','${{action}}')">Save</button>
        ${{e.override_action ? `<button class="rr-clear-btn" onclick="rrClearOverride('${{checkId}}')">Clear</button>` : ''}}
        <button class="rr-clear-btn" onclick="document.getElementById('${{rowId}}').remove()">Cancel</button>
      </div>
    </div>
  </td>`;
  dataRow.after(formRow);
}}

async function rrSaveOverride(checkId, action) {{
  const slug = checkId.replace(/[^a-z0-9]/gi,'_');
  const assignee = document.getElementById('rr-assignee-'+slug)?.value?.trim() || '';
  const note     = document.getElementById('rr-note-'+slug)?.value?.trim() || '';
  const expVal   = document.getElementById('rr-exp-'+slug)?.value?.trim() || '';
  try {{
    const r = await fetch('/api/fleet/risk-register/override', {{
      method: 'POST',
      headers: {{'Content-Type':'application/json'}},
      body: JSON.stringify({{check_id: checkId, action, assignee, note, expires_at: expVal || null}})
    }});
    const d = await r.json();
    if (!d.ok) {{ alert('Save failed: ' + (d.error||'unknown error')); return; }}
    await loadRiskRegister();
  }} catch(e) {{ alert('Save failed: ' + e); }}
}}

async function rrClearOverride(checkId) {{
  if (!confirm('Remove override for this finding?')) return;
  try {{
    const r = await fetch('/api/fleet/risk-register/override/' + encodeURIComponent(checkId) + '/delete', {{method:'POST'}});
    const d = await r.json();
    if (!d.ok) {{ alert('Clear failed: ' + (d.error||'unknown')); return; }}
    await loadRiskRegister();
  }} catch(e) {{ alert('Clear failed: ' + e); }}
}}

function renderRiskRegister() {{
  let rows;
  if (_rrSev === 'accepted') {{
    rows = _rrData.filter(e => e.override_action === 'accepted');
  }} else if (_rrSev === 'false_positive') {{
    rows = _rrData.filter(e => e.override_action === 'false_positive');
  }} else if (_rrSev === 'all') {{
    rows = _rrData.filter(e => e.override_action !== 'false_positive');
  }} else {{
    rows = _rrData.filter(e => e.severity === _rrSev && e.override_action !== 'false_positive');
  }}
  const el = document.getElementById('rr-body');
  const fpCount = _rrData.filter(e => e.override_action === 'false_positive').length;
  if (!rows.length) {{
    let msg = _rrSev === 'accepted' ? 'No accepted risks.'
            : _rrSev === 'false_positive' ? 'No false positives recorded.'
            : _rrData.length ? 'No findings at this severity.' : 'No open findings — fleet is clean.';
    el.innerHTML = '<div style="color:#6B7280;font-size:13px;padding:16px 0">' + msg + '</div>';
    return;
  }}
  const SEV_CLS = {{CRITICAL:'critical',HIGH:'high',MEDIUM:'medium',LOW:'low'}};
  const fpNote = (_rrSev !== 'false_positive' && fpCount)
    ? `<div style="font-size:11px;color:#9CA3AF;margin-bottom:6px">&#128683; ${{fpCount}} false positive${{fpCount!==1?'s':''}} hidden — <button class="rr-fil" style="font-size:11px;padding:1px 8px" onclick="rrFilter('false_positive',document.querySelector('#rr-filters .rr-fil:last-child'))">View</button></div>`
    : '';
  const trs = rows.map(e => {{
    const trendBadge = e.trend === 'Recurring'
      ? '<span class="rr-recurring">Recurring</span>'
      : '<span class="rr-new">New</span>';
    const overrideBadge = e.override_action === 'accepted'
      ? '<span class="rr-accepted">&#10003; Accepted</span>'
      : e.override_action === 'assigned'
        ? `<span class="rr-assigned">&#128100; ${{esc(e.override_assignee||'Assigned')}}</span>`
        : e.override_action === 'false_positive'
          ? '<span class="rr-fp">&#128683; False Positive</span>'
          : '';
    const devTip = e.affected_devices.join(', ');
    const rowClass = e.override_action === 'accepted' ? 'rr-row-accepted'
                   : e.override_action === 'false_positive' ? 'rr-row-fp' : '';
    const cid = e.check_id;
    const fpLabel = e.override_action === 'false_positive' ? 'Unmark FP' : 'False Positive';
    const fpAction = e.override_action === 'false_positive' ? `rrClearOverride('${{esc(cid)}}')` : `rrToggleForm('${{esc(cid)}}','false_positive')`;
    return `<tr class="${{rowClass}}" data-cid="${{esc(cid)}}">
      <td><span class="badge ${{SEV_CLS[e.severity]||'low'}}">${{esc(e.severity)}}</span></td>
      <td style="font-family:monospace;font-size:12px;color:#6B7280">${{esc(cid)}}</td>
      <td style="color:#374151">${{esc(e.title)}}</td>
      <td title="${{esc(devTip)}}" style="cursor:default;color:#111827;font-weight:600">${{e.affected_count}}</td>
      <td>${{trendBadge}}</td>
      <td style="color:#6B7280">${{e.days_open}}d</td>
      <td style="white-space:nowrap">${{overrideBadge}}</td>
      <td style="white-space:nowrap">
        <button class="rr-act-btn" onclick="rrToggleForm('${{esc(cid)}}','accepted')" title="Accept this risk">Accept</button>
        <button class="rr-act-btn" onclick="rrToggleForm('${{esc(cid)}}','assigned')" title="Assign to someone">Assign</button>
        <button class="rr-act-btn" onclick="${{fpAction}}" title="Mark as false positive" style="color:#6B7280">${{fpLabel}}</button>
      </td>
    </tr>`;
  }}).join('');
  el.innerHTML = fpNote + `<table class="rr-table">
    <thead><tr>
      <th>Severity</th><th>Check ID</th><th>Finding</th>
      <th title="Hover for device list">Devices</th><th>Trend</th><th>Open</th>
      <th>Status</th><th>Actions</th>
    </tr></thead>
    <tbody>${{trs}}</tbody>
  </table><div style="font-size:11px;color:#9CA3AF;margin-bottom:8px">${{rows.length}} finding${{rows.length!==1?'s':''}} · hover device count for affected hostnames</div>`;
}}

// ── PSA integrations ─────────────────────────────────────────────────────────

const PSA_DEFS = [
  {{id:'connectwise', name:'ConnectWise Manage', icon:'&#128736;', color:'#E31837',
    desc:'Auto-create service tickets on new CRITICAL/HIGH findings. Uses the ConnectWise Manage REST API.',
    howto:'Settings → My Company → API Keys. Register a client ID at developer.connectwise.com.',
    fields:[
      {{key:'site',          label:'Site',           type:'text',     ph:'na.myconnectwise.net'}},
      {{key:'company_id',    label:'Company ID',     type:'text',     ph:'YourCompanyId'}},
      {{key:'public_key',    label:'Public Key',     type:'text',     ph:'API public key'}},
      {{key:'private_key',   label:'Private Key',    type:'password', ph:'API private key'}},
      {{key:'client_id',     label:'Client ID',      type:'text',     ph:'UUID from developer.connectwise.com'}},
      {{key:'service_board', label:'Service Board',  type:'text',     ph:'Service Requests'}},
      {{key:'company_name',  label:'Company Name',   type:'text',     ph:'Client company identifier'}},
    ]}},
  {{id:'autotask', name:'Autotask PSA', icon:'&#128203;', color:'#0077CC',
    desc:'Auto-create tickets in Autotask when new CRITICAL/HIGH AI security findings are detected.',
    howto:'Admin → Resources → API User (not system) → Add resource. Enable API access and copy the generated key.',
    fields:[
      {{key:'zone',        label:'Zone',        type:'text', ph:'webservices2  (check your login URL)'}},
      {{key:'username',    label:'Username',    type:'text', ph:'api-user@yourcompany.com'}},
      {{key:'api_key',     label:'API Key',     type:'password', ph:'API secret key'}},
      {{key:'account_id',  label:'Account ID',  type:'text', ph:'Numeric client account ID'}},
      {{key:'queue_id',    label:'Queue ID',    type:'text', ph:'Numeric ticket queue ID'}},
    ]}},
  {{id:'halopsa', name:'HaloPSA', icon:'&#128994;', color:'#00B050',
    desc:'Auto-create HaloPSA tickets when new CRITICAL/HIGH AI security findings are detected.',
    howto:'HaloPSA → Configuration → Integrations → HaloPSA API → New Application → Client Credentials.',
    fields:[
      {{key:'tenant',         label:'Instance URL',   type:'text',     ph:'mfdtest.trial.usehalo.com  or  yourco.halopsa.com'}},
      {{key:'client_id',      label:'Client ID',      type:'text',     ph:'OAuth2 client ID'}},
      {{key:'client_secret',  label:'Client Secret',  type:'password', ph:'OAuth2 client secret'}},
      {{key:'ticket_type_id', label:'Ticket Type ID', type:'text',     ph:'1'}},
    ]}},
  {{id:'jira', name:'Jira', icon:'&#128031;', color:'#0052CC',
    desc:'Auto-create Jira issues when new CRITICAL/HIGH AI security findings are detected.',
    howto:'id.atlassian.com → Security → API tokens → Create API token. Use your Atlassian email + token for auth.',
    fields:[
      {{key:'site',        label:'Site',         type:'text',     ph:'yourcompany  (before .atlassian.net)'}},
      {{key:'email',       label:'Email',        type:'text',     ph:'you@yourcompany.com'}},
      {{key:'api_token',   label:'API Token',    type:'password', ph:'Atlassian API token'}},
      {{key:'project_key', label:'Project Key',  type:'text',     ph:'IT  (e.g. IT, SEC, OPS)'}},
      {{key:'issue_type',  label:'Issue Type',   type:'text',     ph:'Bug  (Bug, Task, Story, etc.)'}},
    ]}},
];

var _psaCfg = {{}};

function _psaOrgParam() {{
  const sel = document.getElementById('psa-client-org-select');
  const val = sel ? sel.value : '';
  return val ? ('?client_org=' + encodeURIComponent(val)) : '';
}}

async function loadPsaClientOrgs() {{
  const sel = document.getElementById('psa-client-org-select');
  if (!sel) return;
  try {{
    const r = await fetch('/api/clients');
    if (!r.ok) return;
    const data = await r.json();
    (data.client_orgs || []).filter(o => o.id).forEach(o => {{
      const opt = document.createElement('option');
      opt.value = o.id;
      opt.textContent = o.name;
      sel.appendChild(opt);
    }});
  }} catch (_) {{}}
}}

async function loadPsaConfig() {{
  try {{
    const r = await fetch('/api/psa/config' + _psaOrgParam());
    if (!r.ok) return;
    _psaCfg = await r.json();
    renderPsaCards();
  }} catch (_) {{}}
}}

function renderPsaCards() {{
  const container = document.getElementById('psa-cards');
  if (!container) return;
  container.innerHTML = PSA_DEFS.map(def => {{
    const cfg     = _psaCfg[def.id] || {{}};
    const enabled = !!cfg.enabled;

    const fieldsHtml = def.fields.map(f => {{
      const val = f.type === 'password' && cfg[f.key] ? '__set__' : (cfg[f.key] || '');
      return `<div style="display:flex;align-items:center;gap:10px;padding:5px 0">
        <label style="font-size:13px;color:#374151;min-width:140px;flex-shrink:0">${{f.label}}</label>
        <input type="${{f.type === 'password' ? 'password' : 'text'}}" class="form-input psa-field"
          data-psa="${{def.id}}" data-key="${{f.key}}" value="${{esc(String(val))}}" placeholder="${{f.ph || ''}}"
          style="flex:1;font-size:13px;font-family:${{f.type === 'password' ? 'monospace' : 'inherit'}}">
      </div>`;
    }}).join('');

    return `
    <div style="background:#fff;border:1px solid #E5E7EB;border-radius:8px;overflow:hidden">
      <div style="display:flex;align-items:center;gap:12px;padding:14px 18px;background:#F9FAFB;border-bottom:1px solid #E5E7EB">
        <span style="font-size:22px">${{def.icon}}</span>
        <div style="flex:1">
          <div style="font-weight:700;font-size:15px;color:#111827">${{def.name}}</div>
          <div style="font-size:12px;color:#6B7280;margin-top:2px">${{def.desc}}</div>
        </div>
        <label style="display:flex;align-items:center;gap:6px;cursor:pointer;font-size:12px;color:#374151;font-weight:600;white-space:nowrap">
          <input type="checkbox" id="psa-enable-${{def.id}}" ${{enabled ? 'checked' : ''}}
            onchange="savePsaConfig('${{def.id}}')">
          Enable
        </label>
      </div>
      <div style="padding:14px 18px">
        ${{fieldsHtml}}
        <div style="font-size:11px;color:#9CA3AF;margin-top:10px;line-height:1.5">${{def.howto}}</div>
        <div style="display:flex;gap:10px;margin-top:14px;align-items:center">
          <button class="scan-btn" onclick="savePsaConfig('${{def.id}}')" style="color:#16A34A;border-color:#238636">&#10003; Save</button>
          <button class="scan-btn" onclick="testPsaConnection('${{def.id}}',this)" style="color:#4F46E5;border-color:#C7D2FE">&#9654; Test</button>
          <button class="scan-btn" onclick="testPsaTicket('${{def.id}}',this)" style="color:#CA8A04;border-color:#FDE68A">&#128203; Test Ticket</button>
          <span id="psa-test-${{def.id}}" style="font-size:13px;color:#6B7280"></span>
        </div>
      </div>
    </div>`;
  }}).join('');
}}

async function savePsaConfig(psaId) {{
  const fields = {{}};
  document.querySelectorAll(`.psa-field[data-psa="${{psaId}}"]`).forEach(el => {{
    fields[el.dataset.key] = el.value;
  }});
  const enabled = document.getElementById('psa-enable-' + psaId)?.checked ?? false;
  try {{
    const r = await fetch('/api/psa/config' + _psaOrgParam(), {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{id: psaId, enabled, fields}}),
    }});
    if (r.ok) {{
      _psaCfg[psaId] = {{...(_psaCfg[psaId] || {{}}), ...fields, enabled}};
      const banner = document.getElementById('psa-save-banner');
      if (banner) {{ banner.style.display = ''; setTimeout(() => banner.style.display = 'none', 3000); }}
    }} else {{ alert('Save failed'); }}
  }} catch (e) {{ alert('Save failed: ' + e); }}
}}

async function testPsaConnection(psaId, btn) {{
  const el = document.getElementById('psa-test-' + psaId);
  if (el) el.textContent = 'Testing…';
  btn.disabled = true;
  try {{
    const r = await fetch('/api/psa/test/' + psaId, {{method: 'POST'}});
    const d = await r.json();
    if (el) {{
      el.textContent = (d.ok ? '&#10003; ' : '&#10007; ') + d.message;
      el.style.color = d.ok ? '#16A34A' : '#DC2626';
    }}
  }} catch (e) {{
    if (el) {{ el.textContent = 'Error: ' + e; el.style.color = '#DC2626'; }}
  }}
  btn.disabled = false;
}}

async function testPsaTicket(psaId, btn) {{
  const el = document.getElementById('psa-test-' + psaId);
  if (el) el.textContent = 'Creating test ticket…';
  btn.disabled = true;
  try {{
    const r = await fetch('/api/psa/test-ticket/' + psaId, {{method: 'POST'}});
    const d = await r.json();
    if (el) {{
      el.innerHTML = (d.ok ? '&#10003; ' : '&#10007; ') + d.message;
      el.style.color = d.ok ? '#16A34A' : '#DC2626';
    }}
  }} catch (e) {{
    if (el) {{ el.textContent = 'Error: ' + e; el.style.color = '#DC2626'; }}
  }}
  btn.disabled = false;
}}

loadPsaClientOrgs();
loadPsaConfig();

// ── Wiki/docs integrations ───────────────────────────────────────────────────
// Same array-of-providers shape as PSA_DEFS above — a second wiki/notes
// tool (Confluence, OneNote, etc.) is a new entry here plus one small
// provider function in connectors/, not a new subsystem.

const NOTION_DEFS = [
  {{id:'notion', name:'Notion', icon:'&#128214;', color:'#000000',
    desc:'Create a page for every new CRITICAL/HIGH finding, with the same remediation content sent to chat and tickets.',
    howto:'notion.so/my-integrations → New integration → copy the "Internal Integration Secret" as the token below. Then share your target page or database with that integration (••• menu → Connections) — a valid token alone is not enough, Notion requires this second step.',
    fields:[
      {{key:'token',          label:'Integration Token', type:'password', ph:'secret_...'}},
      {{key:'parent_type',    label:'Parent Type',       type:'select',   ph:'', opts:[['page','Page'],['database','Database']]}},
      {{key:'page_id',        label:'Page ID',           type:'text',     ph:'Parent page ID (if Parent Type = Page)'}},
      {{key:'database_id',    label:'Database ID',       type:'text',     ph:'Parent database ID (if Parent Type = Database)'}},
      {{key:'title_property', label:'Title Property',    type:'text',     ph:'Name  (the title column name in that database)'}},
    ]}},
];

var _wikiCfg = {{}};

async function loadWikiConfig() {{
  try {{
    const r = await fetch('/api/wiki/config');
    if (!r.ok) return;
    _wikiCfg = await r.json();
    renderWikiCards();
  }} catch (_) {{}}
}}

function renderWikiCards() {{
  const container = document.getElementById('wiki-cards');
  if (!container) return;
  container.innerHTML = NOTION_DEFS.map(def => {{
    const cfg     = _wikiCfg[def.id] || {{}};
    const enabled = !!cfg.enabled;

    const fieldsHtml = def.fields.map(f => {{
      const val = f.type === 'password' && cfg[f.key] ? '__set__' : (cfg[f.key] || '');
      if (f.type === 'select') {{
        const optsHtml = (f.opts || []).map(([v, label]) =>
          `<option value="${{v}}" ${{val === v ? 'selected' : ''}}>${{label}}</option>`).join('');
        return `<div style="display:flex;align-items:center;gap:10px;padding:5px 0">
          <label style="font-size:13px;color:#374151;min-width:140px;flex-shrink:0">${{f.label}}</label>
          <select class="form-input wiki-field" data-wiki="${{def.id}}" data-key="${{f.key}}" style="flex:1;font-size:13px">${{optsHtml}}</select>
        </div>`;
      }}
      return `<div style="display:flex;align-items:center;gap:10px;padding:5px 0">
        <label style="font-size:13px;color:#374151;min-width:140px;flex-shrink:0">${{f.label}}</label>
        <input type="${{f.type === 'password' ? 'password' : 'text'}}" class="form-input wiki-field"
          data-wiki="${{def.id}}" data-key="${{f.key}}" value="${{esc(String(val))}}" placeholder="${{f.ph || ''}}"
          style="flex:1;font-size:13px;font-family:${{f.type === 'password' ? 'monospace' : 'inherit'}}">
      </div>`;
    }}).join('');

    return `
    <div style="background:#fff;border:1px solid #E5E7EB;border-radius:8px;overflow:hidden">
      <div style="display:flex;align-items:center;gap:12px;padding:14px 18px;background:#F9FAFB;border-bottom:1px solid #E5E7EB">
        <span style="font-size:22px">${{def.icon}}</span>
        <div style="flex:1">
          <div style="font-weight:700;font-size:15px;color:#111827">${{def.name}}</div>
          <div style="font-size:12px;color:#6B7280;margin-top:2px">${{def.desc}}</div>
        </div>
        <label style="display:flex;align-items:center;gap:6px;cursor:pointer;font-size:12px;color:#374151;font-weight:600;white-space:nowrap">
          <input type="checkbox" id="wiki-enable-${{def.id}}" ${{enabled ? 'checked' : ''}}
            onchange="saveWikiConfig('${{def.id}}')">
          Enable
        </label>
      </div>
      <div style="padding:14px 18px">
        ${{fieldsHtml}}
        <div style="font-size:11px;color:#9CA3AF;margin-top:10px;line-height:1.5">${{def.howto}}</div>
        <div style="display:flex;gap:10px;margin-top:14px;align-items:center">
          <button class="scan-btn" onclick="saveWikiConfig('${{def.id}}')" style="color:#16A34A;border-color:#238636">&#10003; Save</button>
          <button class="scan-btn" onclick="testWikiConnection('${{def.id}}',this)" style="color:#4F46E5;border-color:#C7D2FE">&#9654; Test</button>
          <button class="scan-btn" onclick="testWikiPage('${{def.id}}',this)" style="color:#CA8A04;border-color:#FDE68A">&#128214; Test Page</button>
          <span id="wiki-test-${{def.id}}" style="font-size:13px;color:#6B7280"></span>
        </div>
      </div>
    </div>`;
  }}).join('');
  // Selects render blank via innerHTML value attributes above; set them
  // explicitly after insertion so the previously-saved parent_type sticks.
  NOTION_DEFS.forEach(def => {{
    const cfg = _wikiCfg[def.id] || {{}};
    def.fields.filter(f => f.type === 'select').forEach(f => {{
      const el = document.querySelector(`select.wiki-field[data-wiki="${{def.id}}"][data-key="${{f.key}}"]`);
      if (el && cfg[f.key]) el.value = cfg[f.key];
    }});
  }});
}}

async function saveWikiConfig(wikiId) {{
  const fields = {{}};
  document.querySelectorAll(`.wiki-field[data-wiki="${{wikiId}}"]`).forEach(el => {{
    fields[el.dataset.key] = el.value;
  }});
  const enabled = document.getElementById('wiki-enable-' + wikiId)?.checked ?? false;
  try {{
    const r = await fetch('/api/wiki/config', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{id: wikiId, enabled, fields}}),
    }});
    if (r.ok) {{
      _wikiCfg[wikiId] = {{...(_wikiCfg[wikiId] || {{}}), ...fields, enabled}};
      const banner = document.getElementById('wiki-save-banner');
      if (banner) {{ banner.style.display = ''; setTimeout(() => banner.style.display = 'none', 3000); }}
    }} else {{ alert('Save failed'); }}
  }} catch (e) {{ alert('Save failed: ' + e); }}
}}

async function testWikiConnection(wikiId, btn) {{
  const el = document.getElementById('wiki-test-' + wikiId);
  if (el) el.textContent = 'Testing…';
  btn.disabled = true;
  try {{
    const r = await fetch('/api/wiki/test/' + wikiId, {{method: 'POST'}});
    const d = await r.json();
    if (el) {{
      el.textContent = (d.ok ? '&#10003; ' : '&#10007; ') + d.message;
      el.style.color = d.ok ? '#16A34A' : '#DC2626';
    }}
  }} catch (e) {{
    if (el) {{ el.textContent = 'Error: ' + e; el.style.color = '#DC2626'; }}
  }}
  btn.disabled = false;
}}

async function testWikiPage(wikiId, btn) {{
  const el = document.getElementById('wiki-test-' + wikiId);
  if (el) el.textContent = 'Creating test page…';
  btn.disabled = true;
  try {{
    const r = await fetch('/api/wiki/test-page/' + wikiId, {{method: 'POST'}});
    const d = await r.json();
    if (el) {{
      el.innerHTML = (d.ok ? '&#10003; ' : '&#10007; ') + d.message;
      el.style.color = d.ok ? '#16A34A' : '#DC2626';
    }}
  }} catch (e) {{
    if (el) {{ el.textContent = 'Error: ' + e; el.style.color = '#DC2626'; }}
  }}
  btn.disabled = false;
}}

loadWikiConfig();

// ── SIEM integrations ────────────────────────────────────────────────────────

const SIEM_DEFS = [
  {{id:'splunk',   name:'Splunk',               icon:'&#128200;', color:'#FF6900', status:'HTTP Event Collector',
    desc:'HTTP Event Collector — findings stream to any Splunk index as arckon:finding sourcetype.',
    fields:[
      {{key:'hec_url',    label:'HEC URL',       type:'text',     ph:'https://splunk.example.com:8088'}},
      {{key:'hec_token',  label:'HEC Token',     type:'password', ph:'••••••••'}},
      {{key:'index',      label:'Index',         type:'text',     ph:'arckon'}},
      {{key:'sourcetype', label:'Sourcetype',    type:'text',     ph:'arckon:finding'}},
      {{key:'verify_ssl', label:'Verify SSL',    type:'toggle'}},
    ]}},
  {{id:'sentinel', name:'Microsoft Sentinel',   icon:'&#9729;&#65039;', color:'#0078D4', status:'Log Analytics API',
    desc:'Azure Monitor HTTP Data Collector API — findings indexed to a custom Log Analytics table.',
    fields:[
      {{key:'workspace_id', label:'Workspace ID',  type:'text',     ph:'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'}},
      {{key:'shared_key',   label:'Shared Key',    type:'password', ph:'••••••••'}},
      {{key:'log_type',     label:'Table Name',    type:'text',     ph:'ArckonFindings'}},
    ]}},
  {{id:'qradar',   name:'IBM QRadar',            icon:'&#128274;', color:'#052FAD', status:'CEF / Syslog',
    desc:'CEF-formatted syslog (TCP/UDP) — findings appear as AI security events in QRadar.',
    fields:[
      {{key:'syslog_host', label:'Syslog Host', type:'text', ph:'qradar.example.com'}},
      {{key:'syslog_port', label:'Port',        type:'text', ph:'514'}},
      {{key:'protocol',    label:'Protocol',    type:'select', opts:['tcp','udp']}},
    ]}},
  {{id:'elastic',  name:'Elastic Security',      icon:'&#128269;', color:'#FEC514', status:'REST API / ECS',
    desc:'Direct Elasticsearch REST API — findings indexed with ECS field mapping for Kibana dashboards.',
    fields:[
      {{key:'endpoint',   label:'Endpoint',  type:'text',     ph:'https://elasticsearch.example.com:9200'}},
      {{key:'api_key',    label:'API Key',   type:'password', ph:'••••••••'}},
      {{key:'index',      label:'Index',     type:'text',     ph:'arckon-findings'}},
      {{key:'verify_ssl', label:'Verify SSL',type:'toggle'}},
    ]}},
  {{id:'exabeam',  name:'Exabeam',               icon:'&#128202;', color:'#7B61FF', status:'CEF / Syslog',
    desc:'CEF syslog — same Universal CEF parser as QRadar. Zero additional config once CEF is active.',
    fields:[
      {{key:'syslog_host', label:'Syslog Host', type:'text', ph:'exabeam.example.com'}},
      {{key:'syslog_port', label:'Port',        type:'text', ph:'514'}},
      {{key:'protocol',    label:'Protocol',    type:'select', opts:['udp','tcp']}},
    ]}},
  {{id:'kaseya',   name:'Kaseya',                icon:'&#128736;', color:'#E31E24', status:'VSA / BMS / IT Glue',
    desc:'VSA agent deployment · BMS ticket creation from findings · IT Glue AI inventory sync.',
    fields:[
      {{key:'vsa_url',        label:'VSA URL',        type:'text',     ph:'https://vsa.example.com'}},
      {{key:'vsa_api_key',    label:'VSA API Key',    type:'password', ph:'••••••••'}},
      {{key:'bms_url',        label:'BMS URL',        type:'text',     ph:'https://bms.example.com'}},
      {{key:'bms_api_key',    label:'BMS API Key',    type:'password', ph:'••••••••'}},
      {{key:'itglue_api_key', label:'IT Glue Key',    type:'password', ph:'••••••••'}},
      {{key:'itglue_org_id',  label:'IT Glue Org ID', type:'text',     ph:'123456'}},
      {{key:'ticket_queue',   label:'Ticket Queue',   type:'text',     ph:'Security'}},
    ]}},
];

const SEVERITY_OPTS = ['critical','high','medium','low'];
var _siemCfg = {{}};

async function loadSiemConfig() {{
  try {{
    const r = await fetch('/api/siem/config');
    if (!r.ok) return;
    _siemCfg = await r.json();
    renderSiemCards();
  }} catch (_) {{}}
}}

function renderSiemCards() {{
  const container = document.getElementById('siem-cards');
  if (!container) return;
  container.innerHTML = SIEM_DEFS.map(def => {{
    const cfg = _siemCfg[def.id] || {{}};
    const enabled = !!cfg.enabled;
    const sendOn  = cfg.send_on || ['critical','high'];

    const fieldsHtml = def.fields.map(f => {{
      if (f.type === 'toggle') {{
        return `<div style="display:flex;align-items:center;gap:10px;padding:6px 0">
          <label style="font-size:13px;color:#374151;min-width:140px">${{f.label}}</label>
          <label class="toggle-wrap"><input type="checkbox" class="siem-field" data-siem="${{def.id}}" data-key="${{f.key}}" ${{cfg[f.key]!==false?'checked':''}}><span class="toggle-track"></span></label>
        </div>`;
      }}
      if (f.type === 'select') {{
        const opts = (f.opts||[]).map(o=>`<option value="${{o}}" ${{cfg[f.key]===o?'selected':''}}>${{o}}</option>`).join('');
        return `<div style="display:flex;align-items:center;gap:10px;padding:6px 0">
          <label style="font-size:13px;color:#374151;min-width:140px">${{f.label}}</label>
          <select class="form-select siem-field" data-siem="${{def.id}}" data-key="${{f.key}}" style="width:120px;font-size:13px">${{opts}}</select>
        </div>`;
      }}
      const val = f.type === 'password' && cfg[f.key] ? '__set__' : (cfg[f.key] || '');
      return `<div style="display:flex;align-items:center;gap:10px;padding:6px 0">
        <label style="font-size:13px;color:#374151;min-width:140px">${{f.label}}</label>
        <input type="${{f.type==='password'?'password':'text'}}" class="form-input siem-field"
          data-siem="${{def.id}}" data-key="${{f.key}}" value="${{esc(val)}}" placeholder="${{f.ph||''}}"
          style="flex:1;font-size:13px;font-family:${{f.type==='password'?'monospace':'inherit'}}">
      </div>`;
    }}).join('');

    const severityHtml = SEVERITY_OPTS.map(s => `
      <label style="display:flex;align-items:center;gap:5px;font-size:12px;color:#374151;cursor:pointer">
        <input type="checkbox" class="siem-severity" data-siem="${{def.id}}" value="${{s}}"
          ${{sendOn.includes(s)?'checked':''}}> ${{s.charAt(0).toUpperCase()+s.slice(1)}}
      </label>`).join('');

    const statusStyle = `font-size:10px;padding:2px 8px;border-radius:3px;background:#FEF9C3;color:#92400E;border:1px solid #FDE047`;
    return `
    <div style="background:#fff;border:1px solid #E5E7EB;border-radius:8px;overflow:hidden">
      <div style="display:flex;align-items:center;gap:12px;padding:14px 18px;background:#F9FAFB;border-bottom:1px solid #E5E7EB">
        <span style="font-size:22px">${{def.icon}}</span>
        <div style="flex:1">
          <div style="font-weight:700;font-size:15px;color:#111827">${{def.name}}</div>
          <div style="font-size:12px;color:#6B7280;margin-top:2px">${{def.desc}}</div>
        </div>
        <span style="${{statusStyle}}">${{def.status}}</span>
        <label style="display:flex;align-items:center;gap:6px;cursor:pointer;font-size:12px;color:#374151;font-weight:600">
          <input type="checkbox" id="siem-enable-${{def.id}}" ${{enabled?'checked':''}}
            onchange="saveSiemConfig('${{def.id}}')">
          Enable
        </label>
      </div>
      <div style="padding:14px 18px">
        ${{fieldsHtml}}
        <div style="margin-top:12px">
          <div style="font-size:12px;color:#6B7280;margin-bottom:6px;font-weight:600">Forward on severity:</div>
          <div style="display:flex;gap:16px;flex-wrap:wrap">${{severityHtml}}</div>
        </div>
        <div style="display:flex;gap:10px;margin-top:16px;align-items:center">
          <button class="scan-btn" onclick="saveSiemConfig('${{def.id}}')" style="color:#16A34A;border-color:#238636">&#10003; Save</button>
          <button class="scan-btn" onclick="testSiemConnection('${{def.id}}',this)" style="color:#4F46E5;border-color:#C7D2FE">&#9654; Test</button>
          <span id="siem-test-${{def.id}}" style="font-size:13px;color:#6B7280"></span>
        </div>
      </div>
    </div>`;
  }}).join('');
}}

async function saveSiemConfig(siemId) {{
  const payload = {{}};
  document.querySelectorAll(`.siem-field[data-siem="${{siemId}}"]`).forEach(el => {{
    const key = el.dataset.key;
    payload[key] = el.type === 'checkbox' ? el.checked : el.value;
  }});
  const severities = [...document.querySelectorAll(`.siem-severity[data-siem="${{siemId}}"]:checked`)].map(c=>c.value);
  payload.send_on  = severities;
  payload.enabled  = document.getElementById('siem-enable-' + siemId)?.checked ?? false;

  try {{
    const r = await fetch('/api/siem/config', {{
      method: 'POST',
      headers: {{'Content-Type':'application/json'}},
      body: JSON.stringify({{[siemId]: payload}}),
    }});
    if (r.ok) {{
      _siemCfg[siemId] = {{...(_siemCfg[siemId]||{{}}), ...payload}};
      const banner = document.getElementById('siem-save-banner');
      if (banner) {{ banner.style.display=''; setTimeout(()=>banner.style.display='none', 3000); }}
    }}
  }} catch(e) {{ alert('Save failed: ' + e); }}
}}

async function testSiemConnection(siemId, btn) {{
  const el = document.getElementById('siem-test-' + siemId);
  if (el) el.textContent = 'Testing…';
  btn.disabled = true;
  try {{
    const r = await fetch('/api/siem/test/' + siemId, {{method:'POST'}});
    const d = await r.json();
    if (el) {{
      el.textContent = d.ok ? '&#10003; ' + d.message : '&#10007; ' + d.message;
      el.style.color = d.ok ? '#16A34A' : '#DC2626';
    }}
  }} catch(e) {{
    if (el) {{ el.textContent = 'Error: ' + e; el.style.color='#DC2626'; }}
  }}
  btn.disabled = false;
}}

loadSiemConfig();

async function loadConfig() {{
  try {{
    const r = await fetch('/api/config');
    if (!r.ok) return;
    const c = await r.json();
    const intvl = document.getElementById('cfg-interval');
    if (intvl && c.interval) intvl.value = c.interval;
    const subnets = document.getElementById('cfg-subnets');
    if (subnets && c.extra_subnets) subnets.value = c.extra_subnets;
  }} catch (_) {{}}
  try {{
    const r = await fetch('/api/baseline-profile');
    if (!r.ok) return;
    const c = await r.json();
    const profile = document.getElementById('cfg-baseline-profile');
    if (profile && c.profile) profile.value = c.profile;
  }} catch (_) {{}}
}}

async function saveConfig() {{
  const body = {{}};
  const intvl = document.getElementById('cfg-interval')?.value?.trim();
  if (intvl) body.interval = parseInt(intvl, 10);
  const subnets = document.getElementById('cfg-subnets')?.value?.trim();
  if (subnets !== undefined) body.extra_subnets = subnets;
  try {{
    const baseline = document.getElementById('cfg-baseline-profile')?.value;
    const baselineRequest = baseline ? fetch('/api/baseline-profile', {{
      method: 'POST', headers: {{'Content-Type': 'application/json'}}, body: JSON.stringify({{profile: baseline}}),
    }}) : null;
    const r = await fetch('/api/config', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify(body),
    }});
    const d = await r.json();
    const baselineResponse = baselineRequest ? await baselineRequest : null;
    const baselineResult = baselineResponse ? await baselineResponse.json() : {{pushed_to_agents: 0}};
    if (baselineResponse && !baselineResponse.ok) throw new Error(baselineResult.error || 'Baseline save failed');

    const el = document.getElementById('cfg-saved');
    if (el) {{
      const n = Math.max(d.pushed_to_agents || 0, baselineResult.pushed_to_agents || 0);
      el.textContent = n > 0
        ? `✓ Saved and applied to ${{n}} agent${{n !== 1 ? 's' : ''}}`
        : '✓ Saved — new agents will receive this default on enrollment';
      el.style.display = 'block';
      setTimeout(() => el.style.display = 'none', 6000);
    }}
  }} catch (e) {{ alert('Save failed: ' + e); }}
}}

loadConfig();

async function loadAlertConfig() {{
  try {{
    const r = await fetch('/api/alerts/config');
    if (!r.ok) return;
    const c = await r.json();
    const v = (id, val) => {{ const el = document.getElementById(id); if (el) el.value = val || ''; }};
    v('alert-slack',   '');
    const slackStatus = document.getElementById('alert-slack-status');
    const slackClear = document.getElementById('alert-slack-clear');
    if (c.slack_webhook_configured) {{
      if (slackStatus) slackStatus.textContent = 'A Slack webhook is configured. Enter a replacement URL to change it.';
      if (slackClear) slackClear.style.display = '';
    }} else {{
      if (slackStatus) slackStatus.textContent = 'How to get one: Slack → Your workspace → Apps → Incoming Webhooks';
      if (slackClear) slackClear.style.display = 'none';
    }}
    v('alert-gchat',   c.gchat_webhook  || '');
    v('alert-teams',   c.teams_webhook  || '');
    v('alert-webhook', c.webhook_url    || '');
    v('alert-smtp-host', c.email?.smtp_host || '');
    const portEl = document.getElementById('alert-smtp-port');
    if (portEl) portEl.value = c.email?.smtp_port || 587;
    v('alert-smtp-user', c.email?.smtp_user || '');
    v('alert-smtp-pass', c.email?.smtp_pass || '');
    v('alert-email-from', c.email?.from || '');
    v('alert-email-to',   c.email?.to   || '');
    const t = c.triggers || {{}};
    const cb = (id, val) => {{ const el = document.getElementById(id); if (el) el.checked = val !== false; }};
    cb('trig-crit',           t.new_critical);
    cb('trig-high',           t.new_high);
    cb('trig-shadow',         t.new_shadow_ai);
    cb('trig-unapproved-only', t.alert_unapproved_only);
  }} catch (_) {{}}
}}

function liveModeChanged() {{
  const mode = document.getElementById('live-mode')?.value;
  const epLabel = document.getElementById('live-endpoint-label');
  const epInput = document.getElementById('live-endpoint');
  const modelInput = document.getElementById('live-model');
  if (!epLabel || !epInput || !modelInput) return;
  if (mode === 'anthropic') {{
    epLabel.textContent = 'Endpoint URL';
    epInput.placeholder = 'https://api.anthropic.com (optional)';
    modelInput.placeholder = 'claude-sonnet-4-6';
  }} else if (mode === 'gemini') {{
    epLabel.textContent = 'Endpoint URL';
    epInput.placeholder = 'Leave blank for default';
    modelInput.placeholder = 'gemini-1.5-flash';
  }} else if (mode === 'local') {{
    epLabel.textContent = 'Ollama Host';
    epInput.placeholder = 'http://localhost:11434';
    modelInput.placeholder = 'llama3';
  }} else {{
    epLabel.textContent = 'Endpoint URL';
    epInput.placeholder = 'https://api.openai.com/v1';
    modelInput.placeholder = 'gpt-4o-2024-11-20';
  }}
}}

async function loadBranding() {{
  try {{
    const r = await fetch('/api/branding');
    if (!r.ok) return;
    const d = await r.json();
    const set = (id, val) => {{ const el = document.getElementById(id); if (el && val) el.value = val; }};
    set('brand-msp-name',   d.msp_name);
    set('brand-logo-url',   d.logo_url);
    set('brand-footer-text', d.footer_text);
  }} catch (_) {{}}
}}

async function saveBranding() {{
  const gv = id => document.getElementById(id)?.value?.trim() || '';
  try {{
    const r = await fetch('/api/branding', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{
        msp_name:    gv('brand-msp-name'),
        logo_url:    gv('brand-logo-url'),
        footer_text: gv('brand-footer-text'),
      }}),
    }});
    if (r.ok) {{
      const b = document.getElementById('branding-saved');
      if (b) {{ b.style.display = ''; setTimeout(() => b.style.display = 'none', 3000); }}
    }} else {{ alert('Save failed'); }}
  }} catch (e) {{ alert('Save failed: ' + e); }}
}}

async function loadLiveScanConfig() {{
  try {{
    const r = await fetch('/api/live-scan-config');
    if (!r.ok) return;
    const d = await r.json();
    if (d.locked) return;
    if (d.mode)     {{ const el = document.getElementById('live-mode'); if (el) {{ el.value = d.mode; liveModeChanged(); }} }}
    if (d.endpoint) {{ const el = document.getElementById('live-endpoint'); if (el) el.value = d.endpoint; }}
    if (d.model)    {{ const el = document.getElementById('live-model'); if (el) el.value = d.model; }}
    if (d.api_key_set) {{ const el = document.getElementById('live-key-set'); if (el) el.style.display = 'inline'; }}
  }} catch (_) {{}}
}}

async function saveLiveScanConfig() {{
  const gv = id => document.getElementById(id)?.value?.trim() || '';
  const body = {{
    mode:     gv('live-mode'),
    api_key:  document.getElementById('live-api-key')?.value || '',
    endpoint: gv('live-endpoint'),
    model:    gv('live-model'),
  }};
  if (!body.mode) {{ alert('Select an AI provider first.'); return; }}
  try {{
    const r = await fetch('/api/live-scan-config', {{
      method: 'POST', headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify(body),
    }});
    if (r.ok) {{
      const el = document.getElementById('live-scan-saved');
      if (el) {{ el.style.display = 'block'; setTimeout(() => el.style.display = 'none', 4000); }}
      const keyEl = document.getElementById('live-key-set');
      if (keyEl && body.api_key) keyEl.style.display = 'inline';
      document.getElementById('live-api-key').value = '';
    }} else {{ alert('Save failed.'); }}
  }} catch (e) {{ alert('Save failed: ' + e); }}
}}

async function runLiveScan(btn) {{
  const mode = document.getElementById('live-mode')?.value;
  if (!mode) {{ alert('Select an AI provider first.'); return; }}
  const orig = btn.textContent;
  btn.disabled = true; btn.textContent = 'Starting...';
  try {{
    const r = await fetch('/api/scan', {{
      method: 'POST', headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{mode: 'api', providers: [mode], profile: 'default'}}),
    }});
    const d = await r.json();
    if (d.error) {{ alert(d.error); }}
    else {{ navTo('scan'); }}
  }} catch (e) {{ alert('Failed to start scan: ' + e); }}
  finally {{ btn.disabled = false; btn.textContent = orig; }}
}}

async function saveAlertConfig() {{
  const gv = id => document.getElementById(id)?.value?.trim() || '';
  const body = {{
    slack_webhook:  gv('alert-slack'),
    slack_webhook_clear: document.getElementById('alert-slack')?.dataset.clear === 'true',
    gchat_webhook:  gv('alert-gchat'),
    teams_webhook:  gv('alert-teams'),
    webhook_url:    gv('alert-webhook'),
    email: {{
      smtp_host: gv('alert-smtp-host'),
      smtp_port: parseInt(document.getElementById('alert-smtp-port')?.value || '587', 10),
      smtp_user: gv('alert-smtp-user'),
      smtp_pass: document.getElementById('alert-smtp-pass')?.value || '',
      from:      gv('alert-email-from'),
      to:        gv('alert-email-to'),
    }},
    triggers: {{
      new_critical:          document.getElementById('trig-crit')?.checked           ?? true,
      new_high:              document.getElementById('trig-high')?.checked           ?? true,
      new_shadow_ai:         document.getElementById('trig-shadow')?.checked         ?? true,
      alert_unapproved_only: document.getElementById('trig-unapproved-only')?.checked ?? false,
    }},
  }};
  try {{
    const r = await fetch('/api/alerts/config', {{
      method: 'POST', headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify(body),
    }});
    const el = document.getElementById('alert-saved');
    if (r.ok) {{
      const input = document.getElementById('alert-slack');
      if (input) {{ input.value = ''; delete input.dataset.clear; }}
      loadAlertConfig();
      if (el) {{ el.style.display = 'block'; setTimeout(() => el.style.display = 'none', 4000); }}
    }} else {{ alert('Save failed: ' + (await r.json()).error); }}
  }} catch (e) {{ alert('Save failed: ' + e); }}
}}

function clearSlackWebhook() {{
  const input = document.getElementById('alert-slack');
  if (!input || !confirm('Remove the configured Slack webhook?')) return;
  input.value = '';
  input.dataset.clear = 'true';
  const status = document.getElementById('alert-slack-status');
  if (status) status.textContent = 'Slack webhook will be removed when you save alert settings.';
}}

async function testAlert(channel) {{
  const el = document.getElementById('alert-test-result');
  if (el) {{ el.style.display = 'block'; el.style.color = '#6B7280'; el.textContent = 'Sending test…'; }}
  const urlFields = {{slack:'alert-slack',gchat:'alert-gchat',teams:'alert-teams',webhook:'alert-webhook'}};
  const liveUrl = (document.getElementById(urlFields[channel] || '')?.value || '').trim();
  try {{
    const r = await fetch('/api/alerts/test', {{
      method: 'POST', headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{channel, url: liveUrl}}),
    }});
    const d = await r.json();
    if (el) {{
      el.style.color = d.ok ? '#16A34A' : '#DC2626';
      el.textContent = (d.ok ? '✓ ' : '✗ ') + d.message;
      setTimeout(() => el.style.display = 'none', 6000);
    }}
  }} catch (e) {{
    if (el) {{ el.style.color = '#DC2626'; el.textContent = '✗ Request failed: ' + e; }}
  }}
}}

loadAlertConfig();

// ── Active issues (current CRITICAL/HIGH FAILs from latest reports) ──────────
async function refreshAlertsPage(btn) {{
  if (btn) {{ btn.disabled = true; btn.innerHTML = '&#8635; Refreshing…'; }}
  try {{
    await Promise.all([loadActiveIssues(), loadAlertEvents()]);
  }} finally {{
    if (btn) {{
      btn.innerHTML = '&#10003; Updated';
      setTimeout(() => {{ btn.disabled = false; btn.innerHTML = '&#8635; Refresh'; }}, 1200);
    }}
  }}
}}

async function loadActiveIssues() {{
  const feed = document.getElementById('active-issues-feed');
  if (!feed) return;
  feed.innerHTML = '<div style="color:#9CA3AF;font-size:13px;padding:12px 0">Loading…</div>';
  try {{
    const r = await fetch('/api/alerts/active-issues');
    if (!r.ok) throw new Error(r.status);
    const d = await r.json();
    const issues = d.issues || [];
    if (!issues.length) {{
      feed.innerHTML = '<div style="color:#16A34A;font-size:13px;padding:12px 0;display:flex;align-items:center;gap:6px"><span style="font-size:16px">✓</span> No active critical or high issues across your fleet.</div>';
      return;
    }}
    feed.innerHTML = issues.map(iss => {{
      const sev = iss.severity || 'HIGH';
      const sevColor = sev === 'CRITICAL' ? '#DC2626' : '#CA8A04';
      const sevBg    = sev === 'CRITICAL' ? '#FEF2F2' : '#FFFBEB';
      const ts = new Date(iss.last_seen * 1000);
      const timeStr = 'Last seen ' + ts.toLocaleDateString() + ' ' + ts.toLocaleTimeString([], {{hour:'2-digit',minute:'2-digit'}});
      const cid = iss.check_id.replace(/'/g, '');
      return `<div style="background:#fff;border:1px solid ${{sevBg}};border-left:3px solid ${{sevColor}};border-radius:6px;padding:10px 14px;display:flex;gap:10px;align-items:flex-start">
        <div style="min-width:64px;text-align:center;flex-shrink:0">
          <div style="font-size:10px;font-weight:700;color:${{sevColor}};background:${{sevBg}};border-radius:4px;padding:2px 6px;white-space:nowrap">${{sev}}</div>
          <div style="font-size:10px;color:#6B7280;margin-top:3px">Active</div>
        </div>
        <div style="flex:1;min-width:0">
          <div style="font-size:13px;color:#111827"><strong>${{iss.check_id}}</strong> on <strong>${{iss.hostname}}</strong> — ${{iss.title}}</div>
          <div style="font-size:11px;color:#9CA3AF;margin-top:4px">${{timeStr}}</div>
          <div style="margin-top:8px;display:flex;gap:6px">
            <button onclick="issueAction('${{cid}}','false_positive')" style="font-size:11px;padding:3px 10px;border-radius:4px;border:1px solid #D1D5DB;background:#F9FAFB;cursor:pointer;color:#374151">False Positive</button>
            <button onclick="issueAction('${{cid}}','accepted')" style="font-size:11px;padding:3px 10px;border-radius:4px;border:1px solid #D1D5DB;background:#F9FAFB;cursor:pointer;color:#374151">Accept Risk</button>
          </div>
        </div>
      </div>`;
    }}).join('');
  }} catch (e) {{
    if (feed) feed.innerHTML = '<div style="color:#DC2626;font-size:13px">Failed to load active issues: ' + e + '</div>';
  }}
}}

async function issueAction(checkId, action) {{
  const label = action === 'false_positive' ? 'false positive' : 'accepted risk';
  const note = window.prompt('Optional note for marking as ' + label + ':') ?? '';
  if (note === null) return;
  try {{
    const r = await fetch('/api/fleet/risk-register/override', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{check_id: checkId, action, note, assignee: '', expires_at: null}})
    }});
    if (r.ok) {{
      loadActiveIssues();
    }} else {{
      alert('Failed to save (' + r.status + ')');
    }}
  }} catch (e) {{
    alert('Error: ' + e);
  }}
}}

// ── Alert history feed ────────────────────────────────────────────────────────
async function loadAlertEvents() {{
  const unreviewedOnly = document.getElementById('alerts-unreviewed-only')?.checked;
  const feed = document.getElementById('alerts-feed');
  if (!feed) return;
  feed.innerHTML = '<div style="color:#9CA3AF;font-size:13px;padding:16px 0">Loading…</div>';
  try {{
    const r = await fetch('/api/alerts/events' + (unreviewedOnly ? '?unreviewed=1' : ''));
    if (!r.ok) throw new Error(r.status);
    const d = await r.json();
    const events = d.events || [];
    if (!events.length) {{
      feed.innerHTML = '<div style="color:#9CA3AF;font-size:13px;padding:16px 0">No history yet. New discoveries and newly-detected critical/high findings will appear here going forward.</div>';
      return;
    }}
    feed.innerHTML = events.map(ev => {{
      const sev = ev.severity || 'HIGH';
      const sevColor = sev === 'CRITICAL' ? '#DC2626' : sev === 'HIGH' ? '#CA8A04' : '#4F46E5';
      const sevBg    = sev === 'CRITICAL' ? '#FEF2F2' : sev === 'HIGH' ? '#FFFBEB' : '#EEF2FF';
      const ts = new Date(ev.ts * 1000);
      const timeStr = ts.toLocaleDateString() + ' ' + ts.toLocaleTimeString([], {{hour:'2-digit',minute:'2-digit'}});
      let title = '';
      if (ev.event_type === 'new_shadow_ai') {{
        const srcLabel = ev.source === 'saas_ai' ? 'SaaS AI (active session)' : ev.source || 'network';
        title = `<strong>${{ev.service || 'Unknown service'}}</strong> detected on <strong>${{ev.device}}</strong>`;
        if (ev.host) title += ` — ${{ev.host}}`;
        title += `<span style="font-size:11px;color:#6B7280;margin-left:8px">via ${{srcLabel}}</span>`;
      }} else {{
        title = `<strong>${{ev.check_id || ev.event_type}}</strong> on <strong>${{ev.device}}</strong>`;
        if (ev.title) title += ` — ${{ev.title}}`;
      }}
      const channelBadges = (ev.channels || '').split(',').filter(Boolean).map(c =>
        `<span style="font-size:10px;background:#F3F4F6;color:#374151;border-radius:4px;padding:1px 6px;white-space:nowrap">${{c.trim()}}</span>`
      ).join(' ');
      const reviewedStyle = ev.reviewed ? 'opacity:0.55;' : '';
      return `<div style="${{reviewedStyle}}background:#fff;border:1px solid ${{ev.reviewed ? '#F3F4F6' : sevBg}};border-left:3px solid ${{ev.reviewed ? '#E5E7EB' : sevColor}};border-radius:6px;padding:12px 16px;display:flex;gap:12px;align-items:flex-start">
        <div style="min-width:64px;text-align:center">
          <div style="font-size:10px;font-weight:700;color:${{sevColor}};background:${{sevBg}};border-radius:4px;padding:2px 6px;white-space:nowrap">${{sev}}</div>
          ${{ev.event_type === 'new_shadow_ai' ? '<div style="font-size:10px;color:#6B7280;margin-top:3px">Shadow AI</div>' : '<div style="font-size:10px;color:#6B7280;margin-top:3px">Finding</div>'}}
        </div>
        <div style="flex:1;min-width:0">
          <div style="font-size:13px;color:#111827;line-height:1.4">${{title}}</div>
          <div style="margin-top:6px;display:flex;gap:6px;flex-wrap:wrap;align-items:center">
            <span style="font-size:11px;color:#9CA3AF">${{timeStr}}</span>
            ${{channelBadges || '<span style="font-size:11px;color:#9CA3AF;font-style:italic">no channels configured</span>'}}
          </div>
        </div>
        <div>
          ${{ev.reviewed
            ? '<span style="font-size:11px;color:#9CA3AF">Reviewed</span>'
            : `<button class="scan-btn" onclick="markAlertReviewed(${{ev.id}}, this)" style="font-size:11px;padding:3px 10px;color:#16A34A;border-color:#E5E7EB;white-space:nowrap">Mark reviewed</button>`
          }}
        </div>
      </div>`;
    }}).join('');
    updateAlertBadge();
  }} catch (e) {{
    feed.innerHTML = '<div style="color:#DC2626;font-size:13px;padding:16px 0">Failed to load alerts: ' + e + '</div>';
  }}
}}

async function markAlertReviewed(id, btn) {{
  if (btn) {{ btn.disabled = true; btn.textContent = '…'; }}
  try {{
    await fetch('/api/alerts/events/' + id + '/review', {{method:'POST'}});
    loadAlertEvents();
    updateAlertBadge();
  }} catch(e) {{ if (btn) {{ btn.disabled = false; btn.textContent = 'Mark reviewed'; }} }}
}}

async function markAllAlertsReviewed() {{
  try {{
    await fetch('/api/alerts/events/review-all', {{method:'POST'}});
    loadAlertEvents();
    updateAlertBadge();
  }} catch(e) {{}}
}}

async function updateAlertBadge() {{
  try {{
    const r = await fetch('/api/alerts/unreviewed-count');
    if (!r.ok) return;
    const d = await r.json();
    const badge = document.getElementById('alert-badge');
    if (!badge) return;
    if (d.count > 0) {{
      badge.textContent = d.count;
      badge.style.display = 'inline';
    }} else {{
      badge.style.display = 'none';
    }}
  }} catch(_) {{}}
}}

updateAlertBadge();

// ── Auto-refresh (lightweight poll — no full page reload) ──
(function() {{
  var INTERVAL = 60;
  var remaining = INTERVAL;
  var el = document.getElementById('auto-refresh-countdown');

  function setText(t) {{ if (el) el.textContent = t; }}

  function patch(data) {{
    var cards = {{
      'sc-count': data.count, 'sc-fail': data.ch,
      'sc-warn':  data.med,   'sc-pass': data.li,
      'sc-shadow': data.shadow, 'sc-mcp': data.mcp
    }};
    Object.keys(cards).forEach(function(id) {{
      var e = document.getElementById(id);
      if (e != null) e.textContent = cards[id];
    }});
    var tbody = document.getElementById('device-tbody');
    if (tbody && data.rows_html != null) tbody.innerHTML = data.rows_html;
    remaining = INTERVAL;
    setText('Updated just now');
  }}

  function refresh() {{
    setText('Updating…');
    fetch('/api/fleet/live-stats')
      .then(function(r) {{ return r.ok ? r.json() : null; }})
      .then(function(data) {{ if (data && !data.error) patch(data); else setText('Refreshing in ' + INTERVAL + 's'); }})
      .catch(function() {{ setText('Refreshing in ' + INTERVAL + 's'); }});
  }}

  function tick() {{
    remaining--;
    if (remaining <= 0) {{ remaining = INTERVAL; refresh(); return; }}
    setText('Refreshing in ' + remaining + 's');
  }}

  setText('Refreshing in ' + remaining + 's');
  setInterval(tick, 1000);
}})();
</script>
<div style="margin-top:48px;padding:16px 0 24px;border-top:1px solid #E5E7EB;text-align:center;font-size:11px;color:#9CA3AF">
  © 2026 RiskRaven. All rights reserved. Patent Pending.
  &nbsp;·&nbsp; <span id="auto-refresh-countdown" style="color:#4F46E5"></span>
</div>
</body>
</html>"""


def main():
    import argparse
    ap = argparse.ArgumentParser(description='Arckon Dashboard Server')
    ap.add_argument('--port', type=int, default=PORT, help=f'Port to listen on (default: {PORT})')
    ap.add_argument('--host', default='0.0.0.0', help='Bind address (default: 0.0.0.0 — all interfaces)')
    ap.add_argument('--no-browser', action='store_true', help="Don't auto-open browser")
    args = ap.parse_args()

    global _serve_port
    _serve_port = args.port

    log_file = ROOT / '.sentinel-server.log'
    _handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]
    try:
        _handlers.insert(0, logging.FileHandler(log_file, encoding='utf-8'))
    except OSError:
        pass  # service account may not have write access; console-only logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s %(name)s %(message)s',
        handlers=_handlers,
    )

    try:
        _load_license()
        from license import start_monitors
        start_monitors(_get_store('default'))
    except Exception as _startup_err:
        log.error('License/monitor startup error (non-fatal): %s', _startup_err, exc_info=True)

    _last_report_check_day = [None]  # mutable cell so the closure can update it

    def _check_client_org_reports():
        """Runs at most once per calendar day (UTC) — cheap enough to just
        check on every tick, but no reason to hit the registry 1440x/day
        for something that's only ever due once a month per client."""
        today = datetime.now(timezone.utc).date()
        if _last_report_check_day[0] == today:
            return
        _last_report_check_day[0] = today
        try:
            for org in _get_registry().get_client_orgs_due_for_report():
                ok, msg = send_client_org_report(
                    org['customer_id'], org['id'], org['name'], org['report_email'])
                if ok:
                    _get_registry().mark_client_org_report_sent(org['id'])
                    log.info('Scheduled report sent for client org %s (%s)', org['name'], org['id'])
                else:
                    log.warning('Scheduled report FAILED for client org %s (%s): %s', org['name'], org['id'], msg)
        except Exception as _re:
            log.error('client org report scheduler error: %s', _re)

    def _schedule_ticker():
        import time as _t
        while True:
            _t.sleep(60)
            try:
                customers = _get_registry().list_customers()
                cids = [c['id'] for c in customers] or ['default']
                for cid in cids:
                    try:
                        _st = _get_store(cid)
                        for sched in _st.get_due_schedules():
                            device_id = sched.get('device_id', 'all')
                            if device_id == 'all':
                                devices = _st.list_devices()
                                for d in devices:
                                    _get_store_for_device(d['device_id']).enqueue_command(d['device_id'], 'scan_now')
                                log.info('schedule %s fired for customer %s: %d devices', sched['id'], cid, len(devices))
                            else:
                                _get_store_for_device(device_id).enqueue_command(device_id, 'scan_now')
                                log.info('schedule %s fired for customer %s: device %s', sched['id'], cid, device_id)
                            _st.mark_schedule_fired(sched['id'])
                    except Exception as _ce:
                        log.error('schedule ticker error for customer %s: %s', cid, _ce)
            except Exception as _se:
                log.error('schedule ticker error: %s', _se)
            _check_client_org_reports()

    threading.Thread(target=_schedule_ticker, daemon=True, name='schedule-ticker').start()

    server = http.server.ThreadingHTTPServer((args.host, args.port), _Handler)

    tls_cert = os.environ.get('SENTINEL_TLS_CERT', '')
    tls_key  = os.environ.get('SENTINEL_TLS_KEY', '')
    if tls_cert and tls_key:
        import ssl as _ssl
        ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(tls_cert, tls_key)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        scheme = 'https'
    else:
        scheme = 'http'
        log.warning(
            'TLS not configured — fleet traffic is unencrypted. '
            'Set SENTINEL_TLS_CERT and SENTINEL_TLS_KEY env vars to enable HTTPS, '
            'or run behind a TLS-terminating reverse proxy (nginx, Caddy).'
        )

    url = f'{scheme}://localhost:{args.port}'
    print('\n  Arckon by RiskRaven  ·  Dashboard Server')
    print(f'  Project  : {ROOT}')
    print(f'  Dashboard: {url}')
    print(f'  Command Center: {url}/command (also available at {url}/fleet)')
    print(f'  Devices  : {url}/api/devices')
    print(f'  Network  : {scheme}://0.0.0.0:{args.port} (accessible from LAN)')
    if scheme == 'http':
        print('  WARNING  : TLS not enabled — set SENTINEL_TLS_CERT + SENTINEL_TLS_KEY for HTTPS')
    print('  Stop     : Ctrl+C\n')
    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nStopped.')


if __name__ == '__main__':
    main()
