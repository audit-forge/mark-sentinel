#!/usr/bin/env python3
"""
M.A.R.K. Sentinel — Dashboard Server
Serves the live dashboard and runs on-demand scans via a browser UI.

Usage:
  python3 server.py                   # serves latest results on :7331
  python3 server.py --port 8080       # custom port
  python3 server.py --no-browser      # don't auto-open browser
"""
import sys
if sys.version_info < (3, 11):
    sys.exit(
        "M.A.R.K. Sentinel requires Python 3.11 or later.\n"
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
    import importlib, subprocess as _sp, os as _os, time as _time
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
import io
import json
import logging
import os
import subprocess
import tarfile
import threading
import time
import webbrowser
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

PORT = 7331
ROOT = Path(__file__).parent
_serve_port = PORT   # updated at startup so handlers can reference it

log = logging.getLogger('sentinel.server')

# ── scan state ────────────────────────────────────────────────────────────────
_lock   = threading.Lock()
_status = 'idle'       # idle | running | done | error
_log: list[str] = []
# ─────────────────────────────────────────────────────────────────────────────

# ── agent store (lazy init) ───────────────────────────────────────────────────
_store = None
_store_lock = threading.Lock()

def _get_store():
    global _store
    if _store is None:
        with _store_lock:
            if _store is None:
                from storage import AgentStore
                _store = AgentStore(ROOT / 'output' / 'agents.db')
    return _store


# ── license (loaded once at startup) ─────────────────────────────────────────
def _load_license() -> None:
    from license import load_license
    load_license(ROOT / 'license.json')

def _content_length(headers) -> int:
    """Safely parse Content-Length header; returns 0 on missing or invalid value."""
    try:
        return max(0, int(headers.get('Content-Length', 0)))
    except (ValueError, TypeError):
        return 0


def _agent_token() -> str:
    """Return legacy single-token value. Empty string means no auth configured."""
    if os.environ.get('SENTINEL_AGENT_TOKEN'):
        return os.environ['SENTINEL_AGENT_TOKEN']
    tok_file = ROOT / 'agent_token.txt'
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

def _dashboard_token() -> str:
    """Return expected dashboard token. Empty = no auth required."""
    if os.environ.get('SENTINEL_DASHBOARD_TOKEN'):
        return os.environ['SENTINEL_DASHBOARD_TOKEN']
    tok_file = ROOT / 'dashboard_token.txt'
    if tok_file.exists():
        return tok_file.read_text().strip()
    return ''

# ── per-device report rate limiting ──────────────────────────────────────────
_report_last_seen: dict[str, float] = {}
_report_lock = threading.Lock()
_REPORT_MIN_INTERVAL = 60  # seconds between accepted reports per device
# ─────────────────────────────────────────────────────────────────────────────


def _latest_out_dir() -> Path | None:
    """Return the newest demo_* dir (by directory name) that has a non-empty dashboard.html."""
    candidates = []
    for d in (ROOT / 'output').glob('demo_*'):
        p = d / 'dashboard.html'
        if p.exists():
            try:
                if p.stat().st_size > 1024:
                    candidates.append(d.name)
            except Exception:
                pass
    if not candidates:
        return None
    candidates.sort(reverse=True)
    return ROOT / 'output' / candidates[0]


def _rebuild_dashboard(out_dir: Path) -> bool:
    try:
        sys.path.insert(0, str(ROOT))
        from output.dashboard import generate
        label_map = {
            'config_scan':           'Config Scan',
            'openai':                'ChatGPT (gpt-4o)',
            'claude':                'Anthropic (claude-sonnet-4-6)',
            'ollama___qwen2.5-7b':   'Ollama (qwen2.5-7b)',
            'hash-ai___openclaw':    'Hash-AI (openclaw)',
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
_STATUS_LABEL_HTML = {'FAIL': 'HIGH RISK', 'WARN': 'MEDIUM RISK', 'PASS': 'INFO', 'SKIP': 'SKIP', 'N/A': 'N/A'}


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
    net_servers  = [s for s in servers if s.get('source') == 'network']
    proc_servers = [s for s in servers if s.get('source') == 'process']
    all_tools    = sorted({t for s in servers for t in (s.get('tools') or [])})

    risk_level  = 'CRITICAL' if no_auth else 'MEDIUM' if unknown_auth else 'LOW'
    risk_color  = '#f85149' if risk_level == 'CRITICAL' else '#d29922' if risk_level == 'MEDIUM' else '#3fb950'

    btn_style = ('display:inline-block;padding:6px 14px;border-radius:6px;font-size:12px;'
                 'font-weight:600;cursor:pointer;border:1px solid #30363d;background:#21262d;color:#c9d1d9')
    active_btn = 'color:#58a6ff;border-color:#1f6feb'

    parts = [f'''<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>M.A.R.K. Sentinel — MCP & Agent Governance {esc(tier_label)}</title>
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
</style>
<script>
function switchTier(t){{location.href='/api/fleet/mcp/report?tier='+t;}}
</script>
</head><body>
<div class="toolbar">
  <span style="font-size:13px;font-weight:600;color:#c9d1d9;margin-right:6px">M.A.R.K. Sentinel</span>
  <button onclick="switchTier('executive')" style="{btn_style}{';' + active_btn if tier=='executive' else ''}">Executive</button>
  <button onclick="switchTier('ciso')"      style="{btn_style}{';' + active_btn if tier=='ciso'      else ''}">CISO</button>
  <button onclick="switchTier('technical')" style="{btn_style}{';' + active_btn if tier=='technical' else ''}">Technical</button>
  <button onclick="window.print()" style="{btn_style}">&#128438; Print</button>
</div>
<h1>M.A.R.K. Sentinel &mdash; MCP &amp; Agent Governance &mdash; {esc(tier_label)}</h1>
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
        parts.append(f'<div class="risk-banner" style="background:#0f2a1a;border:1px solid #3fb950;color:#3fb950">'
                     f'&#10003;&nbsp; All MCP servers require authentication.</div>')

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
        parts.append('<h2>Remediation Priorities</h2><div class="block"><ol style="padding-left:20px;line-height:2;font-size:13px">')
        if no_auth:
            parts.append(f'<li><strong style="color:#f85149">IMMEDIATE:</strong> Add authentication to {len(no_auth)} unauthenticated server{"s" if len(no_auth)>1 else ""}: '
                         + ', '.join(f'{s.get("host","")}:{s.get("port",0)}' for s in no_auth[:5])
                         + ('…' if len(no_auth) > 5 else '') + '</li>')
        if unknown_auth:
            parts.append(f'<li><strong style="color:#d29922">SHORT-TERM:</strong> Manually verify authentication on {len(unknown_auth)} server{"s" if len(unknown_auth)>1 else ""} with unconfirmed status</li>')
        parts.append('<li>Establish an MCP server registry — assign an owner to each server</li>')
        parts.append('<li>Enable tool call logging on all MCP servers before the EU AI Act August 2026 deadline</li>')
        parts.append('<li>Review exposed tools — remove or restrict high-risk capabilities (code execution, email, database writes)</li>')
        parts.append('</ol></div>')
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

        parts.append(f'<div class="block">')
        parts.append(f'<h3>&#128279; {esc(loc)} &mdash; {esc(server_name)}</h3>')
        parts.append(f'<table style="margin-bottom:12px"><tbody>')
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
                parts.append(f'<div style="background:#2d0f0f;border:1px solid #f85149;border-radius:4px;padding:8px 12px;font-size:12px;margin-bottom:10px;color:#f85149">'
                             f'&#9888; High-risk tools accessible with no auth: '
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


def _build_fleet_report_html(devices: list, tier: str, profile: str = '', profiles: list | None = None, status_filter: str = '') -> str:
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
    _tier_base    = {'executive': 'Executive Summary', 'ciso': 'CISO Report', 'technical': 'Technical Findings'}.get(tier, 'Fleet Report')
    tier_label    = f'{_tier_base} — {_status_label}' if _status_label else _tier_base
    total_fail = sum(d.get('fail_count', 0) or 0 for d in devices)
    total_warn = sum(d.get('warn_count', 0) or 0 for d in devices)
    total_pass = sum(d.get('pass_count', 0) or 0 for d in devices)
    total_checks = total_fail + total_warn + total_pass
    fleet_score = _risk_score_html(total_fail, total_warn, total_checks)
    score_color = '#3fb950' if fleet_score >= 80 else '#d29922' if fleet_score >= 60 else '#f85149'
    now = datetime.now(tz=timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
    active_profiles = profiles or ([profile] if profile else [])

    _rpt_profiles = [('default', 'Default'), ('fedramp', 'FedRAMP'), ('cmmc', 'CMMC 2.0'),
                     ('financial', 'Financial'), ('smb', 'SMB'), ('biotech', 'Biotech'), ('healthcare', 'Healthcare')]
    _toolbar_cbs = ' '.join(
        f'<label style="font-size:12px;color:#c9d1d9;white-space:nowrap;cursor:pointer">'
        f'<input type="checkbox" class="rpt-cb" value="{v}"{" checked" if v in active_profiles else ""}> {lbl}</label>'
        for v, lbl in _rpt_profiles
    )
    _pdf_profile_param = ('&profile=' + ','.join(active_profiles)) if active_profiles else ''
    _pdf_fname_suffix  = ('_' + '_'.join(active_profiles)) if active_profiles else ''
    _profile_label     = ', '.join(p.upper() for p in active_profiles) if active_profiles else ''

    btn_style = 'display:inline-block;padding:6px 14px;border-radius:6px;font-size:12px;font-weight:600;text-decoration:none;cursor:pointer;border:1px solid #30363d;background:#21262d;color:#c9d1d9'
    parts = [f'''<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>M.A.R.K. Sentinel — Fleet {esc(tier_label)}</title>
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
</style>
<script>
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
</head><body>
<div class="toolbar">
  <span style="font-size:13px;font-weight:600;color:#c9d1d9;margin-right:6px">M.A.R.K. Sentinel</span>
  <button onclick="switchTier('executive')" style="{btn_style}{'color:#58a6ff;border-color:#1f6feb' if tier=='executive' else ''}">Executive</button>
  <button onclick="switchTier('ciso')"      style="{btn_style}{'color:#58a6ff;border-color:#1f6feb' if tier=='ciso' else ''}">CISO</button>
  <button onclick="switchTier('technical')" style="{btn_style}{'color:#58a6ff;border-color:#1f6feb' if tier=='technical' else ''}">Technical</button>
  <span style="font-size:11px;color:#8b949e;white-space:nowrap;margin-left:6px">Profiles:</span>
  {_toolbar_cbs}
  <button onclick="applyProfiles()" style="{btn_style};color:#58a6ff;border-color:#1f6feb">Apply</button>
  <a href="/api/fleet/report?tier={tier}&fmt=pdf{_pdf_profile_param}{'&status=' + status_filter if status_filter else ''}" download="sentinel_fleet_{tier}{_pdf_fname_suffix}.pdf" style="{btn_style};color:#3fb950;border-color:#238636">&#8659; Download PDF</a>
  <button onclick="window.print()" style="{btn_style}">&#128438; Print</button>
  {'<a href="/api/fleet/report?tier=' + tier + '&fmt=html' + _pdf_profile_param + '" style="' + btn_style + ';color:#f85149;border-color:#30363d">&#10005; Clear filter</a>' if status_filter else ''}
</div>
{'<div style="background:#1c2128;border:1px solid #30363d;border-radius:6px;padding:10px 18px;margin-bottom:20px;display:flex;align-items:center;justify-content:space-between"><span style="font-size:13px;font-weight:600;color:' + ('#f85149' if status_filter=='fail' else '#d29922' if status_filter=='warn' else '#58a6ff') + '">Showing: ' + esc(_status_label) + ' only — across all devices</span></div>' if status_filter else ''}
<h1>M.A.R.K. Sentinel &mdash; Fleet {esc(tier_label)}</h1>
<div class="meta">Generated {esc(now)} &nbsp;&bull;&nbsp; {len(devices)} device(s){(' &nbsp;&bull;&nbsp; Profiles: <strong>' + esc(_profile_label) + '</strong>') if _profile_label else ''} &nbsp;&bull;&nbsp; Confidential</div>
<div class="cards">
  <div class="card"><div class="card-n score">{fleet_score}%</div><div class="card-l">Fleet Score</div></div>
  <div class="card"><div class="card-n fail">{total_fail}</div><div class="card-l">High Risk</div></div>
  <div class="card"><div class="card-n warn">{total_warn}</div><div class="card-l">Medium Risk</div></div>
  <div class="card"><div class="card-n pass">{total_pass}</div><div class="card-l">Info</div></div>
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

    _section_label = {'fail': 'High Risk', 'warn': 'Medium Risk', 'pass': 'Info'}.get(status_filter, 'Critical &amp; High')
    if status_filter:
        crit_high = sorted(all_findings, key=lambda x: _SEV_ORDER_REPORT.index(x.get('severity','INFO')) if x.get('severity') in _SEV_ORDER_REPORT else 99)
    else:
        crit_high = [f for f in all_findings if f.get('status') == 'FAIL' and f.get('severity') in ('CRITICAL', 'HIGH')]
        crit_high.sort(key=lambda x: _SEV_ORDER_REPORT.index(x.get('severity', 'INFO')) if x.get('severity') in _SEV_ORDER_REPORT else 99)

    parts.append(f'<h2>{_section_label} Findings ({len(crit_high)})</h2>')
    if not crit_high:
        _empty_msg = f'No {_status_label.lower()} found across the fleet.' if status_filter else 'No critical or high severity issues found across the fleet.'
        parts.append(f'<p style="color:#3fb950;padding:12px 0">{esc(_empty_msg)}</p>')
    else:
        limit = 20 if tier == 'executive' else len(crit_high)
        parts.append('<table><thead><tr><th>Severity</th><th>Device</th><th>Check</th><th>Finding</th></tr></thead><tbody>')
        for f in crit_high[:limit]:
            sev = f.get('severity', 'INFO')
            sc = _SEV_COLOR_HTML.get(sev, '#6e7681')
            parts.append(f'<tr><td style="color:{sc};font-weight:700">{esc(sev)}</td>'
                         f'<td style="color:#8b949e">{esc(f.get("_hostname",""))}</td>'
                         f'<td style="color:#8b949e;font-size:12px">{esc(f.get("check_id",""))}</td>'
                         f'<td>{esc(f.get("title",""))}</td></tr>')
        parts.append('</tbody></table>')

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
        elif tier == 'technical':
            show = results
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
            parts.append(f'<div class="finding">'
                         f'<span style="color:{sc2};font-weight:700">[{esc(_STATUS_LABEL_HTML.get(st, st))}]</span> '
                         f'<span style="color:{sv2}">[{esc(sev)}]</span> '
                         f'<strong>{esc(r.get("title",""))}</strong>')
            if tier == 'technical' and r.get('details'):
                parts.append(f'<div class="det">{esc(r["details"][:300])}</div>')
            if tier == 'technical' and r.get('remediation'):
                parts.append(f'<div class="rem">Fix: {esc(r["remediation"][:250])}</div>')
            parts.append('</div>')
        parts.append('</div>')

    parts.append('</body></html>')
    return ''.join(parts)


def _run_scan(mode: str, target: str, profile: str, providers: list[str]):
    global _status, _log
    with _lock:
        _status = 'running'
        _log = []

    def emit(line: str):
        with _lock:
            _log.append(line)

    try:
        if mode == 'demo':
            cmd = [sys.executable, str(ROOT / 'scripts' / 'demo.py'), '--target', target]
            if profile and profile != 'default':
                cmd += ['--profile', profile]
        else:
            provider = providers[0] if providers else 'config'
            db_path = str(ROOT / 'output' / 'agents.db')
            cmd = [sys.executable, str(ROOT / 'audit.py'),
                   '--target', target,
                   '--mode', provider, '--profile', profile, '--output', 'json',
                   '--store-db', db_path]

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


class _Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_): pass

    def handle_error(self, *_):
        import traceback as _tb
        log.error('HTTP handler thread error: %s', _tb.format_exc())

    # ── auth helpers ──────────────────────────────────────────────────────────

    def _check_dashboard_auth(self) -> bool:
        import hmac as _hmac
        token = _dashboard_token()
        if not token:
            return True
        for part in self.headers.get('Cookie', '').split(';'):
            k, _, v = part.strip().partition('=')
            if k.strip() == 'sentinel_session' and _hmac.compare_digest(v.strip(), token):
                return True
        return False

    def _require_dashboard_auth(self) -> bool:
        if self._check_dashboard_auth():
            return True
        if self.command == 'POST':
            self._send(401, b'Unauthorized - set SENTINEL_DASHBOARD_TOKEN', 'text/plain')
        else:
            from urllib.parse import quote
            self.send_response(302)
            self.send_header('Location', f'/login?next={quote(urlparse(self.path).path)}')
            self.end_headers()
        return False

    def _check_agent_bearer(self) -> bool:
        if not _agent_token() and not (ROOT / 'output' / 'agent_tokens.json').exists():
            return True  # no auth configured
        submitted = self.headers.get('Authorization', '')
        if submitted.startswith('Bearer '):
            submitted = submitted[len('Bearer '):]
        return _check_agent_token(submitted)

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

        # Auth-exempt: health probe and login UI
        if path == '/health':
            self._api_health()
            return
        if path == '/login':
            self._serve_login()
            return
        if path == '/logout':
            self._handle_logout()
            return

        # Agent-token-gated: agents download these during self-update
        if path in ('/agent.py', '/bundle.tar.gz'):
            if not self._check_agent_bearer():
                self._send(401, b'Unauthorized', 'text/plain')
                return
            if path == '/agent.py':
                self._serve_agent_script()
            else:
                self._serve_bundle()
            return

        # Agent-token-gated: command polling (has its own internal check too)
        if path.startswith('/api/agent/commands/'):
            self._api_agent_commands(path[len('/api/agent/commands/'):])
            return

        # All remaining GET endpoints require dashboard auth
        if not self._require_dashboard_auth():
            return

        static = {
            '/':               self._serve_fleet,
            '/dashboard':      self._serve_dashboard,
            '/dashboard.html': self._serve_dashboard,
            '/api/status':     self._api_status,
            '/api/events':     self._api_events,
            '/api/devices':    self._api_devices,
            '/api/discover':   self._api_discover,
            '/fleet':          lambda: self._redirect('/'),
            '/academy':        self._serve_academy,
            '/probe':          self._serve_probe_tester,
            '/command':        lambda: self._redirect('/'),
            '/api/config':        self._api_get_config,
            '/api/fleet/shadow':  self._api_fleet_shadow,
            '/api/fleet/mcp':        self._api_fleet_mcp,
            '/api/fleet/mcp/report': self._api_fleet_mcp_report,
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

        # Login form submission — no auth needed
        if path == '/login':
            self._handle_login_post()
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

        # All other POST endpoints require dashboard auth
        if not self._require_dashboard_auth():
            return

        if path == '/api/scan':
            self._api_scan()
        elif path == '/api/config':
            self._api_set_config()
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
        elif path.startswith('/api/fleet/update/'):
            self._api_fleet_update(path[len('/api/fleet/update/'):])
        elif path.startswith('/api/fleet/remove/'):
            self._api_fleet_remove(path[len('/api/fleet/remove/'):])
        elif path == '/api/admin/license':
            self._api_admin_license()
        elif path == '/api/probe-scan':
            self._api_probe_scan()
        elif path == '/probe':
            self._probe_run()
        elif path == '/api/fleet/discover/all':
            self._api_fleet_discover_all()
        elif path.startswith('/api/fleet/discover/'):
            self._api_fleet_discover(path[len('/api/fleet/discover/'):])
        elif path.startswith('/api/fleet/shadow/dismiss/'):
            self._api_fleet_shadow_dismiss(path[len('/api/fleet/shadow/dismiss/'):])
        elif path == '/api/fleet/mcp/discover/all':
            self._api_fleet_mcp_discover_all()
        elif path.startswith('/api/fleet/mcp/dismiss/'):
            self._api_fleet_mcp_dismiss(path[len('/api/fleet/mcp/dismiss/'):])
        else:
            self._not_found()

    def do_OPTIONS(self):
        self._send(200, b'', 'text/plain')

    # ── login / logout ────────────────────────────────────────────────────────

    def _serve_login(self):
        import html as _html
        from urllib.parse import parse_qs
        qs = parse_qs(urlparse(self.path).query)
        next_url = qs.get('next', ['/'])[0]
        if not next_url.startswith('/') or '//' in next_url:
            next_url = '/'
        safe_next = _html.escape(next_url, quote=True)
        error = bool(qs.get('error'))
        err_html = '<p style="color:#f85149;font-size:13px;margin:0 0 14px">Incorrect token.</p>' if error else ''
        body = f"""<!doctype html><html><head><meta charset="utf-8">
<title>M.A.R.K. Sentinel — Sign in</title>
<style>body{{font-family:system-ui;background:#0d1117;color:#8b949e;
display:flex;align-items:center;justify-content:center;height:100vh;margin:0}}
.box{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:40px 36px;width:320px}}
h2{{color:#e6edf3;font-size:18px;margin:0 0 24px}}
input{{width:100%;box-sizing:border-box;background:#0d1117;border:1px solid #30363d;
border-radius:6px;color:#e6edf3;padding:10px 12px;font-size:14px;margin-bottom:16px}}
button{{width:100%;background:#238636;color:#fff;border:none;border-radius:6px;
padding:10px;font-size:14px;cursor:pointer;font-weight:600}}
button:hover{{background:#2ea043}}
.brand{{color:#58a6ff;font-size:12px;text-align:center;margin-top:20px}}</style>
</head><body><div class="box">
<h2>M.A.R.K. Sentinel</h2>{err_html}
<form method="POST" action="/login">
<input type="hidden" name="next" value="{safe_next}">
<input type="password" name="token" placeholder="Dashboard token" autofocus>
<button type="submit">Sign in</button>
</form>
<div class="brand">Powered by Hash</div>
</div></body></html>""".encode()
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
        params = parse_qs(self.rfile.read(length).decode(errors='ignore'))
        submitted = params.get('token', [''])[0]
        next_url = params.get('next', ['/'])[0]
        if not next_url.startswith('/') or '//' in next_url:
            next_url = '/'
        import hmac as _hmac
        expected = _dashboard_token()
        if expected and _hmac.compare_digest(submitted, expected):
            self.send_response(302)
            self.send_header('Set-Cookie',
                f'sentinel_session={expected}; Path=/; HttpOnly; SameSite=Strict')
            self.send_header('Location', next_url)
            self.end_headers()
        else:
            self.send_response(302)
            self.send_header('Location', f'/login?next={quote(next_url)}&error=1')
            self.end_headers()

    def _handle_logout(self):
        self.send_response(302)
        self.send_header('Set-Cookie',
            'sentinel_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0')
        self.send_header('Location', '/login')
        self.end_headers()

    # ── endpoints ─────────────────────────────────────────────────────────────

    def _serve_dashboard(self):
        out_dir = _latest_out_dir()
        dash = (out_dir / 'dashboard.html') if out_dir else None
        if dash and dash.exists():
            try:
                html = dash.read_text(encoding='utf-8')
                idx = html.lower().find('<body')
                if idx != -1:
                    idx2 = html.find('>', idx)
                    if idx2 != -1:
                        link = (
                            '\n<div style="position:fixed;left:50%;top:14px;'
                            'transform:translateX(-50%);z-index:999;'>
                            '<a href="/" style="background:#161b22;color:#58a6ff;'
                            'padding:6px 10px;border-radius:6px;border:1px solid #21262d;'
                            'text-decoration:none;font-size:13px">Command Center</a> '
                            '<a href="/academy" target="_blank" style="background:#161b22;color:#58a6ff;'
                            'padding:6px 10px;border-radius:6px;border:1px solid #21262d;'
                            'text-decoration:none;font-size:13px;margin-left:8px">Academy</a></div>\n'
                        )
                        html = html[:idx2+1] + link + html[idx2+1:]
                self._send(200, html.encode('utf-8'), 'text/html; charset=utf-8')
                return
            except Exception:
                self._send(200, dash.read_bytes(), 'text/html; charset=utf-8')
        else:
            page = (
                b'<html><head><style>'
                b'body{font:14px sans-serif;background:#0d1117;color:#c9d1d9;padding:48px}'
                b'code{background:#161b22;padding:4px 10px;border-radius:4px;color:#58a6ff}'
                b'</style></head><body>'
                b'<h2>No scan results found.</h2>'
                b'<p>Run a scan first, then reload:</p>'
                b'<p><code>python3 scripts/demo.py .</code></p>'
                b'</body></html>'
            )
            self._send(200, page, 'text/html; charset=utf-8')

    def _api_status(self):
        with _lock:
            self._json({'status': _status, 'lines': len(_log)})

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

    def _serve_agent_script(self):
        """GET /agent.py — serve the fleet agent script for easy remote installation."""
        agent_file = ROOT / 'agent.py'
        if not agent_file.exists():
            self._not_found()
            return
        self._send(200, agent_file.read_bytes(), 'text/x-python; charset=utf-8')

    def _serve_bundle(self):
        """GET /bundle.tar.gz — serve a minimal Sentinel bundle for remote agents.
        Includes everything needed to run agent.py + audit.py on a remote machine.
        Excludes: output/, benchmarks/, docs/, test/, .git, __pycache__, *.db, *.log.
        """
        _SKIP_DIRS  = {'benchmarks', 'docs', 'test', '.git', '__pycache__',
                       '.sentinel_db', 'node_modules'}
        _SKIP_EXTS  = {'.db', '.log', '.pyc', '.egg-info'}
        _SKIP_FILES = {'agent_token.txt'}

        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode='w:gz') as tar:
            for path in sorted(ROOT.rglob('*')):
                if not path.is_file():
                    continue
                rel = path.relative_to(ROOT)
                parts = rel.parts
                if any(p in _SKIP_DIRS for p in parts):
                    continue
                if path.suffix in _SKIP_EXTS:
                    continue
                if path.name in _SKIP_FILES:
                    continue
                # From output/ only ship the Python modules, not scan result dirs
                if parts[0] == 'output' and (len(parts) > 2 or path.suffix != '.py'):
                    continue
                tar.add(path, arcname=str(Path('sentinel') / rel))
        data = buf.getvalue()
        import hashlib as _hashlib
        bundle_sha256 = _hashlib.sha256(data).hexdigest()
        self.send_response(200)
        self.send_header('Content-Type', 'application/gzip')
        self.send_header('Content-Disposition', 'attachment; filename="sentinel.tar.gz"')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('X-Bundle-SHA256', bundle_sha256)
        self.end_headers()
        self.wfile.write(data)

    def _serve_device_dashboard(self, device_id: str):
        """GET /fleet/device/<id>/dashboard — full single-device dashboard with all views."""
        if not device_id:
            self._not_found()
            return
        try:
            report = _get_store().get_latest_report(device_id)
        except Exception as e:
            log.error('get_latest_report error for %s: %s', device_id, e)
            self._send(500, f'Store error: {e}'.encode(), 'text/plain')
            return
        if report is None:
            try:
                device = _get_store().get_device(device_id)
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
            report = _get_store().get_latest_report(device_id)
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
        mode = body.get('mode', 'demo')
        if mode not in ('demo', 'config', 'api', 'local', 'gemini', 'vertex', 'anthropic', 'hash'):
            mode = 'demo'
        profile = body.get('profile', 'default')
        if not profile.replace('-', '').replace('_', '').isalnum():
            profile = 'default'
        threading.Thread(
            target=_run_scan,
            args=(mode, safe_target, profile, body.get('providers', [])),
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

        store = _get_store()
        is_new = not store.is_known_device(device_id)

        # Duplicate hostname detection — warn when a new device_id uses an existing hostname
        duplicate_warning = None
        if is_new:
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

        try:
            store.upsert_report(
                device_id=device_id,
                hostname=hostname,
                report=report,
                platform=body.get('platform', ''),
                agent_version=body.get('agent_version', ''),
                ip_address=self.client_address[0],
            )
        except Exception as e:
            log.error('agent store error: %s', e)
            self._send(500, b'Storage error', 'text/plain')
            return

        try:
            from alerts import load_alert_config, fire_alerts
            alert_cfg = load_alert_config(ROOT / 'alerts_config.json')
            if alert_cfg:
                threading.Thread(
                    target=fire_alerts,
                    args=(report, device_id, hostname, alert_cfg),
                    daemon=True,
                ).start()
        except Exception as _ae:
            log.error('alerts error: %s', _ae)

        resp = {'status': 'accepted', 'device_id': device_id, 'license_status': license_status}
        if duplicate_warning:
            resp['warning'] = duplicate_warning
        self._json(resp)

    def _api_agent_commands(self, device_id: str):
        """GET /api/agent/commands/<device_id> — agent polls for pending commands."""
        if not device_id:
            self._json({'command': None})
            return
        expected = _agent_token()
        if expected:
            auth = self.headers.get('Authorization', '')
            if auth != f'Bearer {expected}':
                self._send(401, b'Unauthorized', 'text/plain')
                return
        command = _get_store().claim_command(device_id)
        self._json({'command': command})

    def _api_fleet_scan(self, device_id: str):
        """POST /api/fleet/scan/<device_id> — enqueue one or more profile scans for a device.
        Body (optional): {"profiles": ["fedramp", "cmmc"]}
        If profiles is absent or empty, falls back to scan_now (uses agent's saved profile).
        """
        if not device_id:
            self._json({'error': 'missing device_id'}, 400)
            return
        store = _get_store()
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
        _VALID = {'default', 'fedramp', 'cmmc', 'financial', 'smb'}
        profiles = [p for p in profiles if p in _VALID]

        if profiles:
            cmd_ids = [store.enqueue_command(device_id, f'scan_profile:{p}') for p in profiles]
            self._json({'status': 'queued', 'device_id': device_id,
                        'profiles': profiles, 'command_ids': cmd_ids})
        else:
            cmd_id = store.enqueue_command(device_id, 'scan_now')
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

        _VALID = {'default', 'fedramp', 'cmmc', 'financial', 'smb'}
        profiles = [p for p in (body.get('profiles') or []) if p in _VALID]
        stagger  = body.get('stagger', 'normal')

        PRESETS = {
            'instant': (9999, 0),
            'normal':  (25,   30),
            'slow':    (10,   60),
        }
        batch_size, sleep_secs = PRESETS.get(stagger, PRESETS['normal'])

        store   = _get_store()
        devices = store.list_devices()
        ids     = [d['device_id'] for d in devices if d.get('device_id')]
        total   = len(ids)

        def _dispatch():
            for i in range(0, total, batch_size):
                batch = ids[i:i + batch_size]
                for did in batch:
                    if profiles:
                        for p in profiles:
                            store.enqueue_command(did, f'scan_profile:{p}')
                    else:
                        store.enqueue_command(did, 'scan_now')
                if sleep_secs and i + batch_size < total:
                    time.sleep(sleep_secs)

        threading.Thread(target=_dispatch, daemon=True, name='scan-all-dispatch').start()
        self._json({'status': 'dispatching', 'total': total,
                    'profiles': profiles or ['default'], 'stagger': stagger,
                    'batch_size': batch_size, 'sleep_secs': sleep_secs})

    def _api_fleet_update(self, device_id: str):
        """POST /api/fleet/update/<device_id> — push update_self command to one device."""
        if not device_id:
            self._json({'error': 'missing device_id'}, 400)
            return
        store = _get_store()
        if store.get_device(device_id) is None:
            self._json({'error': 'device not found'}, 404)
            return
        cmd_id = store.enqueue_command(device_id, 'update_self')
        self._json({'status': 'queued', 'device_id': device_id, 'command_id': cmd_id})

    def _api_fleet_update_all(self):
        """POST /api/fleet/update/all — push update_self command to every known device."""
        store = _get_store()
        devices = store.list_devices()
        queued = []
        for d in devices:
            did = d.get('device_id', '')
            if did:
                store.enqueue_command(did, 'update_self')
                queued.append(did)
        self._json({'status': 'queued', 'count': len(queued), 'devices': queued})

    def _api_fleet_remove(self, device_id: str):
        """POST /api/fleet/remove/<id> — permanently delete a device and its history."""
        device_id = device_id.strip()
        if not device_id:
            self._json({'error': 'missing device_id'}, 400)
            return
        found = _get_store().delete_device(device_id)
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

        store = _get_store()
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
            store.upsert_shadow_device(
                device_id, reporter_host, host, int(port), service, models, source, detail
            )
            stored += 1

        log.info('agent discovery: %s reported %d unmanaged AI services', device_id, stored)
        self._json({'status': 'accepted', 'stored': stored})

    def _api_fleet_discover_all(self):
        """POST /api/fleet/discover/all — push discover_network command to every agent."""
        store = _get_store()
        devices = store.list_devices()
        queued = []
        for d in devices:
            did = d.get('device_id', '')
            if did:
                store.enqueue_command(did, 'discover_network')
                queued.append(did)
        self._json({'status': 'queued', 'count': len(queued), 'devices': queued})

    def _api_fleet_discover(self, device_id: str):
        """POST /api/fleet/discover/<device_id> — push discover_network to one agent."""
        device_id = device_id.strip()
        if not device_id:
            self._json({'error': 'missing device_id'}, 400)
            return
        store = _get_store()
        if store.get_device(device_id) is None:
            self._json({'error': 'device not found'}, 404)
            return
        store.enqueue_command(device_id, 'discover_network')
        self._json({'status': 'queued', 'device_id': device_id})

    def _api_fleet_shadow(self):
        """GET /api/fleet/shadow — list discovered unmanaged AI devices."""
        try:
            shadow = _get_store().list_shadow_devices()
            self._json({'devices': shadow, 'count': len(shadow)})
        except Exception as e:
            self._json({'error': str(e)}, 500)

    def _api_fleet_shadow_dismiss(self, shadow_id_str: str):
        """POST /api/fleet/shadow/dismiss/<id|all> — dismiss one or all shadow findings."""
        if shadow_id_str.strip() == 'all':
            count = _get_store().dismiss_all_shadow_devices()
            self._json({'status': 'dismissed', 'count': count})
            return
        try:
            shadow_id = int(shadow_id_str.strip())
        except ValueError:
            self._json({'error': 'invalid id'}, 400)
            return
        found = _get_store().dismiss_shadow_device(shadow_id)
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
        store   = _get_store()
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
            servers = _get_store().list_mcp_servers()
            self._json({'servers': servers, 'count': len(servers)})
        except Exception as e:
            self._json({'error': str(e)}, 500)

    def _api_fleet_mcp_discover_all(self):
        """POST /api/fleet/mcp/discover/all — push discover_mcp to every agent."""
        store   = _get_store()
        devices = store.list_devices()
        queued  = []
        for d in devices:
            did = d.get('device_id', '')
            if did:
                store.enqueue_command(did, 'discover_mcp')
                queued.append(did)
        self._json({'status': 'queued', 'count': len(queued), 'devices': queued})

    def _api_fleet_mcp_dismiss(self, mcp_id_str: str):
        """POST /api/fleet/mcp/dismiss/<id|all> — dismiss one or all MCP findings."""
        if mcp_id_str.strip() == 'all':
            count = _get_store().dismiss_all_mcp_servers()
            self._json({'status': 'dismissed', 'count': count})
            return
        try:
            mcp_id = int(mcp_id_str.strip())
        except ValueError:
            self._json({'error': 'invalid id'}, 400)
            return
        found = _get_store().dismiss_mcp_server(mcp_id)
        self._json({'status': 'dismissed' if found else 'not_found'})

    def _api_fleet_mcp_report(self):
        """GET /api/fleet/mcp/report?tier=executive|ciso|technical"""
        from urllib.parse import parse_qs, urlparse as _up
        qs   = parse_qs(_up(self.path).query)
        tier = (qs.get('tier', ['ciso'])[0]).lower()
        if tier not in ('executive', 'ciso', 'technical'):
            tier = 'ciso'
        servers = _get_store().list_mcp_servers()
        html    = _build_mcp_report_html(servers, tier)
        body    = html.encode('utf-8')
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _api_admin_license(self):
        """GET /api/admin/license — license status + overage audit log."""
        try:
            from license import license_summary
            summary = license_summary(_get_store())
            self._json(summary)
        except Exception as e:
            self._json({'error': str(e)}, 500)

    def _api_fleet_report(self):
        """GET /api/fleet/report?tier=executive|ciso|technical&fmt=pdf|html|json[&profile=fedramp,cmmc][&status=fail|warn|pass]"""
        from urllib.parse import parse_qs, urlparse as _up
        qs = parse_qs(_up(self.path).query)
        tier          = (qs.get('tier',    ['ciso'])[0]).lower()
        fmt           = (qs.get('fmt',     ['html'])[0]).lower()
        profile_raw   = (qs.get('profile', [''])[0]).lower().strip()
        status_filter = (qs.get('status',  [''])[0]).lower().strip()
        if tier not in ('executive', 'ciso', 'technical'):
            tier = 'ciso'
        if status_filter not in ('fail', 'warn', 'pass', ''):
            status_filter = ''
        _VALID_PROFILES = {'default', 'fedramp', 'cmmc', 'financial', 'smb', 'biotech', 'healthcare', 'lifesciences', 'owasp_agentic', 'eu_ai_act'}
        profiles = [p for p in profile_raw.split(',') if p in _VALID_PROFILES]
        profile  = ','.join(profiles)
        try:
            store = _get_store()
            if profiles:
                devices = store.list_devices_by_profile(profiles)
            else:
                devices = store.list_devices()
                for d in devices:
                    d['_report'] = store.get_latest_report(d['device_id']) or {}

            if fmt == 'json':
                payload = [{'device_id': d['device_id'], 'hostname': d['hostname'],
                            'platform': d.get('platform', ''), 'fail_count': d.get('fail_count', 0),
                            'warn_count': d.get('warn_count', 0), 'pass_count': d.get('pass_count', 0),
                            'last_seen': d.get('last_seen'), 'results': d['_report'].get('findings', d['_report'].get('results', []))}
                           for d in devices]
                self._json({'tier': tier, 'devices': payload})
                return

            if fmt == 'pdf':
                try:
                    from output.fleet_report import generate_fleet_pdf
                    pdf_bytes = generate_fleet_pdf(devices, tier=tier, profile=profile or None)
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

            html = _build_fleet_report_html(devices, tier, profile=profile, profiles=profiles, status_filter=status_filter)
            data = html.encode('utf-8')
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; img-src data:")
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:
            log.error('fleet report error: %s', e)
            self._json({'error': str(e)}, 500)

    def _api_discover(self):
        """GET /api/discover[?subnets=10.0.1.0/24,10.0.2.0/24] — scan for AI services."""
        try:
            from urllib.parse import urlparse, parse_qs
            from discovery import discover, expand_subnets
            qs = parse_qs(urlparse(self.path).query)
            raw = qs.get('subnets', [''])[0].strip()
            hosts = expand_subnets(raw) if raw else None
            services = discover(hosts=hosts)
            self._json({'services': services, 'count': len(services)})
        except Exception as e:
            log.error('discovery error: %s', e, exc_info=True)
            self._json({'error': str(e), 'services': []}, 500)

    def _api_devices(self):
        try:
            devices = _get_store().list_devices()
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
            report = _get_store().get_latest_report(device_id)
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
            points = _get_store().get_device_timeseries(device_id)
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
                store = _get_store()
                cmd_payload = json.dumps({k: clean[k] for k in _push_keys if k in clean})
                for d in store.list_devices():
                    did = d.get('device_id', '')
                    if did:
                        store.enqueue_command(did, f'set_config:{cmd_payload}')
                        pushed += 1
            except Exception:
                pass

        self._json({'status': 'saved', 'pushed_to_agents': pushed})

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

    def _serve_fleet(self):
        print('[SENTINEL] _serve_fleet: start', flush=True)
        try:
            store = _get_store()
            devices = store.list_devices()
            shadow  = store.list_shadow_devices()
            mcp     = store.list_mcp_servers()
            print(f'[SENTINEL] _serve_fleet: got {len(devices)} devices, {len(shadow)} shadow, {len(mcp)} mcp', flush=True)
        except Exception as _e:
            print(f'[SENTINEL] _serve_fleet: store error: {_e}', flush=True)
            log.error('_serve_fleet: store error: %s', _e, exc_info=True)
            devices = []
            shadow  = []
            mcp     = []
        try:
            body = _build_fleet_html(devices, shadow, mcp).encode('utf-8')
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
            print(f'[SENTINEL] _serve_fleet: sent OK', flush=True)
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

        if not api_key:
            self._json({'error': 'api_key is required'}, 400)
            return
        if provider not in ('openai', 'anthropic', 'gemini'):
            self._json({'error': 'unknown provider'}, 400)
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
                mdl = model or 'gpt-4o'
                log.info('probe-scan connecting to %s model=%s', ep, mdl)
                ctx = connect(ep, api_key, mdl, str(ROOT))
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

        if not api_key:
            self._serve_probe_tester(error='Please enter an API key.')
            return
        if provider not in ('openai', 'anthropic', 'gemini'):
            self._serve_probe_tester(error='Unknown provider.')
            return

        log.info('probe-run start: provider=%s endpoint=%s', provider, endpoint or '(default)')
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
                ep  = endpoint or 'https://api.openai.com/v1'
                mdl = model or 'gpt-4o'
                ctx = connect(ep, api_key, mdl, str(ROOT))
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
<title>M.A.R.K. Sentinel - Probe Results</title>
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
  <span class="brand-mark">M.A.R.K.</span>
  <span class="brand-name">SENTINEL</span>
  <span class="brand-sub">Probe Results</span>
  <a class="back" href="/probe">Run Another Test</a>
</div>
<div class="print-date">M.A.R.K. Sentinel &#8212; AI API Security Report &nbsp;|&nbsp; {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M')}</div>
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
            b'<title>M.A.R.K. Sentinel - API Security Tester</title>'
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
            b'select,input{width:100%;background:#0d1117;border:1px solid #30363d;border-radius:6px;color:#e6edf3;font-size:14px;padding:9px 12px;outline:none}'
            b'select:focus,input:focus{border-color:#58a6ff}'
            b'.field{margin-bottom:18px}'
            b'.row{display:grid;grid-template-columns:1fr 1fr;gap:16px}'
            b'.hint{font-size:11px;color:#6e7681;margin-top:4px}'
            b'.btn{background:#238636;border:none;border-radius:6px;color:#fff;cursor:pointer;font-size:14px;font-weight:600;padding:10px 22px}'
            b'.btn:hover{background:#2ea043}'
            b'#ep-field{display:block}'
            b'#wait{display:none;color:#8b949e;font-size:13px;margin-top:16px}'
            b'</style></head><body>'
            b'<div class="wrap">'
            b'<div class="bar"><span class="bm">M.A.R.K.</span><span class="bn">SENTINEL</span>'
            b'<span class="bs">API Security Tester</span></div>'
            b'<h1>AI API Security Tester</h1>'
            b'<p class="sub">Enter your API credentials to run live adversarial probes against your AI endpoint.<br>'
            b'Tests: prompt injection, jailbreaks, PII leakage, system prompt disclosure, harmful content refusals.<br>'
            b'Your key is sent only to your endpoint and never stored by Sentinel.</p>'
        ) + err_html.encode() + (
            b'<div class="card">'
            b'<form method="POST" action="/probe" onsubmit="document.getElementById(\'wait\').style.display=\'block\';document.querySelector(\'.btn\').disabled=true;">'
            b'<div class="field"><label>Provider</label>'
            b'<select name="provider" onchange="var s=this.value;document.getElementById(\'ep-field\').style.display=s===\'openai\'?\'block\':\'none\'">'
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
            b'<input type="text" name="model" placeholder="gpt-4o">'
            b'<div class="hint">Leave blank for provider default.</div></div>'
            b'</div>'
            b'<div class="field"><label>Does your AI system use document retrieval (RAG)?</label>'
            b'<select name="uses_rag">'
            b'<option value="">I\'m not sure</option>'
            b'<option value="no">No - it answers from its training data only</option>'
            b'<option value="yes">Yes - it retrieves documents, files, or a knowledge base</option>'
            b'</select>'
            b'<div class="hint">RAG = Retrieval-Augmented Generation. Used in chatbots that search a document library before responding.</div></div>'
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
                sub_html = (f'<span style="font-size:12px;color:#6e7681">{detail}</span>'
                            if detail else '')
            model_html = _model_tags(models) if models else (
                f'<span style="font-size:11px;color:#484f58">No model details available</span>'
            )
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
                f'<div style="text-align:right;flex-shrink:0">'
                f'<div style="font-size:11px;color:#484f58;margin-bottom:3px">Detected {age}</div>'
                f'<div style="font-size:11px;color:#6e7681;margin-bottom:8px">via {reporter}</div>'
                f'<button class="scan-btn" onclick="dismissShadow({sid})" '
                f'style="font-size:11px;color:#6e7681;border-color:#30363d">Dismiss</button>'
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
                    f'<span style="font-size:11px;color:#484f58">No model details available</span>'
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
        f'<button class="scan-btn" onclick="dismissAllShadow()" '
        f'style="font-size:11px;color:#6e7681;border-color:#30363d;margin-left:8px">'
        f'Dismiss All</button>'
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
                location_html = (f'<span style="font-weight:700;color:#e6edf3;font-size:14px">'
                                 f'MCP Server Process</span>')
                sub_html = (f'<span style="font-size:11px;color:#6e7681;font-family:monospace">'
                            f'{process_info[:80]}</span>') if process_info else ''
            else:
                display = server_name or f'MCP Server'
                location_html = (f'<span style="font-weight:700;color:#e6edf3;font-size:14px">'
                                 f'{host}:{port}</span>')
                sub_html = (f'<span style="font-size:12px;color:#58a6ff">{display}</span>')

            tool_html = _tool_tags(tools) if tools else (
                f'<span style="font-size:11px;color:#484f58">No tools enumerated</span>'
            )

            risk_note = ''
            if auth_status == 'none':
                risk_note = (f'<div style="font-size:11px;color:#f85149;margin-top:4px;font-weight:600">'
                             f'&#9888; Unauthenticated — any AI agent can connect to this server</div>')

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
        f'<button class="scan-btn" onclick="dismissAllMcp()" '
        f'style="font-size:11px;color:#6e7681;border-color:#30363d;margin-left:8px">'
        f'Dismiss All</button>'
    ) if servers else ''

    return (f'<div id="mcp-section" style="margin-top:32px">'
            f'<div class="sec-hdr" style="display:flex;align-items:center;justify-content:space-between">'
            f'<span style="display:flex;align-items:center">MCP &amp; Agent Governance{badge}{risk_badge}{dismiss_all_btn}</span>'
            f'<span style="font-size:11px;color:#6e7681;font-weight:400;text-transform:none;letter-spacing:0">'
            f'&#128279; MCP server discovered on network &nbsp;|&nbsp; &#9881; Running as local process'
            f'</span></div>'
            f'<div id="mcp-cards" style="margin-bottom:28px">{cards}</div>'
            f'</div>')


def _build_fleet_html(devices: list[dict], shadow: list[dict] | None = None,
                      mcp: list[dict] | None = None) -> str:
    shadow = shadow or []
    mcp    = mcp    or []
    ts_now = int(time.time())

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

    def _risk_cls(fail: int, warn: int) -> str:
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
        rc   = _risk_cls(fail, warn)
        did  = d.get('device_id', '')
        rows += f"""
        <tr class="dev-row" onclick="selectDevice('{did}')">
          <td class="dev-host">{d.get('hostname','unknown')}</td>
          <td>{d.get('platform','')}</td>
          <td class="c-red">{fail}</td>
          <td class="c-yellow">{warn}</td>
          <td class="c-green">{pas}</td>
          <td>{d.get('profile','')}</td>
          <td>{age}</td>
          <td><span class="risk-dot {rc}"></span></td>
          <td onclick="event.stopPropagation()" style="white-space:nowrap">
            <button class="scan-btn" id="sb-{did}" onclick="openScanModal('{did}',this)">Scan ▾</button>
            <button class="scan-btn" id="ub-{did}" onclick="updateDevice('{did}')"
                    style="margin-left:4px;color:#e3b341;border-color:#30363d">Update</button>
            <a href="/fleet/device/{did}/dashboard" target="_blank"
               style="margin-left:8px;background:#161b22;border:1px solid #30363d;color:#8b949e;
                      border-radius:4px;padding:3px 10px;font-size:12px;text-decoration:none;
                      display:inline-block;white-space:nowrap"
               onmouseover="this.style.borderColor='#58a6ff';this.style.color='#c9d1d9'"
               onmouseout="this.style.borderColor='#30363d';this.style.color='#8b949e'">Full Report</a>
            <button class="scan-btn" onclick="removeDevice('{did}','{d.get('hostname','')}')"
                    style="margin-left:4px;color:#f85149;border-color:#30363d;font-size:11px">Remove</button>
          </td>
        </tr>"""

    if not rows:
        rows = '<tr><td colspan="8" style="text-align:center;padding:32px;color:#484f58">No agents have reported yet.</td></tr>'

    total_fail = sum((d.get('fail_count') or 0) for d in devices)
    total_warn = sum((d.get('warn_count') or 0) for d in devices)
    total_pass = sum((d.get('pass_count') or 0) for d in devices)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>M.A.R.K. Sentinel — Command Center</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:#0d1117;color:#c9d1d9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;font-size:14px}}
#wrap{{max-width:1200px;margin:0 auto;padding:32px 24px}}
.brand-bar{{display:flex;align-items:baseline;gap:14px;margin-bottom:28px;border-bottom:1px solid #21262d;padding-bottom:18px}}
.brand-mark{{font-size:10px;letter-spacing:3px;color:#58a6ff;font-weight:700;text-transform:uppercase}}
.brand-name{{font-size:22px;font-weight:800;color:#e6edf3;letter-spacing:1px}}
.brand-sub{{font-size:12px;color:#484f58}}
.hlink{{margin-left:auto;font-size:12px;color:#58a6ff;text-decoration:none}}
.hlink:hover{{text-decoration:underline}}
.stat-row{{display:flex;gap:12px;margin-bottom:24px;flex-wrap:wrap}}
.scard{{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:16px 22px;min-width:120px;text-align:center;cursor:pointer;transition:border-color .15s,background .15s;user-select:none}}
.scard:hover{{background:#1c2128}}
.scard.sf-active{{border-color:#58a6ff;background:#1a2332}}
.scard.sf-active-red{{border-color:#f85149;background:#2a1010}}
.scard.sf-active-yellow{{border-color:#d29922;background:#2a2010}}
.scard.sf-active-green{{border-color:#3fb950;background:#102a18}}
.scard-n{{font-size:36px;font-weight:800;line-height:1}}
.scard-l{{font-size:11px;color:#8b949e;margin-top:5px;text-transform:uppercase;letter-spacing:.5px}}
.c-red{{color:#f85149}}.c-yellow{{color:#d29922}}.c-green{{color:#3fb950}}.c-blue{{color:#58a6ff}}.c-gray{{color:#6e7681}}
.sec-hdr{{font-size:12px;font-weight:600;color:#6e7681;text-transform:uppercase;letter-spacing:1px;margin-bottom:12px;display:flex;align-items:center;gap:8px}}
.dev-table{{width:100%;border-collapse:collapse;margin-bottom:28px}}
.dev-table th{{background:#161b22;color:#8b949e;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;padding:10px 12px;text-align:left;border-bottom:2px solid #30363d}}
.dev-table td{{padding:10px 12px;border-bottom:1px solid #21262d;font-size:13px}}
.dev-row{{cursor:pointer;transition:background .1s}}
.dev-row:hover{{background:#161b22}}
.dev-host{{font-weight:600;color:#e6edf3}}
.risk-dot{{display:inline-block;width:10px;height:10px;border-radius:50%}}
.risk-dot.r-fail{{background:#f85149}}.risk-dot.r-warn{{background:#d29922}}.risk-dot.r-pass{{background:#3fb950}}
.scan-btn{{background:#161b22;border:1px solid #30363d;color:#58a6ff;border-radius:4px;padding:3px 10px;font-size:12px;cursor:pointer;white-space:nowrap}}
.scan-btn:hover{{background:#1c2128;border-color:#58a6ff}}
.scan-btn:disabled{{color:#484f58;border-color:#21262d;cursor:default}}
#detail-panel{{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:22px;min-height:200px}}
.detail-hdr{{display:flex;align-items:center;gap:12px;margin-bottom:18px}}
.detail-host{{font-size:18px;font-weight:700;color:#e6edf3}}
.detail-meta{{font-size:12px;color:#6e7681}}
.finding{{background:#0d1117;border:1px solid #21262d;border-radius:6px;margin-bottom:6px;overflow:hidden}}
.fhdr{{display:flex;align-items:center;gap:10px;padding:10px 14px;cursor:pointer}}
.fhdr:hover{{background:#161b22}}
.find-ind{{width:3px;height:28px;border-radius:2px;flex-shrink:0}}
.find-ind.critical,.find-ind.fail{{background:#f85149}}
.find-ind.high{{background:#f0883e}}.find-ind.medium{{background:#d29922}}
.find-ind.pass{{background:#58a6ff}}.find-ind.warn{{background:#d29922}}.find-ind.skip{{background:#363d47}}
.sev-badge,.stat-badge{{font-size:10px;font-weight:700;padding:2px 7px;border-radius:3px;text-transform:uppercase;flex-shrink:0}}
.sev-badge.critical{{background:#3d1212;color:#f85149;border:1px solid #f85149}}
.sev-badge.high{{background:#3d1f00;color:#f0883e;border:1px solid #f0883e}}
.sev-badge.medium{{background:#2d2000;color:#d29922;border:1px solid #d29922}}
.sev-badge.low{{background:#0d1f3d;color:#388bfd;border:1px solid #388bfd}}
.stat-badge.fail{{background:#3d1212;color:#f85149}}
.stat-badge.warn{{background:#2d2000;color:#d29922}}
.stat-badge.pass{{background:#0d1a2d;color:#58a6ff}}
.stat-badge.skip{{background:#1a1f27;color:#6e7681}}
.find-id{{font-size:11px;color:#6e7681;font-family:monospace;flex-shrink:0}}
.find-title{{font-size:13px;font-weight:500;color:#c9d1d9;flex:1}}
.find-chev{{color:#363d47;font-size:11px;transition:transform .2s;flex-shrink:0}}
.finding.open .find-chev{{transform:rotate(90deg)}}
.fbody{{display:none;padding:4px 14px 14px;border-top:1px solid #21262d;color:#8b949e;font-size:13px;line-height:1.7}}
.finding.open .fbody{{display:block}}
.empty{{text-align:center;padding:48px;color:#484f58}}
.refresh-note{{font-size:11px;color:#484f58;text-align:right;margin-bottom:8px}}
.shadow-card{{background:#161b22;border:1px solid #30363d;border-left:3px solid #a371f7;border-radius:6px;padding:14px 16px;margin-bottom:8px}}
.shadow-card:hover{{background:#1a1f2e}}
::-webkit-scrollbar{{width:6px}}::-webkit-scrollbar-track{{background:#0d1117}}
::-webkit-scrollbar-thumb{{background:#30363d;border-radius:3px}}
</style>
</head>
<body>
<div id="wrap">
  <div class="brand-bar">
    <span class="brand-mark">M.A.R.K.</span>
    <span class="brand-name">SENTINEL</span>
    <span class="brand-sub">Command Center</span>
    <a class="hlink" href="/academy" target="_blank" style="margin-right:16px">Academy</a>
    <a class="hlink" href="/probe" target="_blank">&#128272; API Security Tester</a>
  </div>

  <div class="stat-row">
    <div class="scard" id="sf-all" onclick="window.open('/','_blank')" title="Open all devices in new tab">
      <div class="scard-n c-blue" id="sc-count">{len(devices)}</div><div class="scard-l">Devices</div></div>
    <div class="scard" id="sf-fail" onclick="window.open('/api/fleet/report?tier=technical&amp;status=fail&amp;fmt=html','_blank')" title="View all failed items across all devices">
      <div class="scard-n c-red" id="sc-fail">{total_fail}</div><div class="scard-l">High Risk</div></div>
    <div class="scard" id="sf-warn" onclick="window.open('/api/fleet/report?tier=technical&amp;status=warn&amp;fmt=html','_blank')" title="View all medium risk items across all devices">
      <div class="scard-n c-yellow" id="sc-warn">{total_warn}</div><div class="scard-l">Medium Risk</div></div>
    <div class="scard" id="sf-pass" onclick="window.open('/api/fleet/report?tier=technical&amp;status=pass&amp;fmt=html','_blank')" title="View all low risk checks across all devices">
      <div class="scard-n c-blue" id="sc-pass">{total_pass}</div><div class="scard-l">Info</div></div>
    <div class="scard" id="sf-shadow" onclick="document.getElementById('shadow-section').scrollIntoView({{behavior:'smooth'}})" title="Unmanaged AI devices discovered on your network — click to view">
      <div class="scard-n" id="sc-shadow" style="color:#a371f7">{len(shadow)}</div><div class="scard-l">Shadow AI</div></div>
    <div class="scard" id="sf-mcp" onclick="window.open('/api/fleet/mcp/report?tier=ciso','_blank')" title="MCP servers and AI agent tool call exposure — click to open report">
      <div class="scard-n" id="sc-mcp" style="color:#58a6ff">{len(mcp)}</div><div class="scard-l">MCP Servers</div></div>
  </div>
  <div id="filter-banner" style="display:none;background:#161b22;border:1px solid #30363d;border-radius:6px;padding:10px 18px;margin-bottom:18px;align-items:center;justify-content:space-between;gap:12px">
    <span id="filter-banner-text" style="font-size:13px;font-weight:600"></span>
    <a href="/" style="font-size:12px;color:#8b949e;text-decoration:none;white-space:nowrap;flex-shrink:0">&#8592; All devices</a>
  </div>

  <div class="sec-hdr" style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px">
    <span>Connected Devices</span>
    <span id="filter-badge" style="display:none;font-size:11px;background:#1a2332;color:#58a6ff;border:1px solid #30363d;border-radius:10px;padding:2px 10px;cursor:pointer" onclick="filterBy(null)" title="Clear filter">&#10005; clear filter</span>
    <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
      <span style="font-size:11px;color:#8b949e;white-space:nowrap">Profiles:</span>
      <label style="font-size:12px;color:#c9d1d9;white-space:nowrap;cursor:pointer"><input type="checkbox" class="rpt-profile" value="default"> Default</label>
      <label style="font-size:12px;color:#c9d1d9;white-space:nowrap;cursor:pointer"><input type="checkbox" class="rpt-profile" value="fedramp"> FedRAMP</label>
      <label style="font-size:12px;color:#c9d1d9;white-space:nowrap;cursor:pointer"><input type="checkbox" class="rpt-profile" value="cmmc"> CMMC 2.0</label>
      <label style="font-size:12px;color:#c9d1d9;white-space:nowrap;cursor:pointer"><input type="checkbox" class="rpt-profile" value="financial"> Financial</label>
      <label style="font-size:12px;color:#c9d1d9;white-space:nowrap;cursor:pointer"><input type="checkbox" class="rpt-profile" value="smb"> SMB</label>
      <label style="font-size:12px;color:#c9d1d9;white-space:nowrap;cursor:pointer"><input type="checkbox" class="rpt-profile" value="biotech"> Biotech</label>
      <label style="font-size:12px;color:#c9d1d9;white-space:nowrap;cursor:pointer"><input type="checkbox" class="rpt-profile" value="healthcare"> Healthcare</label>
      <label style="font-size:12px;color:#c9d1d9;white-space:nowrap;cursor:pointer"><input type="checkbox" class="rpt-profile" value="owasp_agentic"> OWASP Agentic</label>
      <label style="font-size:12px;color:#c9d1d9;white-space:nowrap;cursor:pointer"><input type="checkbox" class="rpt-profile" value="eu_ai_act"> EU AI Act</label>
      <button onclick="openReport('executive')" class="scan-btn"
         style="color:#3fb950;border-color:#30363d;font-size:12px">&#9654; Executive Report</button>
      <button onclick="openReport('ciso')" class="scan-btn"
         style="color:#58a6ff;border-color:#30363d;font-size:12px">&#9654; CISO Report</button>
      <button onclick="openReport('technical')" class="scan-btn"
         style="color:#8b949e;border-color:#30363d;font-size:12px">&#9654; Technical Report</button>
      <select id="scan-all-stagger" class="form-select" style="font-size:12px;padding:3px 6px;height:28px" title="Scan stagger — spread scans over time to avoid network spikes">
        <option value="normal">Normal (25/30s)</option>
        <option value="slow">Slow (10/60s)</option>
        <option value="instant">Instant</option>
      </select>
      <button id="btn-scan-all" class="scan-btn" onclick="scanAllDevices(this)"
              style="color:#f0883e;border-color:#30363d;font-size:12px">&#9654;&#9654; Scan All</button>
      <button class="scan-btn" onclick="updateAllDevices()"
              style="color:#e3b341;border-color:#30363d;font-size:12px">Update All Agents</button>
      <button id="btn-discover-all" class="scan-btn" onclick="discoverAll(this)"
              style="color:#a371f7;border-color:#30363d;font-size:12px">&#128270; Find Shadow AI</button>
      <button id="btn-discover-mcp" class="scan-btn" onclick="discoverMcp(this)"
              style="color:#58a6ff;border-color:#30363d;font-size:12px">&#128279; Scan MCP Servers</button>
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
  <div id="device-pagination" style="display:none;align-items:center;justify-content:space-between;padding:10px 2px 4px;font-size:13px;color:#8b949e;flex-wrap:wrap;gap:8px">
    <div style="display:flex;align-items:center;gap:8px">
      <span>Show</span>
      <select id="page-size-sel" onchange="changePageSize(+this.value)"
              style="background:#161b22;border:1px solid #30363d;color:#c9d1d9;border-radius:4px;padding:2px 8px;font-size:12px;cursor:pointer">
        <option value="10" selected>10</option>
        <option value="25">25</option>
        <option value="50">50</option>
        <option value="100">100</option>
      </select>
      <span id="page-info" style="color:#6e7681"></span>
    </div>
    <div id="page-btns" style="display:flex;gap:4px;align-items:center;flex-wrap:wrap"></div>
  </div>

  {_build_shadow_section(shadow, ts_now)}

  {_build_mcp_section(mcp, ts_now)}

  <div class="sec-hdr" style="margin-top:32px">
    AI Service Discovery
    <button id="discover-btn" class="scan-btn" style="margin-left:12px" onclick="runDiscovery()">Scan Network</button>
  </div>
  <div style="display:flex;align-items:center;gap:8px;margin-bottom:10px;flex-wrap:wrap">
    <label style="font-size:12px;color:#6e7681;white-space:nowrap">Subnets to scan:</label>
    <input id="discover-subnets" type="text" placeholder="auto-detect  (e.g. 10.0.1.0/24, 192.168.2.0/24)"
      style="flex:1;min-width:260px;max-width:540px;background:#0d1117;border:1px solid #30363d;border-radius:4px;
             color:#e6edf3;font-size:12px;font-family:monospace;padding:5px 10px;outline:none" />
    <span style="font-size:11px;color:#484f58">Leave blank to scan the local subnet automatically</span>
  </div>
  <div id="discover-panel" style="background:#161b22;border:1px solid #21262d;border-radius:8px;padding:18px;min-height:60px;margin-bottom:28px">
    <div class="empty" style="padding:12px">Click Scan Network to probe the local subnet for AI services.</div>
  </div>

  <div class="sec-hdr">Device Findings</div>
  <div id="detail-panel">
    <div class="empty">← Click a device row to view its dashboard</div>
  </div>

  <div class="sec-hdr" style="margin-top:32px;display:flex;align-items:center;justify-content:space-between">
    <span>Settings</span>
    <a href="/download/shortcut" class="scan-btn"
       style="text-decoration:none;font-size:12px;color:#58a6ff;border-color:#30363d;padding:3px 10px">
      &#8659; Desktop Shortcut
    </a>
  </div>
  <div style="background:#161b22;border:1px solid #21262d;border-radius:8px;padding:20px;margin-bottom:16px">
    <div style="font-size:12px;color:#8b949e;font-weight:600;text-transform:uppercase;letter-spacing:.06em;margin-bottom:14px">Configuration</div>
    <div id="cfg-saved" style="display:none;color:#3fb950;font-size:12px;margin-bottom:10px">&#10003; Saved — takes effect on next scan</div>
    <div style="display:grid;grid-template-columns:160px 1fr;gap:10px 16px;align-items:center;max-width:640px">
      <label style="font-size:13px;color:#8b949e;align-self:start;padding-top:4px">Compliance Profile</label>
      <div id="cfg-profile-group" style="display:flex;flex-wrap:wrap;gap:8px 24px">
        <label style="font-size:13px;color:#e6edf3;display:flex;align-items:center;gap:6px;cursor:pointer"><input type="checkbox" class="cfg-profile-cb" value="default"> Default</label>
        <label style="font-size:13px;color:#e6edf3;display:flex;align-items:center;gap:6px;cursor:pointer"><input type="checkbox" class="cfg-profile-cb" value="financial"> Financial Services</label>
        <label style="font-size:13px;color:#e6edf3;display:flex;align-items:center;gap:6px;cursor:pointer"><input type="checkbox" class="cfg-profile-cb" value="fedramp"> FedRAMP / NIST 800-53</label>
        <label style="font-size:13px;color:#e6edf3;display:flex;align-items:center;gap:6px;cursor:pointer"><input type="checkbox" class="cfg-profile-cb" value="cmmc"> CMMC 2.0</label>
        <label style="font-size:13px;color:#e6edf3;display:flex;align-items:center;gap:6px;cursor:pointer"><input type="checkbox" class="cfg-profile-cb" value="smb"> SMB</label>
        <label style="font-size:13px;color:#e6edf3;display:flex;align-items:center;gap:6px;cursor:pointer"><input type="checkbox" class="cfg-profile-cb" value="biotech"> Biotech (FDA 21 CFR Part 11 / HIPAA / GxP)</label>
        <label style="font-size:13px;color:#e6edf3;display:flex;align-items:center;gap:6px;cursor:pointer"><input type="checkbox" class="cfg-profile-cb" value="healthcare"> Healthcare (HIPAA / HITECH / FDA SaMD)</label>
        <label style="font-size:13px;color:#e6edf3;display:flex;align-items:center;gap:6px;cursor:pointer"><input type="checkbox" class="cfg-profile-cb" value="owasp_agentic"> OWASP Agentic AI Top 10</label>
        <label style="font-size:13px;color:#e6edf3;display:flex;align-items:center;gap:6px;cursor:pointer"><input type="checkbox" class="cfg-profile-cb" value="eu_ai_act"> EU AI Act (High-Risk Systems)</label>
      </div>
      <label style="font-size:13px;color:#8b949e">Scan Interval</label>
      <div style="display:flex;align-items:center;gap:8px">
        <input id="cfg-interval" class="form-input" type="number" min="60" placeholder="3600" style="width:120px">
        <span style="font-size:12px;color:#484f58">seconds &nbsp;(3600 = hourly · 86400 = daily)</span>
      </div>
      <label style="font-size:13px;color:#8b949e">Extra Subnets</label>
      <div style="display:flex;align-items:center;gap:8px">
        <input id="cfg-subnets" class="form-input" type="text" placeholder="192.168.50.0/24, 10.0.2.0/24" style="width:320px">
        <span style="font-size:12px;color:#484f58">additional ranges for Shadow AI scans</span>
      </div>
    </div>
    <div style="margin-top:16px">
      <button class="scan-btn" onclick="saveConfig()" style="color:#3fb950;border-color:#30363d">Save</button>
    </div>
  </div>

  <div style="background:#161b22;border:1px solid #21262d;border-radius:8px;padding:20px;margin-bottom:28px">
    <div style="font-size:12px;color:#8b949e;font-weight:600;text-transform:uppercase;letter-spacing:.06em;margin-bottom:14px">System</div>
    <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px">
      <button class="scan-btn" id="btn-pull" onclick="pullUpdates()"
              style="color:#e3b341;border-color:#30363d">&#8659; Pull Latest Updates</button>
      <button class="scan-btn" id="btn-restart-agent" onclick="restartAgent()"
              style="color:#58a6ff;border-color:#30363d">&#8635; Restart Agent</button>
      <button class="scan-btn" id="btn-restart-server" onclick="restartServer()"
              style="color:#58a6ff;border-color:#30363d">&#8635; Restart Dashboard</button>
    </div>
    <div id="sys-log" style="display:none;background:#0d1117;border:1px solid #30363d;border-radius:6px;
         padding:12px;font-family:monospace;font-size:12px;color:#8b949e;white-space:pre-wrap;
         max-height:200px;overflow-y:auto;line-height:1.6"></div>
  </div>
</div>

<script>
let _countdown = 60;
let _allDevices = [];
let _activeFilter = new URLSearchParams(location.search).get('filter') || null;
let _pageSize = 10;
let _currentPage = 1;
const _note = document.getElementById('refresh-note');
setInterval(() => {{
  _countdown--;
  if (_countdown <= 0) {{ _countdown = 60; refreshDevices(); refreshShadow(); refreshMcp(); }}
  _note.textContent = 'Devices refresh in ' + _countdown + 's';
}}, 1000);
refreshDevices();
refreshShadow();
refreshMcp();

function _age(ts) {{
  if (!ts) return 'never';
  const s = Math.floor(Date.now()/1000) - ts;
  if (s < 120) return s + 's ago';
  if (s < 3600) return Math.floor(s/60) + 'm ago';
  if (s < 86400) return Math.floor(s/3600) + 'h ago';
  return Math.floor(s/86400) + 'd ago';
}}

function _riskCls(fail, warn) {{
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
      bannerText.style.color = _activeFilter === 'fail' ? '#f85149' : _activeFilter === 'warn' ? '#d29922' : '#58a6ff';
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
    document.getElementById('sc-fail').textContent  = devs.reduce((s,d)=>s+(d.fail_count||0),0);
    document.getElementById('sc-warn').textContent  = devs.reduce((s,d)=>s+(d.warn_count||0),0);
    document.getElementById('sc-pass').textContent  = devs.reduce((s,d)=>s+(d.pass_count||0),0);
    _allDevices = devs;
    _syncFilterUI();
    const maxPage = Math.max(1, Math.ceil(_visibleDevices().length / _pageSize));
    if (_currentPage > maxPage) _currentPage = maxPage;
    renderDevicePage();
  }} catch (_) {{ /* silently ignore refresh errors */ }}
}}

function renderDevicePage() {{
  const tbody   = document.getElementById('device-tbody');
  const pgEl    = document.getElementById('device-pagination');
  const visible = _visibleDevices();
  if (!_allDevices.length) {{
    tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;padding:32px;color:#484f58">No agents have reported yet.</td></tr>';
    pgEl.style.display = 'none';
    return;
  }}
  if (!visible.length) {{
    const msg = _activeFilter === 'fail' ? 'No high risk devices.' : _activeFilter === 'warn' ? 'No medium risk devices.' : 'No info items.';
    tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;padding:32px;color:#484f58">' + msg + '</td></tr>';
    pgEl.style.display = 'none';
    return;
  }}
  const start = (_currentPage - 1) * _pageSize;
  const page  = visible.slice(start, start + _pageSize);
  tbody.innerHTML = page.map(d => {{
    const did  = d.device_id || '';
    const fail = d.fail_count || 0;
    const warn = d.warn_count || 0;
    const pas  = d.pass_count || 0;
    const rc   = _riskCls(fail, warn);
    const age  = _age(d.last_seen);
    return `<tr class="dev-row" onclick="selectDevice('${{esc(did)}}')" >
      <td class="dev-host">${{esc(d.hostname||'unknown')}}</td>
      <td>${{esc(d.platform||'')}}</td>
      <td class="c-red">${{fail}}</td>
      <td class="c-yellow">${{warn}}</td>
      <td class="c-green">${{pas}}</td>
      <td>${{esc(d.profile||'')}}</td>
      <td>${{age}}</td>
      <td><span class="risk-dot ${{rc}}"></span></td>
      <td onclick="event.stopPropagation()" style="white-space:nowrap">
        <button class="scan-btn" id="sb-${{esc(did)}}" onclick="openScanModal('${{esc(did)}}',this)">Scan ▾</button>
        <button class="scan-btn" id="ub-${{esc(did)}}" onclick="updateDevice('${{esc(did)}}')"
                style="margin-left:4px;color:#e3b341;border-color:#30363d">Update</button>
        <a href="/fleet/device/${{esc(did)}}/dashboard" target="_blank"
           style="margin-left:8px;background:#161b22;border:1px solid #30363d;color:#8b949e;
                  border-radius:4px;padding:3px 10px;font-size:12px;text-decoration:none;display:inline-block"
           onmouseover="this.style.borderColor='#58a6ff';this.style.color='#c9d1d9'"
           onmouseout="this.style.borderColor='#30363d';this.style.color='#8b949e'">Full Report</a>
        <button class="scan-btn" onclick="removeDevice('${{esc(did)}}','${{esc(d.hostname||'')}}')"
                style="margin-left:4px;color:#f85149;border-color:#30363d;font-size:11px">Remove</button>
      </td>
    </tr>`;
  }}).join('');
  renderPagination();
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
    if (prev !== null && p > prev + 1) html += `<span style="color:#484f58;padding:0 2px;line-height:24px">&#8230;</span>`;
    const active = p === _currentPage ? 'color:#58a6ff;border-color:#58a6ff;' : '';
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
  btn.textContent = 'Scanning…';
  const subnetHint = subnetInput ? ` (${{subnetInput}})` : ' (auto-detect)';
  panel.innerHTML = `<div class="empty" style="padding:12px">Probing subnet${{subnetHint}} for AI services — this may take 10–30 seconds…</div>`;
  try {{
    const url = subnetInput ? `/api/discover?subnets=${{encodeURIComponent(subnetInput)}}` : '/api/discover';
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
            return '<span style="color:#484f58;font-size:11px">n/a — monitoring tool</span>';
          if (svc.includes('jupyter') || svc.includes('streamlit') || svc.includes('gradio'))
            return '<span style="color:#484f58;font-size:11px">n/a — notebook/UI server</span>';
          if (svc.includes('unknown'))
            return '<span style="color:#e3b341;font-size:11px">⚠ unable to identify — check device</span>';
          return '<span style="color:#6e7681;font-size:11px;font-style:italic">no models loaded</span>';
        }}
        const badges = models.slice(0, 6).map(m =>
          `<span style="background:#21262d;border-radius:3px;padding:1px 6px;font-size:11px;font-family:monospace;white-space:nowrap">${{esc(m)}}</span>`
        ).join(' ');
        return badges + (models.length > 6 ? ` <span style="color:#6e7681;font-size:11px">+${{models.length - 6}} more</span>` : '');
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
        html += `<div style="margin-bottom:14px;border:1px solid #21262d;border-radius:6px;overflow:hidden">
          <div style="background:#161b22;padding:7px 12px;display:flex;align-items:center;gap:10px;border-bottom:1px solid #21262d">
            <span style="font-family:monospace;font-size:13px;font-weight:600;color:#e6edf3">${{esc(host)}}</span>
            <span style="font-size:11px;color:#6e7681">${{hostSvcs.length}} service${{hostSvcs.length !== 1 ? 's' : ''}} found</span>
          </div>
          <table style="width:100%;border-collapse:collapse">
            <thead><tr style="font-size:10px;color:#6e7681;text-transform:uppercase;letter-spacing:.4px;background:#0d1117">
              <th style="text-align:left;padding:5px 12px;width:22%">Service</th>
              <th style="text-align:left;padding:5px 8px;width:6%">Port</th>
              <th style="text-align:left;padding:5px 8px">Models Detected</th>
              <th style="text-align:left;padding:5px 8px;width:22%">URL</th>
            </tr></thead>
            <tbody>`;
        for (const s of hostSvcs) {{
          const httpStatus = s.status ? ` <span style="color:#484f58;font-size:10px">(HTTP ${{s.status}})</span>` : '';
          html += `<tr style="border-top:1px solid #161b22">
            <td style="padding:7px 12px;font-weight:600;color:#e6edf3;white-space:nowrap">${{esc(s.service)}}</td>
            <td style="padding:7px 8px;color:#6e7681;font-family:monospace;font-size:12px">${{s.port}}</td>
            <td style="padding:7px 8px">${{modelBadges(s.models, s.service)}}</td>
            <td style="padding:7px 8px;font-size:11px"><a href="${{esc(s.url)}}" target="_blank" style="color:#58a6ff;text-decoration:none;font-family:monospace">${{esc(s.url)}}</a>${{httpStatus}}</td>
          </tr>`;
        }}
        html += '</tbody></table></div>';
      }}

      // ── Local machine: running processes ──────────────────────────────────
      if (procs.length) {{
        html += `<div style="margin-bottom:14px;border:1px solid #21262d;border-radius:6px;overflow:hidden">
          <div style="background:#161b22;padding:7px 12px;display:flex;align-items:center;gap:10px;border-bottom:1px solid #21262d">
            <span style="font-size:12px;font-weight:600;color:#e3b341">⚙ Running Processes</span>
            <span style="font-size:11px;color:#6e7681">detected on this machine</span>
          </div>
          <table style="width:100%;border-collapse:collapse">
            <thead><tr style="font-size:10px;color:#6e7681;text-transform:uppercase;letter-spacing:.4px;background:#0d1117">
              <th style="text-align:left;padding:5px 12px">Service</th>
              <th style="text-align:left;padding:5px 8px">Process Signature</th>
            </tr></thead>
            <tbody>`;
        for (const p of procs) {{
          html += `<tr style="border-top:1px solid #161b22">
            <td style="padding:7px 12px;font-weight:600;color:#e6edf3">${{esc(p.service)}}</td>
            <td style="padding:7px 8px;font-family:monospace;font-size:11px;color:#6e7681"><code style="background:#21262d;padding:1px 5px;border-radius:2px">${{esc(p.process_sig || '')}}</code></td>
          </tr>`;
        }}
        html += '</tbody></table></div>';
      }}

      // ── Local machine: API keys in environment ────────────────────────────
      if (envs.length) {{
        html += `<div style="margin-bottom:14px;border:1px solid #21262d;border-radius:6px;overflow:hidden">
          <div style="background:#161b22;padding:7px 12px;display:flex;align-items:center;gap:10px;border-bottom:1px solid #21262d">
            <span style="font-size:12px;font-weight:600;color:#bc8cff">🔑 Cloud API Keys</span>
            <span style="font-size:11px;color:#6e7681">found in environment on this machine</span>
          </div>
          <table style="width:100%;border-collapse:collapse">
            <thead><tr style="font-size:10px;color:#6e7681;text-transform:uppercase;letter-spacing:.4px;background:#0d1117">
              <th style="text-align:left;padding:5px 12px">Provider</th>
              <th style="text-align:left;padding:5px 8px">Environment Variable</th>
            </tr></thead>
            <tbody>`;
        for (const e of envs) {{
          html += `<tr style="border-top:1px solid #161b22">
            <td style="padding:7px 12px;font-weight:600;color:#e6edf3">${{esc(e.service)}}</td>
            <td style="padding:7px 8px;font-family:monospace;font-size:11px;color:#6e7681"><code style="background:#21262d;padding:1px 5px;border-radius:2px">${{esc(e.env_var || '')}}</code></td>
          </tr>`;
        }}
        html += '</tbody></table></div>';
      }}

      const totalHosts = hostCount;
      const totalSvcs  = svcs.filter(s => s.source === 'network_probe').length;
      panel.innerHTML = html + `<div style="font-size:11px;color:#484f58;margin-top:2px;display:flex;align-items:center;gap:12px">
        <span>${{totalHosts}} host${{totalHosts !== 1 ? 's' : ''}} · ${{totalSvcs}} network service${{totalSvcs !== 1 ? 's' : ''}}${{procs.length ? ' · ' + procs.length + ' process' + (procs.length !== 1 ? 'es' : '') : ''}}${{envs.length ? ' · ' + envs.length + ' API key' + (envs.length !== 1 ? 's' : '') : ''}} · <span style="color:#30363d">v2025-c</span></span>
        <button onclick="this.closest('div').parentElement.innerHTML='<div class=\\'empty\\'style=\\'padding:12px\\'>Click Scan Network to detect AI services.</div>'" style="background:none;border:1px solid #30363d;color:#6e7681;border-radius:3px;padding:2px 8px;font-size:11px;cursor:pointer">Clear</button>
      </div>`;
    }}
  }} catch (e) {{
    panel.innerHTML = '<div class="empty" style="padding:12px;color:#f85149">Discovery failed: ' + esc(String(e)) + '</div>';
  }} finally {{
    btn.disabled = false;
    btn.textContent = 'Scan Network';
  }}
}}

const _SCAN_PROFILES = [
  {{id:'default',       label:'Default',             desc:'Full AI-STIG suite — all checks across all 6 risk categories, no framework filter. Best starting point.'}},
  {{id:'fedramp',       label:'FedRAMP',             desc:'FedRAMP Moderate — NIST 800-53 control mappings. Required for federal cloud systems and agency deployments.'}},
  {{id:'cmmc',          label:'CMMC 2.0',            desc:'Cybersecurity Maturity Model Certification — required for DoD contractors handling CUI.'}},
  {{id:'financial',     label:'Financial Services',  desc:'Financial sector AI controls — SOC 2, FFIEC, SR 11-7 model risk guidance.'}},
  {{id:'smb',           label:'SMB',                 desc:'Essential controls for small and medium businesses — plain language, highest-impact items only.'}},
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
  modal.style.cssText = 'background:#161b22;border:1px solid #30363d;border-radius:8px;padding:20px 24px;min-width:280px;max-width:340px;box-shadow:0 8px 32px rgba(0,0,0,.6)';

  const hostname = triggerBtn.closest('tr')?.querySelector('.dev-host')?.textContent || id.slice(0,12);

  modal.innerHTML = `
    <div style="font-size:13px;font-weight:600;color:#e6edf3;margin-bottom:4px">Select Profiles to Scan</div>
    <div style="font-size:11px;color:#6e7681;margin-bottom:14px">${{esc(hostname)}}</div>
    <div id="smp-list" style="display:flex;flex-direction:column;gap:8px;margin-bottom:16px">
      ${{_SCAN_PROFILES.map(p => `
        <label style="display:flex;align-items:flex-start;gap:10px;cursor:pointer;padding:7px 10px;border:1px solid #21262d;border-radius:5px;transition:border-color .15s"
               onmouseover="this.style.borderColor='#30363d'" onmouseout="this.style.borderColor='#21262d'">
          <input type="checkbox" value="${{p.id}}" style="margin-top:2px;accent-color:#58a6ff;cursor:pointer">
          <span>
            <span style="font-size:12px;font-weight:600;color:#e6edf3;display:block">${{p.label}}</span>
            <span style="font-size:11px;color:#6e7681">${{p.desc}}</span>
          </span>
        </label>`).join('')}}
    </div>
    <div style="display:flex;gap:8px;justify-content:flex-end">
      <button id="smp-cancel" style="background:none;border:1px solid #30363d;color:#6e7681;border-radius:4px;padding:5px 14px;font-size:12px;cursor:pointer">Cancel</button>
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

async function scanAllDevices(btn) {{
  const profiles = [...document.querySelectorAll('.rpt-profile:checked')].map(c => c.value);
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
        btn.innerHTML = '&#128270; Find Shadow AI';
        refreshShadow();
      }}, 45000);
    }} else {{
      btn.disabled = false;
      btn.innerHTML = '&#128270; Find Shadow AI';
      alert(data.error || 'Failed to queue discovery');
    }}
  }} catch (e) {{
    btn.disabled = false;
    btn.innerHTML = '&#128270; Find Shadow AI';
  }}
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

const _SHADOW_SRC = {{
  network:   {{icon:'&#127760;', color:'#a371f7', label:'Network'}},
  cloud_api: {{icon:'&#9729;',   color:'#58a6ff', label:'Cloud API'}},
  process:   {{icon:'&#9881;',   color:'#f0883e', label:'Process'}},
  docker:    {{icon:'&#128051;', color:'#3fb950', label:'Container'}},
}};

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
      container.innerHTML = '<div class="empty" style="padding:20px;text-align:center;color:#484f58">No Shadow AI detected yet. Click <strong style="color:#a371f7">Find Shadow AI</strong> above to scan your network through all installed agents.</div>';
      return;
    }}
    const _modelTags = (models) => {{
      const shown = (models||[]).slice(0,5);
      const extra = (models||[]).length > 5 ? ` <span style="font-size:11px;color:#6e7681">+${{(models||[]).length-5}} more</span>` : '';
      return shown.map(m => `<span style="background:#0d1117;border:1px solid #30363d;border-radius:3px;padding:1px 8px;font-size:11px;font-family:monospace;color:#c9d1d9">${{esc(m)}}</span>`).join(' ') + extra;
    }};

    const dockerItems = devs.filter(d => d.source === 'docker');
    const otherItems  = devs.filter(d => d.source !== 'docker');

    const otherHtml = otherItems.map(d => {{
      const src = _SHADOW_SRC[d.source] || _SHADOW_SRC.network;
      const age = _age(d.last_seen);
      const locationHtml = d.source === 'network'
        ? `<span style="font-weight:700;color:#e6edf3;font-size:14px">${{esc(d.host)}}:${{d.port}}</span>`
        : `<span style="font-weight:700;color:#e6edf3;font-size:14px">${{esc(d.service)}}</span>`;
      const subHtml = d.source === 'network'
        ? `<div style="font-size:12px;color:${{src.color}};margin-bottom:8px">${{esc(d.service)}}</div>`
        : d.detail ? `<div style="font-size:12px;color:#6e7681;margin-bottom:8px">${{esc(d.detail)}}</div>` : '';
      const modelSection = (d.models||[]).length
        ? `<div style="display:flex;flex-wrap:wrap;gap:5px;align-items:center">${{_modelTags(d.models)}}</div>`
        : `<div style="font-size:11px;color:#484f58">No model details available</div>`;
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
          <div style="text-align:right;flex-shrink:0">
            <div style="font-size:11px;color:#484f58;margin-bottom:3px">Detected ${{age}}</div>
            <div style="font-size:11px;color:#6e7681;margin-bottom:8px">via ${{esc(d.reporter_hostname)}}</div>
            <button class="scan-btn" onclick="dismissShadow(${{d.id}})" style="font-size:11px;color:#6e7681;border-color:#30363d">Dismiss</button>
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
        const portHtml   = d.port   ? `<span style="font-size:11px;color:#484f58;font-family:monospace">:${{d.port}}</span>` : '';
        const detailHtml = d.detail ? `<span style="font-size:11px;color:#6e7681;font-family:monospace">${{esc(d.detail)}}</span>` : '';
        const modelSection = (d.models||[]).length
          ? `<div style="display:flex;flex-wrap:wrap;gap:4px;align-items:center">${{_modelTags(d.models)}}</div>`
          : `<div style="font-size:11px;color:#484f58">No model details available</div>`;
        return `<div style="background:#0d1117;border:1px solid #21262d;border-radius:6px;padding:10px 14px;margin-bottom:8px">
          <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:8px">
            <div style="flex:1;min-width:0">
              <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-bottom:5px">
                <span style="font-size:13px;color:#e6edf3;font-weight:600">${{esc(d.service)}}</span>
                ${{detailHtml}}${{portHtml}}
              </div>
              ${{modelSection}}
            </div>
            <div style="text-align:right;flex-shrink:0;min-width:80px">
              <div style="font-size:11px;color:#484f58;margin-bottom:6px">${{_age(d.last_seen)}}</div>
              <button class="scan-btn" onclick="dismissShadow(${{d.id}})" style="font-size:11px;color:#6e7681;border-color:#30363d">Dismiss</button>
            </div>
          </div>
        </div>`;
      }}).join('');
      return `<div class="shadow-card" style="border-left-color:#3fb950;padding:0;overflow:hidden">
        <div style="display:flex;align-items:center;gap:8px;padding:12px 14px 10px;background:#0f1f14;border-bottom:1px solid #1a3020;margin-bottom:10px">
          <span style="font-size:18px">&#128051;</span>
          <span style="font-weight:700;color:#e6edf3;font-size:14px">${{esc(reporter)}}</span>
          <span style="font-size:10px;font-weight:700;padding:1px 7px;border-radius:3px;background:#1a3020;color:#3fb950;border:1px solid #3fb950;text-transform:uppercase">Docker Host</span>
          <span style="font-size:11px;color:#484f58;margin-left:auto">${{cntLabel}} &nbsp;&middot;&nbsp; last seen ${{_age(latestTs)}}</span>
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
  none:     {{color:'#f85149', label:'No Auth',  risk: true}},
  unknown:  {{color:'#e3b341', label:'Auth?',    risk: false}},
  required: {{color:'#3fb950', label:'Auth OK',  risk: false}},
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
      container.innerHTML = '<div class="empty" style="padding:20px;text-align:center;color:#484f58">No MCP servers detected yet. Click <strong style="color:#58a6ff">Scan MCP Servers</strong> above to scan your network through all installed agents.</div>';
      return;
    }}
    container.innerHTML = servers.map(s => {{
      const auth = _MCP_AUTH[s.auth_status] || _MCP_AUTH.unknown;
      const isProcess = s.source === 'process';
      const locationHtml = isProcess
        ? `<span style="font-weight:700;color:#e6edf3;font-size:14px">MCP Server Process</span>`
        : `<span style="font-weight:700;color:#e6edf3;font-size:14px">${{esc(s.host)}}:${{s.port}}</span>`;
      const subHtml = isProcess
        ? (s.process_info ? `<div style="font-size:11px;color:#6e7681;font-family:monospace;margin-bottom:6px">${{esc(s.process_info.substring(0,80))}}</div>` : '')
        : `<div style="font-size:12px;color:#58a6ff;margin-bottom:6px">${{esc(s.server_name || 'MCP Server')}}</div>`;
      const tools = (s.tools||[]).slice(0,6);
      const toolTags = tools.map(t => `<span style="background:#0d1117;border:1px solid #30363d;border-radius:3px;padding:1px 8px;font-size:11px;font-family:monospace;color:#c9d1d9">${{esc(t)}}</span>`).join(' ');
      const toolExtra = (s.tools||[]).length > 6 ? `<span style="font-size:11px;color:#6e7681">+${{(s.tools||[]).length-6}} more</span>` : '';
      const toolSection = (s.tools||[]).length
        ? `<div style="display:flex;flex-wrap:wrap;gap:5px;align-items:center">${{toolTags}}${{toolExtra}}</div>`
        : `<div style="font-size:11px;color:#484f58">No tools enumerated</div>`;
      const riskNote = auth.risk
        ? `<div style="font-size:11px;color:#f85149;margin-top:4px;font-weight:600">&#9888; Unauthenticated — any AI agent can connect to this server</div>` : '';
      return `<div class="shadow-card" style="border-left-color:${{auth.color}}">
        <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:12px">
          <div style="flex:1;min-width:0">
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
              <span style="font-size:16px">&#128279;</span>
              ${{locationHtml}}
              <span style="font-size:10px;font-weight:700;padding:1px 7px;border-radius:3px;background:#1a1f2e;color:${{auth.color}};border:1px solid ${{auth.color}};text-transform:uppercase">${{auth.label}}</span>
              <span style="font-size:10px;padding:1px 7px;border-radius:3px;background:#0d1117;color:#6e7681;border:1px solid #30363d;text-transform:uppercase">${{isProcess ? 'Process' : 'Network'}}</span>
            </div>
            ${{subHtml}}
            ${{toolSection}}
            ${{riskNote}}
          </div>
          <div style="text-align:right;flex-shrink:0">
            <div style="font-size:11px;color:#484f58;margin-bottom:3px">Found ${{_age(s.last_seen)}}</div>
            <div style="font-size:11px;color:#6e7681;margin-bottom:8px">via ${{esc(s.reporter_hostname)}}</div>
            <button class="scan-btn" onclick="dismissMcp(${{s.id}})" style="font-size:11px;color:#6e7681;border-color:#30363d">Dismiss</button>
          </div>
        </div>
      </div>`;
    }}).join('');
  }} catch (_) {{ /* ignore */ }}
}}

async function selectDevice(id) {{
  const panel = document.getElementById('detail-panel');
  panel.style.padding = '0';
  panel.style.minHeight = 'unset';
  panel.innerHTML = `
    <div style="display:flex;align-items:center;justify-content:space-between;
                padding:0 16px 0 0;background:#161b22;border-radius:8px 8px 0 0;
                border-bottom:1px solid #30363d">
      <div style="display:flex;align-items:center;gap:0">
        <button id="tab-btn-dash" onclick="showDashTab('${{id}}')"
          style="background:none;border:none;border-bottom:2px solid #58a6ff;color:#e6edf3;
                 font-size:13px;font-weight:600;padding:10px 16px 8px;cursor:pointer">Dashboard</button>
        <button id="tab-btn-trend" onclick="showTrendTab('${{id}}')"
          style="background:none;border:none;border-bottom:2px solid transparent;color:#6e7681;
                 font-size:13px;font-weight:400;padding:10px 16px 8px;cursor:pointer">Trend</button>
      </div>
      <div style="display:flex;gap:8px;align-items:center">
        <span id="dash-title" style="font-size:12px;color:#8b949e"></span>
        <a id="dash-ext" href="/fleet/device/${{id}}/dashboard" target="_blank"
           style="font-size:11px;color:#58a6ff;text-decoration:none">open in new tab ↗</a>
        <a href="/fleet/device/${{id}}/report.pdf"
           style="font-size:11px;color:#3fb950;text-decoration:none">&#8659; Download PDF</a>
        <button onclick="closeDevice()"
                style="background:none;border:1px solid #30363d;color:#6e7681;
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
      <div id="trend-chart" style="color:#8b949e;font-size:13px">Loading trend data…</div>
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
  if (b1) {{ b1.style.borderBottomColor = '#58a6ff'; b1.style.color = '#e6edf3'; b1.style.fontWeight = '600'; }}
  if (b2) {{ b2.style.borderBottomColor = 'transparent'; b2.style.color = '#6e7681'; b2.style.fontWeight = '400'; }}
}}

async function showTrendTab(id) {{
  const dp = document.getElementById('device-dash-pane');
  const tp = document.getElementById('device-trend-pane');
  if (dp) dp.style.display = 'none';
  if (tp) tp.style.display = '';
  const b1 = document.getElementById('tab-btn-dash'), b2 = document.getElementById('tab-btn-trend');
  if (b1) {{ b1.style.borderBottomColor = 'transparent'; b1.style.color = '#6e7681'; b1.style.fontWeight = '400'; }}
  if (b2) {{ b2.style.borderBottomColor = '#58a6ff'; b2.style.color = '#e6edf3'; b2.style.fontWeight = '600'; }}
  const chart = document.getElementById('trend-chart');
  if (!chart) return;
  chart.textContent = 'Loading…';
  try {{
    const r = await fetch('/fleet/device/' + id + '/timeseries.json');
    const data = await r.json();
    chart.innerHTML = renderTrendChart(data.points || []);
  }} catch (e) {{
    chart.innerHTML = '<div style="color:#f85149;padding:20px">Failed to load trend data: ' + e + '</div>';
  }}
}}

function renderTrendChart(points) {{
  if (!points.length) {{
    return '<div style="padding:48px;text-align:center;color:#484f58">No historical data yet.<br>'
      + '<small style="color:#363d47">The trend view populates after the device completes multiple scans.</small></div>';
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
      return '<circle cx="'+xp(i)+'" cy="'+yp(p[ser]||0)+'" r="3.5" fill="'+col+'" stroke="#0d1117" stroke-width="1"/>';
    }}).join('');
  }}
  let grid = '';
  for (let k = 0; k <= 4; k++) {{
    const yy = padT + (k/4)*cH;
    const v = Math.round(maxVal*(1 - k/4));
    grid += '<line x1="'+padL+'" y1="'+yy+'" x2="'+(padL+cW)+'" y2="'+yy+'" stroke="#21262d" stroke-width="1"/>'
          + '<text x="'+(padL-6)+'" y="'+(yy+4)+'" text-anchor="end" font-size="10" fill="#6e7681">'+v+'</text>';
  }}
  let xlabels = '';
  const step = Math.max(1, Math.floor((n-1)/5));
  for (let i = 0; i < n; i++) {{
    if (i % step !== 0 && i !== n-1) continue;
    const d = new Date(points[i].t * 1000);
    const lbl = String(d.getMonth()+1).padStart(2,'0')+'-'+String(d.getDate()).padStart(2,'0');
    xlabels += '<text x="'+xp(i)+'" y="'+(padT+cH+16)+'" text-anchor="middle" font-size="10" fill="#6e7681">'+lbl+'</text>';
  }}
  return '<div style="overflow-x:auto">'
    + '<svg viewBox="0 0 '+W+' '+H+'" style="width:100%;max-width:'+W+'px;display:block" xmlns="http://www.w3.org/2000/svg">'
    + grid
    + '<line x1="'+padL+'" y1="'+padT+'" x2="'+padL+'" y2="'+(padT+cH)+'" stroke="#30363d" stroke-width="1"/>'
    + '<line x1="'+padL+'" y1="'+(padT+cH)+'" x2="'+(padL+cW)+'" y2="'+(padT+cH)+'" stroke="#30363d" stroke-width="1"/>'
    + mkline('fail','#f85149') + mkline('warn','#d29922') + mkline('pass','#3fb950')
    + mkdots('fail','#f85149') + mkdots('warn','#d29922') + mkdots('pass','#3fb950')
    + xlabels
    + '<circle cx="'+(padL+10)+'" cy="12" r="4" fill="#f85149"/><text x="'+(padL+18)+'" y="16" font-size="11" fill="#8b949e">HIGH</text>'
    + '<circle cx="'+(padL+58)+'" cy="12" r="4" fill="#d29922"/><text x="'+(padL+66)+'" y="16" font-size="11" fill="#8b949e">MEDIUM</text>'
    + '<circle cx="'+(padL+106)+'" cy="12" r="4" fill="#58a6ff"/><text x="'+(padL+114)+'" y="16" font-size="11" fill="#8b949e">INFO</text>'
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
  el.style.color = color || '#8b949e';
  el.textContent = msg;
}}

function openReport(tier) {{
  const checked = [...document.querySelectorAll('.rpt-profile:checked')].map(c => c.value);
  const profileParam = checked.length ? '&profile=' + checked.join(',') : '';
  window.open('/api/fleet/report?tier=' + tier + '&fmt=html' + profileParam, '_blank');
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

async function pullUpdates() {{
  const btn = document.getElementById('btn-pull');
  btn.disabled = true;
  _sysLog('Checking for updates…', '#8b949e');
  try {{
    const r = await fetch('/api/system/update', {{method:'POST'}});
    const d = await r.json();
    _sysLog(d.output || '(no output)', d.status === 'error' ? '#f85149' : '#3fb950');
    if (d.status === 'restarting') {{
      btn.textContent = '↻ Restarting…';
      _sysLog('Server restarting with new code — reconnecting…', '#e3b341');
      await _waitForRestart();
      _sysLog('Server is back online. Page will reload.', '#3fb950');
      setTimeout(() => location.reload(), 800);
    }} else if (d.status === 'ok') {{
      btn.textContent = '⇓ Already up to date';
      setTimeout(() => {{ btn.disabled = false; btn.innerHTML = '&#8659; Pull Latest Updates'; }}, 4000);
    }} else {{
      btn.textContent = '⇓ Pull failed';
      setTimeout(() => {{ btn.disabled = false; btn.innerHTML = '&#8659; Pull Latest Updates'; }}, 5000);
    }}
  }} catch(e) {{
    _sysLog('Error: ' + e, '#f85149');
    btn.disabled = false; btn.innerHTML = '&#8659; Pull Latest Updates';
  }}
}}

async function _waitForRestart() {{
  for (let i = 0; i < 30; i++) {{
    await new Promise(r => setTimeout(r, 1000));
    try {{
      const r = await fetch('/api/status', {{cache:'no-store'}});
      if (r.ok) return;
    }} catch (_) {{}}
  }}
}}


async function restartAgent() {{
  const btn = document.getElementById('btn-restart-agent');
  btn.disabled = true; btn.textContent = 'Restarting…';
  _sysLog('Restarting agent service…', '#8b949e');
  try {{
    await fetch('/api/system/restart-agent', {{method:'POST'}});
    _sysLog('Agent restart queued — waiting for check-in…', '#e3b341');
    let waited = 0;
    const poll = setInterval(async () => {{
      waited += 5;
      try {{
        const r = await fetch('/api/fleet/devices');
        if (r.ok) {{
          _sysLog('Agent back online ✓', '#3fb950');
          clearInterval(poll);
          btn.disabled = false; btn.innerHTML = '&#8635; Restart Agent';
          refreshDevices();
          return;
        }}
      }} catch (_) {{}}
      if (waited >= 60) {{
        clearInterval(poll);
        _sysLog('Agent did not check in within 60s — check logs.', '#f85149');
        btn.disabled = false; btn.innerHTML = '&#8635; Restart Agent';
      }}
    }}, 5000);
  }} catch(e) {{
    _sysLog('Error: ' + e, '#f85149');
    btn.disabled = false; btn.innerHTML = '&#8635; Restart Agent';
  }}
}}

async function restartServer() {{
  const btn = document.getElementById('btn-restart-server');
  btn.disabled = true; btn.textContent = 'Restarting…';
  _sysLog('Dashboard is restarting — page will reload in 5 seconds…', '#e3b341');
  try {{
    await fetch('/api/system/restart-server', {{method:'POST'}});
  }} catch(_) {{}}
  setTimeout(() => location.reload(), 5000);
}}

async function loadConfig() {{
  try {{
    const r = await fetch('/api/config');
    if (!r.ok) return;
    const c = await r.json();
    const profs = (c.profile || '').split(',').map(p => p.trim()).filter(Boolean);
    document.querySelectorAll('.cfg-profile-cb').forEach(cb => {{
      cb.checked = profs.includes(cb.value);
    }});
    const intvl = document.getElementById('cfg-interval');
    if (intvl && c.interval) intvl.value = c.interval;
    const subnets = document.getElementById('cfg-subnets');
    if (subnets && c.extra_subnets) subnets.value = c.extra_subnets;
  }} catch (_) {{}}
}}

async function saveConfig() {{
  const body = {{}};
  const checked = [...document.querySelectorAll('.cfg-profile-cb:checked')].map(cb => cb.value);
  if (checked.length) body.profile = checked.join(',');
  const intvl = document.getElementById('cfg-interval')?.value?.trim();
  if (intvl) body.interval = parseInt(intvl, 10);
  const subnets = document.getElementById('cfg-subnets')?.value?.trim();
  if (subnets !== undefined) body.extra_subnets = subnets;
  try {{
    const r = await fetch('/api/config', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify(body),
    }});
    const d = await r.json();
    const el = document.getElementById('cfg-saved');
    if (el) {{
      const n = d.pushed_to_agents || 0;
      el.textContent = n > 0
        ? `✓ Saved — pushed to ${{n}} connected agent${{n !== 1 ? 's' : ''}}`
        : '✓ Saved — takes effect on next scan';
      el.style.display = 'block';
      setTimeout(() => el.style.display = 'none', 4000);
    }}
  }} catch (e) {{ alert('Save failed: ' + e); }}
}}

loadConfig();
</script>
<div style="margin-top:48px;padding:16px 0 24px;border-top:1px solid #21262d;text-align:center;font-size:11px;color:#484f58">
  © 2026 M.A.R.K. AI Systems. All rights reserved. Patent Pending.
</div>
</body>
</html>"""


def main():
    import argparse
    ap = argparse.ArgumentParser(description='M.A.R.K. Sentinel Dashboard Server')
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
    except OSError as _e:
        pass  # service account may not have write access; console-only logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s %(name)s %(message)s',
        handlers=_handlers,
    )

    try:
        _load_license()
        from license import start_monitors
        start_monitors(_get_store())
    except Exception as _startup_err:
        log.error('License/monitor startup error (non-fatal): %s', _startup_err, exc_info=True)
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
    print('\n  M.A.R.K. Sentinel  ·  Dashboard Server')
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
