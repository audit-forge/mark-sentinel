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
            'claude':                'Anthropic (claude-opus-4-7)',
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
_STATUS_COLOR_HTML = {'FAIL': '#f85149', 'WARN': '#d29922', 'PASS': '#3fb950', 'SKIP': '#6e7681'}


def _risk_score_html(fail, warn, total) -> int:
    if not total:
        return 0
    return max(0, 100 - round((fail * 3 + warn) / max(total, 1) * 100))


def _build_fleet_report_html(devices: list, tier: str) -> str:
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

    tier_label = {'executive': 'Executive Summary', 'ciso': 'CISO Report', 'technical': 'Technical Findings'}.get(tier, 'Fleet Report')
    total_fail = sum(d.get('fail_count', 0) or 0 for d in devices)
    total_warn = sum(d.get('warn_count', 0) or 0 for d in devices)
    total_pass = sum(d.get('pass_count', 0) or 0 for d in devices)
    total_checks = total_fail + total_warn + total_pass
    fleet_score = _risk_score_html(total_fail, total_warn, total_checks)
    score_color = '#3fb950' if fleet_score >= 80 else '#d29922' if fleet_score >= 60 else '#f85149'
    now = datetime.now(tz=timezone.utc).strftime('%Y-%m-%d %H:%M UTC')

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
.fail{{color:#f85149}}.warn{{color:#d29922}}.pass{{color:#3fb950}}.skip{{color:#6e7681}}
.crit{{color:#f85149}}.high{{color:#d29922}}.med{{color:#58a6ff}}.low{{color:#3fb950}}
.device-block{{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:20px;margin-bottom:20px}}
.finding{{padding:6px 0;border-bottom:1px solid #21262d;font-size:13px}}
.finding:last-child{{border-bottom:none}}
.rem{{color:#3fb950;font-size:12px;margin-top:3px;font-style:italic}}
.det{{color:#8b949e;font-size:12px;margin-top:3px}}
.toolbar{{position:sticky;top:0;z-index:100;background:#161b22;border-bottom:1px solid #21262d;
          margin:-32px -32px 28px;padding:10px 32px;display:flex;align-items:center;gap:10px}}
@media print{{.toolbar{{display:none}}body{{background:#fff;color:#000;padding:16px}}h1,h2,h3,.card-l{{color:#000}}.card{{border:1px solid #ccc}}.fail{{color:#c00}}.pass{{color:#090}}.warn{{color:#850}}}}
</style></head><body>
<div class="toolbar">
  <span style="flex:1;font-size:13px;font-weight:600;color:#c9d1d9">M.A.R.K. Sentinel &mdash; Fleet {esc(tier_label)}</span>
  <a href="/api/fleet/report?tier={tier}&fmt=pdf" download="sentinel_fleet_{tier}.pdf" style="{btn_style};color:#3fb950;border-color:#238636">&#8659; Download PDF</a>
  <button onclick="window.print()" style="{btn_style}">&#128438; Print</button>
</div>
<h1>M.A.R.K. Sentinel &mdash; Fleet {esc(tier_label)}</h1>
<div class="meta">Generated {esc(now)} &nbsp;&bull;&nbsp; {len(devices)} device(s) &nbsp;&bull;&nbsp; Confidential</div>
<div class="cards">
  <div class="card"><div class="card-n score">{fleet_score}%</div><div class="card-l">Fleet Score</div></div>
  <div class="card"><div class="card-n fail">{total_fail}</div><div class="card-l">Failing Checks</div></div>
  <div class="card"><div class="card-n warn">{total_warn}</div><div class="card-l">Warnings</div></div>
  <div class="card"><div class="card-n pass">{total_pass}</div><div class="card-l">Passing</div></div>
  <div class="card"><div class="card-n" style="color:#58a6ff">{len(devices)}</div><div class="card-l">Devices</div></div>
</div>''']

    # Device summary table
    parts.append('<h2>Device Status</h2><table><thead><tr><th>Hostname</th><th>Platform</th><th>Fail</th><th>Warn</th><th>Pass</th><th>Score</th><th>Last Seen</th></tr></thead><tbody>')
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

    # Critical/High findings across fleet
    all_findings = []
    for d in devices:
        rep = d.get('_report') or {}
        for r in rep.get('findings', rep.get('results', [])):
            r2 = dict(r); r2['_hostname'] = d.get('hostname') or d.get('device_id') or '?'
            all_findings.append(r2)
    crit_high = [f for f in all_findings if f.get('status') == 'FAIL' and f.get('severity') in ('CRITICAL', 'HIGH')]
    crit_high.sort(key=lambda x: _SEV_ORDER_REPORT.index(x.get('severity', 'INFO')) if x.get('severity') in _SEV_ORDER_REPORT else 99)

    parts.append(f'<h2>Critical &amp; High Findings ({len(crit_high)})</h2>')
    if not crit_high:
        parts.append('<p style="color:#3fb950;padding:12px 0">No critical or high severity failures found across the fleet.</p>')
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
        show = results if tier == 'technical' else [r for r in results if r.get('status') in ('FAIL', 'WARN')]
        show.sort(key=lambda x: _SEV_ORDER_REPORT.index(x.get('severity', 'INFO')) if x.get('severity') in _SEV_ORDER_REPORT else 99)
        if not show:
            parts.append('<p style="color:#3fb950;font-size:13px;padding:8px 0">No failures on this device.</p>')
        for r in show:
            st = r.get('status', '')
            sev = r.get('severity', 'INFO')
            sc2 = _STATUS_COLOR_HTML.get(st, '#c9d1d9')
            sv2 = _SEV_COLOR_HTML.get(sev, '#6e7681')
            parts.append(f'<div class="finding">'
                         f'<span style="color:{sc2};font-weight:700">[{esc(st)}]</span> '
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
            '/':               self._serve_dashboard,
            '/dashboard.html': self._serve_dashboard,
            '/api/status':     self._api_status,
            '/api/events':     self._api_events,
            '/api/devices':    self._api_devices,
            '/api/discover':   self._api_discover,
            '/fleet':          self._serve_fleet,
            '/academy':        self._serve_academy,
            '/command':        self._serve_fleet,
            '/api/config':     self._api_get_config,
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
        path = urlparse(self.path).path

        # Login form submission — no auth needed
        if path == '/login':
            self._handle_login_post()
            return

        # Agent report — uses its own agent-token auth
        if path == '/api/agent/report':
            self._api_agent_report()
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
        elif path.startswith('/api/fleet/scan/'):
            self._api_fleet_scan(path[len('/api/fleet/scan/'):])
        elif path == '/api/fleet/update/all':
            self._api_fleet_update_all()
        elif path.startswith('/api/fleet/update/'):
            self._api_fleet_update(path[len('/api/fleet/update/'):])
        elif path.startswith('/api/fleet/remove/'):
            self._api_fleet_remove(path[len('/api/fleet/remove/'):])
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
                            '<a href="/fleet" style="background:#161b22;color:#58a6ff;'
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

        try:
            _get_store().upsert_report(
                device_id=device_id,
                hostname=hostname,
                report=report,
                platform=body.get('platform', ''),
                agent_version=body.get('agent_version', ''),
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

        self._json({'status': 'accepted', 'device_id': device_id})

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
        """POST /api/fleet/scan/<device_id> — enqueue an on-demand scan for a device."""
        if not device_id:
            self._json({'error': 'missing device_id'}, 400)
            return
        store = _get_store()
        if store.get_device(device_id) is None:
            self._json({'error': 'device not found'}, 404)
            return
        cmd_id = store.enqueue_command(device_id, 'scan_now')
        self._json({'status': 'queued', 'device_id': device_id, 'command_id': cmd_id})

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

    def _api_fleet_report(self):
        """GET /api/fleet/report?tier=executive|ciso|technical&fmt=pdf|html|json"""
        from urllib.parse import parse_qs, urlparse as _up
        qs = parse_qs(_up(self.path).query)
        tier = (qs.get('tier', ['ciso'])[0]).lower()
        fmt  = (qs.get('fmt',  ['html'])[0]).lower()
        if tier not in ('executive', 'ciso', 'technical'):
            tier = 'ciso'
        try:
            store = _get_store()
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
                    pdf_bytes = generate_fleet_pdf(devices, tier=tier)
                    fname = f'sentinel_fleet_{tier}.pdf'
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

            html = _build_fleet_report_html(devices, tier)
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
        """GET /api/discover — scan local subnet for AI services (runs in thread)."""
        try:
            from discovery import discover
            services = discover()
            self._json({'services': services, 'count': len(services)})
        except Exception as e:
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
                    subprocess.run(['net', 'stop', 'SentinelAgent'], capture_output=True)
                    subprocess.run(['net', 'start', 'SentinelAgent'], capture_output=True)
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
        """POST /api/system/restart-server — restart this server process via os.execv."""
        def _do_restart():
            time.sleep(0.5)
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
        allowed = {'server', 'token', 'target', 'profile', 'interval'}
        clean = {k: v for k, v in body.items() if k in allowed}
        config_path = ROOT / 'agent_config.json'
        try:
            existing = json.loads(config_path.read_text(encoding='utf-8')) if config_path.exists() else {}
            existing.update(clean)
            config_path.write_text(json.dumps(existing, indent=2), encoding='utf-8')
        except Exception as e:
            self._json({'error': str(e)}, 500)
            return

        # Push profile/interval changes to all connected remote agents
        pushed = 0
        if 'profile' in clean or 'interval' in clean:
            try:
                store = _get_store()
                cmd_payload = json.dumps({k: clean[k] for k in ('profile', 'interval') if k in clean})
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
        try:
            devices = _get_store().list_devices()
        except Exception:
            devices = []
        body = _build_fleet_html(devices).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', len(body))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)

    def _serve_academy(self):
        try:
            sys.path.insert(0, str(ROOT))
            from academy import build
            html = build(ROOT)
            self._send(200, html, 'text/html; charset=utf-8')
        except Exception as e:
            self._send(500, f'Academy build failed: {e}'.encode(), 'text/plain')

    # ── helpers ───────────────────────────────────────────────────────────────

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


def _build_fleet_html(devices: list[dict]) -> str:
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
            <button class="scan-btn" id="sb-{did}" onclick="scanDevice('{did}')">Scan Now</button>
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
.scard{{background:#161b22;border:1px solid #21262d;border-radius:8px;padding:16px 22px;min-width:120px;text-align:center}}
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
.find-ind.pass{{background:#3fb950}}.find-ind.warn{{background:#d29922}}.find-ind.skip{{background:#363d47}}
.sev-badge,.stat-badge{{font-size:10px;font-weight:700;padding:2px 7px;border-radius:3px;text-transform:uppercase;flex-shrink:0}}
.sev-badge.critical{{background:#3d1212;color:#f85149;border:1px solid #f85149}}
.sev-badge.high{{background:#3d1f00;color:#f0883e;border:1px solid #f0883e}}
.sev-badge.medium{{background:#2d2000;color:#d29922;border:1px solid #d29922}}
.sev-badge.low{{background:#0d1f3d;color:#388bfd;border:1px solid #388bfd}}
.stat-badge.fail{{background:#3d1212;color:#f85149}}
.stat-badge.warn{{background:#2d2000;color:#d29922}}
.stat-badge.pass{{background:#0d2d1a;color:#3fb950}}
.stat-badge.skip{{background:#1a1f27;color:#6e7681}}
.find-id{{font-size:11px;color:#6e7681;font-family:monospace;flex-shrink:0}}
.find-title{{font-size:13px;font-weight:500;color:#c9d1d9;flex:1}}
.find-chev{{color:#363d47;font-size:11px;transition:transform .2s;flex-shrink:0}}
.finding.open .find-chev{{transform:rotate(90deg)}}
.fbody{{display:none;padding:4px 14px 14px;border-top:1px solid #21262d;color:#8b949e;font-size:13px;line-height:1.7}}
.finding.open .fbody{{display:block}}
.empty{{text-align:center;padding:48px;color:#484f58}}
.refresh-note{{font-size:11px;color:#484f58;text-align:right;margin-bottom:8px}}
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
    <a class="hlink" href="/">← Single-device dashboard</a>
  </div>

  <div class="stat-row">
    <div class="scard"><div class="scard-n c-blue" id="sc-count">{len(devices)}</div><div class="scard-l">Devices</div></div>
    <div class="scard"><div class="scard-n c-red" id="sc-fail">{total_fail}</div><div class="scard-l">Total Fails</div></div>
    <div class="scard"><div class="scard-n c-yellow" id="sc-warn">{total_warn}</div><div class="scard-l">Total Warns</div></div>
    <div class="scard"><div class="scard-n c-green" id="sc-pass">{total_pass}</div><div class="scard-l">Total Passes</div></div>
  </div>

  <div class="sec-hdr" style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px">
    <span>Connected Devices</span>
    <div style="display:flex;gap:8px;flex-wrap:wrap">
      <a href="/api/fleet/report?tier=executive&fmt=html" target="_blank" class="scan-btn"
         style="text-decoration:none;color:#3fb950;border-color:#30363d;font-size:12px">&#9654; Executive Report</a>
      <a href="/api/fleet/report?tier=ciso&fmt=html" target="_blank" class="scan-btn"
         style="text-decoration:none;color:#58a6ff;border-color:#30363d;font-size:12px">&#9654; CISO Report</a>
      <a href="/api/fleet/report?tier=technical&fmt=html" target="_blank" class="scan-btn"
         style="text-decoration:none;color:#8b949e;border-color:#30363d;font-size:12px">&#9654; Technical Report</a>
      <button class="scan-btn" onclick="updateAllDevices()"
              style="color:#e3b341;border-color:#30363d;font-size:12px">Update All Agents</button>
    </div>
  </div>
  <div class="refresh-note" id="refresh-note">Auto-refreshes every 60s</div>
  <table class="dev-table">
    <thead><tr>
      <th>Hostname</th><th>Platform</th>
      <th class="c-red">Fail</th><th class="c-yellow">Warn</th><th class="c-green">Pass</th>
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

  <div class="sec-hdr" style="margin-top:32px">
    AI Service Discovery
    <button id="discover-btn" class="scan-btn" style="margin-left:12px" onclick="runDiscovery()">Scan Network</button>
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
      <label style="font-size:13px;color:#8b949e">Compliance Profile</label>
      <select id="cfg-profile" class="form-select">
        <option value="default">Default</option>
        <option value="financial">Financial Services (NIST AI RMF / SR 26-2)</option>
        <option value="fedramp">FedRAMP / NIST 800-53</option>
        <option value="cmmc">CMMC</option>
        <option value="smb">SMB</option>
      </select>
      <label style="font-size:13px;color:#8b949e">Scan Interval</label>
      <div style="display:flex;align-items:center;gap:8px">
        <input id="cfg-interval" class="form-input" type="number" min="60" placeholder="3600" style="width:120px">
        <span style="font-size:12px;color:#484f58">seconds &nbsp;(3600 = hourly · 86400 = daily)</span>
      </div>
    </div>
    <div style="margin-top:16px">
      <button class="scan-btn" onclick="saveConfig()" style="color:#3fb950;border-color:#30363d">Save</button>
    </div>
  </div>

  <div style="background:#161b22;border:1px solid #21262d;border-radius:8px;padding:20px;margin-bottom:28px">
    <div style="font-size:12px;color:#8b949e;font-weight:600;text-transform:uppercase;letter-spacing:.06em;margin-bottom:14px">System</div>
    <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px">
      <button class="scan-btn" id="btn-scan-local" onclick="scanLocalMachine()"
              style="color:#3fb950;border-color:#30363d">&#9654; Scan This Machine</button>
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
let _pageSize = 10;
let _currentPage = 1;
const _note = document.getElementById('refresh-note');
setInterval(() => {{
  _countdown--;
  if (_countdown <= 0) {{ _countdown = 60; refreshDevices(); }}
  _note.textContent = 'Devices refresh in ' + _countdown + 's';
}}, 1000);
refreshDevices();

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
    const maxPage = Math.max(1, Math.ceil(devs.length / _pageSize));
    if (_currentPage > maxPage) _currentPage = maxPage;
    renderDevicePage();
  }} catch (_) {{ /* silently ignore refresh errors */ }}
}}

function renderDevicePage() {{
  const tbody = document.getElementById('device-tbody');
  const pgEl  = document.getElementById('device-pagination');
  if (!_allDevices.length) {{
    tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;padding:32px;color:#484f58">No agents have reported yet.</td></tr>';
    pgEl.style.display = 'none';
    return;
  }}
  const start = (_currentPage - 1) * _pageSize;
  const page  = _allDevices.slice(start, start + _pageSize);
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
        <button class="scan-btn" id="sb-${{esc(did)}}" onclick="scanDevice('${{esc(did)}}')" >Scan Now</button>
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
  const total = _allDevices.length;
  const pages = Math.max(1, Math.ceil(total / _pageSize));
  const pgEl  = document.getElementById('device-pagination');
  pgEl.style.display = 'flex';
  const start = (_currentPage - 1) * _pageSize + 1;
  const end   = Math.min(_currentPage * _pageSize, total);
  document.getElementById('page-info').textContent = start + '–' + end + ' of ' + total + ' device' + (total !== 1 ? 's' : '');
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
  const pages = Math.ceil(_allDevices.length / _pageSize);
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
  btn.disabled = true;
  btn.textContent = 'Scanning…';
  panel.innerHTML = '<div class="empty" style="padding:12px">Probing local subnet — this may take 10–30 seconds…</div>';
  try {{
    const resp = await fetch('/api/discover');
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || 'HTTP ' + resp.status);
    const svcs = data.services || [];
    if (svcs.length === 0) {{
      panel.innerHTML = '<div class="empty" style="padding:12px">No AI services found on the local network.</div>';
    }} else {{
      const rows = svcs.map(s => {{
        const status = s.status ? 'HTTP ' + s.status : 'TCP open';
        return `<tr>
          <td style="font-weight:600;color:#e6edf3">${{esc(s.service)}}</td>
          <td><a href="${{esc(s.url)}}" target="_blank" style="color:#58a6ff;text-decoration:none">${{esc(s.url)}}</a></td>
          <td style="color:#6e7681;font-family:monospace;font-size:12px">${{esc(s.host)}}</td>
          <td style="color:#6e7681">${{esc(String(s.port))}}</td>
          <td style="color:#3fb950;font-size:12px">${{esc(status)}}</td>
        </tr>`;
      }}).join('');
      panel.innerHTML = `<table style="width:100%;border-collapse:collapse">
        <thead><tr style="font-size:11px;color:#6e7681;text-transform:uppercase;letter-spacing:.5px">
          <th style="text-align:left;padding:6px 10px;border-bottom:1px solid #30363d">Service</th>
          <th style="text-align:left;padding:6px 10px;border-bottom:1px solid #30363d">URL</th>
          <th style="text-align:left;padding:6px 10px;border-bottom:1px solid #30363d">Host</th>
          <th style="text-align:left;padding:6px 10px;border-bottom:1px solid #30363d">Port</th>
          <th style="text-align:left;padding:6px 10px;border-bottom:1px solid #30363d">Status</th>
        </tr></thead>
        <tbody>${{rows}}</tbody>
      </table>
      <div style="font-size:11px;color:#484f58;margin-top:10px;display:flex;align-items:center;gap:12px">
        <span>${{svcs.length}} service(s) found</span>
        <button onclick="this.closest('div').parentElement.innerHTML='<div class=\\'empty\\'style=\\'padding:12px\\'>Click Scan Network to probe the local subnet for AI services.</div>'" style="background:none;border:1px solid #30363d;color:#6e7681;border-radius:3px;padding:2px 8px;font-size:11px;cursor:pointer">Clear</button>
      </div>`;
    }}
  }} catch (e) {{
    panel.innerHTML = '<div class="empty" style="padding:12px;color:#f85149">Discovery failed: ' + esc(String(e)) + '</div>';
  }} finally {{
    btn.disabled = false;
    btn.textContent = 'Scan Network';
  }}
}}

async function scanDevice(id) {{
  const btn = document.getElementById('sb-' + id);
  if (btn) {{ btn.disabled = true; btn.textContent = 'Queued…'; }}
  try {{
    const resp = await fetch('/api/fleet/scan/' + id, {{method: 'POST'}});
    const data = await resp.json();
    if (resp.ok) {{
      if (btn) btn.textContent = 'Queued ✓';
      setTimeout(() => {{ if (btn) {{ btn.disabled = false; btn.textContent = 'Scan Now'; }} }}, 5000);
    }} else {{
      if (btn) {{ btn.disabled = false; btn.textContent = 'Error'; }}
      alert(data.error || 'Failed to queue scan');
    }}
  }} catch (e) {{
    if (btn) {{ btn.disabled = false; btn.textContent = 'Scan Now'; }}
  }}
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
    + '<circle cx="'+(padL+10)+'" cy="12" r="4" fill="#f85149"/><text x="'+(padL+18)+'" y="16" font-size="11" fill="#8b949e">FAIL</text>'
    + '<circle cx="'+(padL+58)+'" cy="12" r="4" fill="#d29922"/><text x="'+(padL+66)+'" y="16" font-size="11" fill="#8b949e">WARN</text>'
    + '<circle cx="'+(padL+106)+'" cy="12" r="4" fill="#3fb950"/><text x="'+(padL+114)+'" y="16" font-size="11" fill="#8b949e">PASS</text>'
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

async function scanLocalMachine() {{
  const btn = document.getElementById('btn-scan-local');
  const profile = document.getElementById('cfg-profile')?.value || 'default';
  btn.disabled = true; btn.textContent = 'Scanning…';
  _sysLog('Running config scan on this machine…', '#8b949e');
  try {{
    const r = await fetch('/api/scan', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify({{mode: 'config', target: '.', profile: profile, providers: ['config']}})
    }});
    const d = await r.json();
    if (d.error) {{
      _sysLog('Scan error: ' + d.error, '#f85149');
    }} else {{
      _sysLog('Scan started. Polling for results…', '#8b949e');
      let polls = 0;
      const poll = setInterval(async () => {{
        polls++;
        btn.textContent = `Scanning… ${{polls * 3}}s`;
        try {{
          const sr = await fetch('/api/status');
          const sd = await sr.json();
          if (sd.status === 'done' || sd.status === 'error') {{
            clearInterval(poll);
            const color = sd.status === 'done' ? '#3fb950' : '#f85149';
            _sysLog('Scan ' + sd.status + '. Results stored — check Fleet tab for trend data.', color);
            btn.textContent = sd.status === 'done' ? '&#9654; Scan Complete' : '&#9654; Scan Error';
            setTimeout(() => {{ btn.disabled = false; btn.innerHTML = '&#9654; Scan This Machine'; }}, 5000);
          }}
        }} catch(e) {{}}
        if (polls > 100) {{ clearInterval(poll); btn.disabled = false; btn.innerHTML = '&#9654; Scan This Machine'; }}
      }}, 3000);
    }}
  }} catch(e) {{
    _sysLog('Error: ' + e, '#f85149');
    btn.disabled = false; btn.innerHTML = '&#9654; Scan This Machine';
  }}
}}

async function restartAgent() {{
  const btn = document.getElementById('btn-restart-agent');
  btn.disabled = true; btn.textContent = 'Restarting…';
  _sysLog('Restarting agent service…', '#8b949e');
  try {{
    await fetch('/api/system/restart-agent', {{method:'POST'}});
    _sysLog('Agent restart queued. It will check back in within 30 seconds.', '#3fb950');
    setTimeout(() => {{ btn.disabled = false; btn.innerHTML = '&#8635; Restart Agent'; }}, 5000);
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
    const prof = document.getElementById('cfg-profile');
    if (prof && c.profile) prof.value = c.profile;
    const intvl = document.getElementById('cfg-interval');
    if (intvl && c.interval) intvl.value = c.interval;
  }} catch (_) {{}}
}}

async function saveConfig() {{
  const body = {{}};
  const prof  = document.getElementById('cfg-profile')?.value;
  const intvl = document.getElementById('cfg-interval')?.value?.trim();
  if (prof)  body.profile  = prof;
  if (intvl) body.interval = parseInt(intvl, 10);
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
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s %(name)s %(message)s',
        handlers=[
            logging.FileHandler(log_file, encoding='utf-8'),
            logging.StreamHandler(sys.stderr),
        ],
    )

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
