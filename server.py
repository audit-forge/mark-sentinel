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
import http.server
import io
import json
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

def _agent_token() -> str:
    """Return expected bearer token from env or token file. Empty = no auth."""
    if os.environ.get('SENTINEL_AGENT_TOKEN'):
        return os.environ['SENTINEL_AGENT_TOKEN']
    tok_file = ROOT / 'agent_token.txt'
    if tok_file.exists():
        return tok_file.read_text().strip()
    return ''
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
            'claude':                'Claude (claude-opus-4-7)',
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
        print(f'[server] dashboard rebuild error: {e}', file=sys.stderr)
    return False


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
            cmd = [sys.executable, str(ROOT / 'audit.py'), target,
                   '--mode', provider, '--profile', profile, '--output', 'json']

        emit(f'$ {" ".join(cmd)}')
        emit('')
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, cwd=str(ROOT),
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

    def do_GET(self):
        path = urlparse(self.path).path
        static = {
            '/':               self._serve_dashboard,
            '/dashboard.html': self._serve_dashboard,
            '/api/status':     self._api_status,
            '/api/events':     self._api_events,
            '/api/devices':    self._api_devices,
            '/api/discover':   self._api_discover,
            '/fleet':          self._serve_fleet,
            '/health':         self._api_health,
            '/agent.py':       self._serve_agent_script,
            '/bundle.tar.gz':  self._serve_bundle,
        }
        if path in static:
            static[path]()
        # timeseries endpoint for fleet device charts
        elif path.startswith('/fleet/device/') and path.endswith('/timeseries.json'):
            # path: /fleet/device/<id>/timeseries.json
            did = path[len('/fleet/device/'): -len('/timeseries.json')]
            self._api_device_timeseries(did)
        elif path.startswith('/api/devices/'):
            self._api_device_report(path[len('/api/devices/'):])
        elif path.startswith('/api/agent/commands/'):
            self._api_agent_commands(path[len('/api/agent/commands/'):])
        else:
            self._not_found()

    def do_POST(self):
        path = urlparse(self.path).path
        if path == '/api/scan':
            self._api_scan()
        elif path == '/api/agent/report':
            self._api_agent_report()
        elif path.startswith('/api/fleet/scan/'):
            self._api_fleet_scan(path[len('/api/fleet/scan/'):])
        else:
            self._not_found()

    def do_OPTIONS(self):
        self._send(200, b'', 'text/plain')

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
                            f'\n<div style="position:fixed;left:50%;top:14px;'
                            f'transform:translateX(-50%);z-index:999;">'
                            f'<a href="/fleet" style="background:#161b22;color:#58a6ff;'
                            f'padding:6px 10px;border-radius:6px;border:1px solid #21262d;'
                            f'text-decoration:none;font-size:13px">Enterprise View</a></div>\n'
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
        _SKIP_DIRS  = {'output', 'benchmarks', 'docs', 'test', '.git', '__pycache__',
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
                tar.add(path, arcname=str(Path('sentinel') / rel))
        data = buf.getvalue()
        self.send_response(200)
        self.send_header('Content-Type', 'application/gzip')
        self.send_header('Content-Disposition', 'attachment; filename="sentinel.tar.gz"')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

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
        origin = self.headers.get('Origin', '')
        if origin and not origin.startswith('http://localhost') and not origin.startswith('http://127.0.0.1'):
            self._send(403, b'Forbidden', 'text/plain')
            return
        with _lock:
            if _status == 'running':
                self._json({'error': 'scan already running'}, 409)
                return
        length = int(self.headers.get('Content-Length', 0))
        body = json.loads(self.rfile.read(length)) if length else {}
        threading.Thread(
            target=_run_scan,
            args=(
                body.get('mode', 'demo'),
                body.get('target', '.'),
                body.get('profile', 'default'),
                body.get('providers', []),
            ),
            daemon=True,
        ).start()
        self._json({'status': 'started'})

    # ── agent API ─────────────────────────────────────────────────────────────

    def _api_agent_report(self):
        expected = _agent_token()
        if expected:
            auth = self.headers.get('Authorization', '')
            if auth != f'Bearer {expected}':
                self._send(401, b'Unauthorized', 'text/plain')
                return

        length = int(self.headers.get('Content-Length', 0))
        if not length:
            self._send(400, b'Empty body', 'text/plain')
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

        try:
            _get_store().upsert_report(
                device_id=device_id,
                hostname=hostname,
                report=report,
                platform=body.get('platform', ''),
                agent_version=body.get('agent_version', ''),
            )
        except Exception as e:
            print(f'[server] agent store error: {e}', file=__import__('sys').stderr)
            self._send(500, b'Storage error', 'text/plain')
            return

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
            store = _get_store()
            # Use a direct DB connection to read historical reports for this device.
            with store._conn() as conn:
                rows = conn.execute(
                    "SELECT received_at, fail_count, warn_count, pass_count FROM reports "
                    "WHERE device_id = ? ORDER BY received_at ASC",
                    (device_id,)
                ).fetchall()
            points = []
            for r in rows:
                points.append({
                    't': int(r['received_at']),
                    'fail': int(r['fail_count']),
                    'warn': int(r['warn_count']),
                    'pass': int(r['pass_count']),
                })
            self._json({'points': points})
        except Exception as e:
            self._json({'error': str(e)}, 500)

    def _serve_fleet(self):
        try:
            devices = _get_store().list_devices()
        except Exception:
            devices = []
        self._send(200, _build_fleet_html(devices).encode(), 'text/html; charset=utf-8')

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
          <td onclick="event.stopPropagation()"><button class="scan-btn" id="sb-{did}" onclick="scanDevice('{did}')">Scan Now</button></td>
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
<title>M.A.R.K. Sentinel — Enterprise View</title>
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
    <span class="brand-sub">Enterprise View</span>
    <a class="hlink" href="/">← Single-device dashboard</a>
  </div>

  <div class="stat-row">
    <div class="scard"><div class="scard-n c-blue">{len(devices)}</div><div class="scard-l">Devices</div></div>
    <div class="scard"><div class="scard-n c-red">{total_fail}</div><div class="scard-l">Total Fails</div></div>
    <div class="scard"><div class="scard-n c-yellow">{total_warn}</div><div class="scard-l">Total Warns</div></div>
    <div class="scard"><div class="scard-n c-green">{total_pass}</div><div class="scard-l">Total Passes</div></div>
  </div>

  <div class="sec-hdr">Connected Devices</div>
  <div class="refresh-note" id="refresh-note">Auto-refreshes every 60s</div>
  <table class="dev-table">
    <thead><tr>
      <th>Hostname</th><th>Platform</th>
      <th class="c-red">Fail</th><th class="c-yellow">Warn</th><th class="c-green">Pass</th>
      <th>Profile</th><th>Last seen</th><th>Risk</th><th></th>
    </tr></thead>
    <tbody>{rows}</tbody>
  </table>

  <div class="sec-hdr" style="margin-top:32px">
    AI Service Discovery
    <button id="discover-btn" class="scan-btn" style="margin-left:12px" onclick="runDiscovery()">Scan Network</button>
  </div>
  <div id="discover-panel" style="background:#161b22;border:1px solid #21262d;border-radius:8px;padding:18px;min-height:60px;margin-bottom:28px">
    <div class="empty" style="padding:12px">Click Scan Network to probe the local subnet for AI services.</div>
  </div>

  <div class="sec-hdr">Device Findings</div>
  <div id="detail-panel">
    <div class="empty">← Click a device row to view its findings</div>
  </div>
</div>

<script>
let _countdown = 60;
const _note = document.getElementById('refresh-note');
setInterval(() => {{
  _countdown--;
  if (_countdown <= 0) location.reload();
  _note.textContent = 'Auto-refreshes in ' + _countdown + 's';
}}, 1000);

function esc(s) {{
  if (!s) return '';
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
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
      <div style="font-size:11px;color:#484f58;margin-top:10px">${{svcs.length}} service(s) found</div>`;
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

async function selectDevice(id) {{
  const panel = document.getElementById('detail-panel');
  panel.innerHTML = '<div class="empty">Loading…</div>';
  try {{
    const resp = await fetch('/api/devices/' + id);
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    const data = await resp.json();
    renderDeviceFindings(panel, data, id);
  }} catch (e) {{
    panel.innerHTML = '<div class="empty">Failed to load: ' + esc(String(e)) + '</div>';
  }}
}}

function togF(i) {{
  document.getElementById('df' + i).classList.toggle('open');
}}

function renderDeviceFindings(panel, report, deviceId) {{
  const hostname = report._hostname || deviceId;
  const s = report.summary || {{}};
  const findings = (report.findings || []).sort((a, b) => {{
    const so = {{FAIL:0,WARN:1,PASS:2,SKIP:3}};
    const ss = {{CRITICAL:0,HIGH:1,MEDIUM:2,LOW:3}};
    const sd = (so[a.status]??3) - (so[b.status]??3);
    return sd !== 0 ? sd : (ss[a.severity]??3) - (ss[b.severity]??3);
  }});

  const rows = findings.map((f, i) => {{
    const sl = (f.severity || '').toLowerCase();
    const stl = (f.status || '').toLowerCase();
    const remHtml = (f.remediation || '').split('\n').filter(Boolean)
      .map(s => '<div>' + esc(s) + '</div>').join('');
    return `<div class="finding" id="df${{i}}">
      <div class="fhdr" onclick="togF(${{i}})">
        <div class="find-ind ${{sl}}"></div>
        <span class="sev-badge ${{sl}}">${{esc(f.severity)}}</span>
        <span class="stat-badge ${{stl}}">${{esc(f.status)}}</span>
        <span class="find-id">${{esc(f.check_id)}}</span>
        <span class="find-title">${{esc(f.title)}}</span>
        <span class="find-chev">▶</span>
      </div>
      <div class="fbody">
        ${{esc(f.details)}}
        ${{remHtml ? '<div style="margin-top:10px;font-size:12px"><strong>How to fix:</strong><br>' + remHtml + '</div>' : ''}}
      </div>
    </div>`;
  }}).join('');

  panel.innerHTML = `
    <div class="detail-hdr">
      <span class="detail-host">${{esc(hostname)}}</span>
      <span class="detail-meta">
        ${{s.fail || 0}} fail · ${{s.warn || 0}} warn · ${{s.pass || 0}} pass
        · Profile: ${{esc(report.profile || '')}}
        · Scan date: ${{esc(report.scan_date || '')}}
      </span>
    </div>

    <div style="margin-bottom:14px">
      <canvas id="ts-chart" width="800" height="160" style="width:100%;height:160px;background:#0d1117;border:1px solid #21262d;border-radius:6px"></canvas>
    </div>

    ${{rows || '<div class="empty">No findings for this device.</div>'}}`;

  // After populating, load timeseries data and draw chart
  loadTimeseries(deviceId);
}}

async function loadTimeseries(deviceId) {{
  try {{
    const resp = await fetch('/fleet/device/' + deviceId + '/timeseries.json');
    if (!resp.ok) throw new Error('HTTP ' + resp.status);
    const json = await resp.json();
    drawTimeseries(json.points || []);
  }} catch (e) {{
    // silently ignore chart errors and leave the canvas empty
    console.warn('timeseries load failed', e);
  }}
}}

function drawTimeseries(points) {{
  const c = document.getElementById('ts-chart');
  if (!c) return;
  const ctx = c.getContext('2d');
  // clear
  ctx.clearRect(0,0,c.width,c.height);
  if (!points || points.length === 0) {{
    // draw placeholder
    ctx.fillStyle = '#484f58';
    ctx.font = '12px sans-serif';
    ctx.fillText('No historical data', 12, 24);
    return;
  }}
  // prepare series arrays
  const ts = points.map(p => p.t * 1000); // ms
  const fail = points.map(p => p.fail);
  const warn = points.map(p => p.warn);
  const pass = points.map(p => p.pass);

  const pad = 8;
  const w = c.width - pad*2;
  const h = c.height - pad*2;
  const minT = Math.min(...ts);
  const maxT = Math.max(...ts);
  const maxY = Math.max(...fail.concat(warn).concat(pass).concat([1]));

  function xFor(t) {{
    if (maxT === minT) return pad + w/2;
    return pad + ((t - minT) / (maxT - minT)) * w;
  }}
  function yFor(v) {{
    if (maxY === 0) return pad + h;
    return pad + (1 - (v / maxY)) * h;
  }}

  // grid
  ctx.strokeStyle = '#171a1f';
  ctx.lineWidth = 1;
  ctx.beginPath();
  for (let i=0;i<=4;i++) {{
    const yy = pad + (i/4)*h;
    ctx.moveTo(pad, yy); ctx.lineTo(pad + w, yy);
  }}
  ctx.stroke();

  // draw lines for pass (green), warn (yellow), fail (red)
  const series = [
    {{arr: pass, color:'#3fb950'}},
    {{arr: warn, color:'#d29922'}},
    {{arr: fail, color:'#f85149'}},
  ];

  series.forEach(sv => {{
    ctx.beginPath();
    ctx.strokeStyle = sv.color;
    ctx.lineWidth = 2;
    sv.arr.forEach((v,i) => {{
      const x = xFor(ts[i]);
      const y = yFor(v);
      if (i===0) ctx.moveTo(x,y); else ctx.lineTo(x,y);
    }});
    ctx.stroke();
    // draw points
    ctx.fillStyle = sv.color;
    sv.arr.forEach((v,i) => {{
      const x = xFor(ts[i]);
      const y = yFor(v);
      ctx.beginPath(); ctx.arc(x,y,2,0,Math.PI*2); ctx.fill();
    }});
  }});

  // X axis labels (first and last)
  ctx.fillStyle = '#6e7681'; ctx.font = '11px sans-serif';
  const fmt = (t) => new Date(t).toLocaleString();
  ctx.fillText(fmt(minT), pad+2, c.height - 6);
  ctx.fillText(fmt(maxT), c.width - ctx.measureText(fmt(maxT)).width - 6, c.height - 6);
}}
</script>
</body>
</html>"""


def main():
    import argparse
    ap = argparse.ArgumentParser(description='M.A.R.K. Sentinel Dashboard Server')
    ap.add_argument('--port', type=int, default=PORT, help=f'Port to listen on (default: {PORT})')
    ap.add_argument('--host', default='0.0.0.0', help='Bind address (default: 0.0.0.0 — all interfaces)')
    ap.add_argument('--no-browser', action='store_true', help="Don't auto-open browser")
    args = ap.parse_args()

    server = http.server.ThreadingHTTPServer((args.host, args.port), _Handler)
    url = f'http://localhost:{args.port}'
    print(f'\n  M.A.R.K. Sentinel  ·  Dashboard Server')
    print(f'  Project  : {ROOT}')
    print(f'  Dashboard: {url}')
    print(f'  Enterprise View: {url}/fleet')
    print(f'  Devices  : {url}/api/devices')
    print(f'  Network  : http://0.0.0.0:{args.port} (accessible from LAN)')
    print(f'  Stop     : Ctrl+C\n')
    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nStopped.')


if __name__ == '__main__':
    main()
