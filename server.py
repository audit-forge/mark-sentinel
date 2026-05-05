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
_serve_port = PORT   # updated at startup so handlers can reference it

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

    def do_GET(self):
        path = urlparse(self.path).path
        static = {
            '/':               self._serve_dashboard,
            '/dashboard.html': self._serve_dashboard,
            '/api/status':     self._api_status,
            '/api/events':     self._api_events,
            '/api/devices':    self._api_devices,
            '/api/discover':   self._api_discover,
            '/fleet':              self._serve_fleet,
            '/health':             self._api_health,
            '/agent.py':           self._serve_agent_script,
            '/bundle.tar.gz':      self._serve_bundle,
            '/academy':            self._serve_academy,
            '/command':            self._serve_fleet,
            '/api/config':         self._api_get_config,
            '/download/shortcut':  self._serve_shortcut,
        }
        if path in static:
            static[path]()
        # timeseries endpoint for fleet device charts
        elif path.startswith('/fleet/device/') and path.endswith('/timeseries.json'):
            did = path[len('/fleet/device/'): -len('/timeseries.json')]
            self._api_device_timeseries(did)
        # full single-device dashboard (all views: findings, remediation, heatmap, etc.)
        elif path.startswith('/fleet/device/') and path.endswith('/dashboard'):
            did = path[len('/fleet/device/'): -len('/dashboard')]
            self._serve_device_dashboard(did)
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
        elif path == '/api/config':
            self._api_set_config()
        elif path.startswith('/api/fleet/scan/'):
            self._api_fleet_scan(path[len('/api/fleet/scan/'):])
        elif path == '/api/fleet/update/all':
            self._api_fleet_update_all()
        elif path.startswith('/api/fleet/update/'):
            self._api_fleet_update(path[len('/api/fleet/update/'):])
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
        self.send_response(200)
        self.send_header('Content-Type', 'application/gzip')
        self.send_header('Content-Disposition', 'attachment; filename="sentinel.tar.gz"')
        self.send_header('Content-Length', str(len(data)))
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
            print(f'[server] get_latest_report error for {device_id}: {e}', file=sys.stderr)
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
                    b'<div class="title">No scan report yet for ' + hostname.encode() + b'</div>'
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
            generate([report], tmp_path,
                     meta={'scan_date': report.get('scan_date', ''),
                           'target':    report.get('target', device_id)})
            html = Path(tmp_path).read_bytes()
            _os.unlink(tmp_path)
            self._send(200, html, 'text/html; charset=utf-8')
        except Exception as e:
            print(f'[server] dashboard generation error for {device_id}: {e}', file=sys.stderr)
            self._send(500, f'Dashboard generation failed: {e}'.encode(), 'text/plain')

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

        try:
            from alerts import load_alert_config, fire_alerts
            alert_cfg = load_alert_config(ROOT / 'alerts_config.json')
            if alert_cfg:
                fire_alerts(report, device_id, hostname, alert_cfg)
        except Exception as _ae:
            print(f'[server] alerts error: {_ae}', file=sys.stderr)

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
        length = int(self.headers.get('Content-Length', 0))
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
            self._json({'status': 'saved'})
        except Exception as e:
            self._json({'error': str(e)}, 500)

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
        self._send(200, _build_fleet_html(devices).encode(), 'text/html; charset=utf-8')

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

  <div class="sec-hdr" style="display:flex;align-items:center;justify-content:space-between">
    <span>Connected Devices</span>
    <button class="scan-btn" onclick="updateAllDevices()"
            style="color:#e3b341;border-color:#30363d;font-size:12px">Update All Agents</button>
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
  <div style="background:#161b22;border:1px solid #21262d;border-radius:8px;padding:20px;margin-bottom:28px">
    <div id="cfg-saved" style="display:none;color:#3fb950;font-size:12px;margin-bottom:10px">&#10003; Saved</div>
    <div style="display:grid;grid-template-columns:160px 1fr;gap:10px 16px;align-items:center;max-width:640px">
      <label style="font-size:13px;color:#8b949e">Server URL</label>
      <input id="cfg-server" class="form-input" type="text" placeholder="http://10.0.1.50:7331">
      <label style="font-size:13px;color:#8b949e">Agent Token</label>
      <input id="cfg-token" class="form-input" type="password" placeholder="leave blank if none">
      <label style="font-size:13px;color:#8b949e">Scan Target</label>
      <input id="cfg-target" class="form-input" type="text" placeholder=".">
      <label style="font-size:13px;color:#8b949e">Profile</label>
      <select id="cfg-profile" class="form-select">
        <option value="default">Default</option>
        <option value="financial">Financial Services (NIST AI RMF / SR 26-2)</option>
        <option value="fedramp">FedRAMP / NIST 800-53</option>
        <option value="cmmc">CMMC</option>
        <option value="smb">SMB</option>
      </select>
      <label style="font-size:13px;color:#8b949e">Scan Interval (s)</label>
      <input id="cfg-interval" class="form-input" type="number" min="60" placeholder="3600">
    </div>
    <div style="margin-top:16px">
      <button class="scan-btn" onclick="saveConfig()" style="color:#3fb950;border-color:#30363d">Save Config</button>
    </div>
  </div>
</div>

<script>
let _countdown = 60;
const _note = document.getElementById('refresh-note');
setInterval(() => {{
  _countdown--;
  if (_countdown <= 0) {{ _countdown = 60; refreshDevices(); }}
  _note.textContent = 'Devices refresh in ' + _countdown + 's';
}}, 1000);

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
    const tFail = devs.reduce((s,d)=>s+(d.fail_count||0),0);
    const tWarn = devs.reduce((s,d)=>s+(d.warn_count||0),0);
    const tPass = devs.reduce((s,d)=>s+(d.pass_count||0),0);
    document.getElementById('sc-count').textContent = devs.length;
    document.getElementById('sc-fail').textContent  = tFail;
    document.getElementById('sc-warn').textContent  = tWarn;
    document.getElementById('sc-pass').textContent  = tPass;
    const tbody = document.getElementById('device-tbody');
    if (!devs.length) {{
      tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;padding:32px;color:#484f58">No agents have reported yet.</td></tr>';
      return;
    }}
    tbody.innerHTML = devs.map(d => {{
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
                    border-radius:4px;padding:3px 10px;font-size:12px;text-decoration:none;
                    display:inline-block"
             onmouseover="this.style.borderColor='#58a6ff';this.style.color='#c9d1d9'"
             onmouseout="this.style.borderColor='#30363d';this.style.color='#8b949e'">Full Report</a>
        </td>
      </tr>`;
    }}).join('');
  }} catch (_) {{ /* silently ignore refresh errors */ }}
}}

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

async function loadConfig() {{
  try {{
    const r = await fetch('/api/config');
    if (!r.ok) return;
    const c = await r.json();
    const set = (id, val) => {{ const el = document.getElementById(id); if (el && val !== undefined) el.value = val; }};
    set('cfg-server',   c.server   || '');
    set('cfg-token',    c.token    || '');
    set('cfg-target',   c.target   || '');
    set('cfg-interval', c.interval || '');
    const prof = document.getElementById('cfg-profile');
    if (prof && c.profile) prof.value = c.profile;
  }} catch (_) {{}}
}}

async function saveConfig() {{
  const get = id => document.getElementById(id)?.value?.trim() || '';
  const body = {{}};
  const server = get('cfg-server');   if (server)   body.server   = server;
  const token  = get('cfg-token');    if (token)    body.token    = token;
  const target = get('cfg-target');   if (target)   body.target   = target;
  const prof   = document.getElementById('cfg-profile')?.value; if (prof) body.profile = prof;
  const intvl  = get('cfg-interval'); if (intvl)    body.interval = parseInt(intvl, 10);
  try {{
    const r = await fetch('/api/config', {{
      method: 'POST',
      headers: {{'Content-Type': 'application/json'}},
      body: JSON.stringify(body),
    }});
    const d = await r.json();
    const el = document.getElementById('cfg-saved');
    if (el) {{ el.style.display = 'block'; setTimeout(() => el.style.display = 'none', 3000); }}
  }} catch (e) {{ alert('Save failed: ' + e); }}
}}

loadConfig();
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

    global _serve_port
    _serve_port = args.port
    server = http.server.ThreadingHTTPServer((args.host, args.port), _Handler)
    url = f'http://localhost:{args.port}'
    print('\n  M.A.R.K. Sentinel  ·  Dashboard Server')
    print(f'  Project  : {ROOT}')
    print(f'  Dashboard: {url}')
    print(f'  Command Center: {url}/command (also available at {url}/fleet)')
    print(f'  Devices  : {url}/api/devices')
    print(f'  Network  : http://0.0.0.0:{args.port} (accessible from LAN)')
    print('  Stop     : Ctrl+C\n')
    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nStopped.')


if __name__ == '__main__':
    main()
