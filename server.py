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
import json
import subprocess
import threading
import time
import webbrowser
from pathlib import Path
from urllib.parse import urlparse

PORT = 7331
ROOT = Path(__file__).parent

# ── scan state ────────────────────────────────────────────────────────────────
_lock   = threading.Lock()
_status = 'idle'       # idle | running | done | error
_log: list[str] = []
# ─────────────────────────────────────────────────────────────────────────────


def _latest_out_dir() -> Path | None:
    dirs = sorted((ROOT / 'output').glob('demo_*'), reverse=True)
    return dirs[0] if dirs else None


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
        {
            '/':               self._serve_dashboard,
            '/dashboard.html': self._serve_dashboard,
            '/api/status':     self._api_status,
            '/api/events':     self._api_events,
        }.get(path, self._not_found)()

    def do_POST(self):
        path = urlparse(self.path).path
        if path == '/api/scan':
            self._api_scan()
        else:
            self._not_found()

    def do_OPTIONS(self):
        self._send(200, b'', 'text/plain')

    # ── endpoints ─────────────────────────────────────────────────────────────

    def _serve_dashboard(self):
        out_dir = _latest_out_dir()
        dash = (out_dir / 'dashboard.html') if out_dir else None
        if dash and dash.exists():
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


def main():
    import argparse
    ap = argparse.ArgumentParser(description='M.A.R.K. Sentinel Dashboard Server')
    ap.add_argument('--port', type=int, default=PORT, help=f'Port to listen on (default: {PORT})')
    ap.add_argument('--no-browser', action='store_true', help="Don't auto-open browser")
    args = ap.parse_args()

    server = http.server.ThreadingHTTPServer(('127.0.0.1', args.port), _Handler)
    url = f'http://localhost:{args.port}'
    print(f'\n  M.A.R.K. Sentinel  ·  Dashboard Server')
    print(f'  Project : {ROOT}')
    print(f'  URL     : {url}')
    print(f'  Stop    : Ctrl+C\n')
    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print('\nStopped.')


if __name__ == '__main__':
    main()
