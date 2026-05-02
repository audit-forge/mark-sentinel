#!/usr/bin/env python3
"""
M.A.R.K. Sentinel Agent — distributed device scanner

Runs local AI security checks on a schedule and reports results to a
central Sentinel server. Designed to be installed as a system service
(systemd, launchd, Windows Service, Intune) on every device you want
to audit.

Usage:
  python3 agent.py --server http://10.0.1.50:7331 --token <tok>
  python3 agent.py --daemon --interval 3600
  python3 agent.py --config /etc/sentinel/agent_config.json --once
  python3 agent.py --scan-only          # local scan, no reporting

Config file (agent_config.json):
  {
    "server":   "http://10.0.1.50:7331",
    "token":    "your-secret-token",
    "target":   ".",
    "profile":  "default",
    "interval": 3600
  }

Environment overrides:
  SENTINEL_SERVER       — server URL
  SENTINEL_AGENT_TOKEN  — auth token
"""
import sys
if sys.version_info < (3, 11):
    sys.exit(
        "M.A.R.K. Sentinel requires Python 3.11 or later.\n"
        f"Running: Python {sys.version.split()[0]}\n"
        "Install: https://python.org/downloads/"
    )

import argparse
import hashlib
import json
import logging
import os
import platform
import socket
import subprocess
import time
from pathlib import Path
from urllib import error as _urlerr
from urllib import request as _urlreq

ROOT = Path(__file__).parent
DEFAULT_CONFIG = ROOT / 'agent_config.json'
VERSION = '1.0.0'
_PROCESS_NAME = 'sentinel-agent'


def _set_process_name() -> None:
    """Rename the process so it shows as 'sentinel-agent' in Activity Monitor,
    ps, top, Task Manager, etc. — not as 'python3' or 'python.exe'."""
    import ctypes
    import ctypes.util

    sys.argv[0] = _PROCESS_NAME  # affects ps on some systems

    system = __import__('platform').system()

    if system == 'Darwin':
        try:
            libc = ctypes.CDLL(ctypes.util.find_library('c'), use_errno=True)
            libc.setproctitle(b'sentinel-agent')
        except Exception:
            pass

    elif system == 'Linux':
        try:
            ctypes.CDLL('libc.so.6', use_errno=True).prctl(
                15, b'sentinel-agent', 0, 0, 0)  # PR_SET_NAME = 15
        except Exception:
            pass

    elif system == 'Windows':
        try:
            ctypes.windll.kernel32.SetConsoleTitleW('sentinel-agent')
        except Exception:
            pass

logging.basicConfig(
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S',
    level=logging.INFO,
)
log = logging.getLogger('sentinel-agent')


# ── Device identity ────────────────────────────────────────────────────────────

def _device_id() -> str:
    """Stable 16-char hex ID derived from hostname + MAC address."""
    hostname = socket.gethostname()
    try:
        import uuid
        # node = 48-bit MAC integer
        node = uuid.getnode()
        mac = ':'.join(f'{(node >> i) & 0xff:02x}' for i in range(0, 48, 8))
    except Exception:
        mac = 'unknown'
    return hashlib.sha256(f'{hostname}:{mac}'.encode()).hexdigest()[:16]


# ── Config loading ─────────────────────────────────────────────────────────────

def load_config(path: Path | None = None) -> dict:
    path = path or DEFAULT_CONFIG
    cfg: dict = {}
    if path.exists():
        try:
            cfg = json.loads(path.read_text())
        except Exception as e:
            log.warning('Could not parse config %s: %s', path, e)
    if os.environ.get('SENTINEL_SERVER'):
        cfg['server'] = os.environ['SENTINEL_SERVER']
    if os.environ.get('SENTINEL_AGENT_TOKEN'):
        cfg['token'] = os.environ['SENTINEL_AGENT_TOKEN']
    return cfg


# ── Local scan ─────────────────────────────────────────────────────────────────

def run_scan(target: str, profile: str) -> dict | None:
    """
    Run a config-mode Sentinel scan and return the parsed JSON report.
    Captures stdout (JSON) separately from stderr (progress output).
    """
    audit_script = ROOT / 'audit.py'
    if not audit_script.exists():
        log.error('audit.py not found at %s', audit_script)
        return None

    cmd = [
        sys.executable, str(audit_script),
        '--mode', 'config',
        '--target', target,
        '--profile', profile,
        '--output', 'json',
        '--quiet',
    ]
    log.info('Scan: %s', ' '.join(cmd))

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=300, cwd=str(ROOT),
        )
    except subprocess.TimeoutExpired:
        log.error('Scan timed out after 300 s')
        return None
    except Exception as e:
        log.error('Failed to launch scan: %s', e)
        return None

    # audit.py exits 1 when findings exist (standard scanner behavior).
    # Only treat it as a fatal error if there's no JSON on stdout.
    stdout = proc.stdout.strip()
    if not stdout:
        log.error('Scan produced no output (exit %d): %s',
                  proc.returncode, (proc.stderr or '')[-400:])
        return None

    try:
        return json.loads(stdout)
    except json.JSONDecodeError as e:
        log.error('Could not parse scan JSON (exit %d): %s\nOutput: %s',
                  proc.returncode, e, stdout[:300])
        return None


# ── Reporting ──────────────────────────────────────────────────────────────────

def report_to_server(report: dict, config: dict,
                     device_id: str, hostname: str) -> bool:
    """POST the scan report to the central Sentinel server."""
    server = config.get('server', '').rstrip('/')
    if not server:
        log.warning('No server configured — scan-only mode')
        return True

    token = config.get('token', '')
    payload = json.dumps({
        'device_id':     device_id,
        'hostname':      hostname,
        'platform':      platform.system(),
        'agent_version': VERSION,
        'report':        report,
    }).encode()

    headers: dict[str, str] = {
        'Content-Type':   'application/json',
        'Content-Length': str(len(payload)),
        'User-Agent':     f'sentinel-agent/{VERSION}',
    }
    if token:
        headers['Authorization'] = f'Bearer {token}'

    url = f'{server}/api/agent/report'
    for attempt in range(1, 4):
        try:
            req = _urlreq.Request(url, data=payload, headers=headers, method='POST')
            with _urlreq.urlopen(req, timeout=30) as resp:
                if 200 <= resp.status < 300:
                    log.info('Report accepted (HTTP %s)', resp.status)
                    return True
                log.warning('Server returned HTTP %s (attempt %d/3)', resp.status, attempt)
        except _urlerr.HTTPError as e:
            log.warning('HTTP %s from server (attempt %d/3)', e.code, attempt)
        except _urlerr.URLError as e:
            log.warning('Connection error (attempt %d/3): %s', attempt, e.reason)
        except Exception as e:
            log.warning('Unexpected error (attempt %d/3): %s', attempt, e)

        if attempt < 3:
            wait = 2 ** attempt
            log.info('Retry in %ds…', wait)
            time.sleep(wait)

    log.error('Failed to deliver report after 3 attempts')
    return False


# ── Command polling ────────────────────────────────────────────────────────────

def poll_for_command(config: dict, device_id: str) -> str | None:
    """Check the server for a pending on-demand command. Returns command string or None."""
    server = config.get('server', '').rstrip('/')
    if not server:
        return None
    token = config.get('token', '')
    url = f'{server}/api/agent/commands/{device_id}'
    headers: dict[str, str] = {'User-Agent': f'sentinel-agent/{VERSION}'}
    if token:
        headers['Authorization'] = f'Bearer {token}'
    try:
        req = _urlreq.Request(url, headers=headers)
        with _urlreq.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())
            return data.get('command')
    except Exception:
        return None


# ── Main scan cycle ────────────────────────────────────────────────────────────

def run_cycle(config: dict) -> bool:
    target    = config.get('target', '.')
    profile   = config.get('profile', 'default')
    device_id = _device_id()
    hostname  = socket.gethostname()

    log.info('Device: %s  Hostname: %s  Target: %s  Profile: %s',
             device_id, hostname, target, profile)

    report = run_scan(target, profile)
    if report is None:
        return False

    summary = report.get('summary', {})
    log.info('Scan complete — FAIL:%d WARN:%d PASS:%d',
             summary.get('fail', 0), summary.get('warn', 0), summary.get('pass', 0))

    return report_to_server(report, config, device_id, hostname)


# ── Entry point ────────────────────────────────────────────────────────────────

_LAUNCHD_LABEL = 'com.mark.sentinel.agent'
_SYSTEMD_UNIT   = 'sentinel-agent'


def _install_service(args: argparse.Namespace, cfg: dict) -> None:
    """Install the agent as an auto-starting background service."""
    import platform as _platform
    system = _platform.system()

    # Build the daemon command from current invocation args
    python  = sys.executable
    script  = str(Path(__file__).resolve())
    cmd     = [python, script, '--daemon']
    if cfg.get('server'):  cmd += ['--server',  cfg['server']]
    if cfg.get('token'):   cmd += ['--token',   cfg['token']]
    if cfg.get('target'):  cmd += ['--target',  cfg['target']]
    if cfg.get('profile'): cmd += ['--profile', cfg['profile']]
    if cfg.get('interval'):cmd += ['--interval',str(cfg['interval'])]

    if system == 'Darwin':
        _install_launchd(cmd)
    elif system == 'Linux':
        _install_systemd(cmd)
    else:
        log.error('Service install not supported on %s — run with --daemon manually.', system)
        sys.exit(1)


def _install_launchd(cmd: list[str]) -> None:
    """Create and load a launchd user agent plist."""
    import plistlib as _plist
    plist_dir  = Path.home() / 'Library' / 'LaunchAgents'
    plist_path = plist_dir / f'{_LAUNCHD_LABEL}.plist'
    log_dir    = Path.home() / 'Library' / 'Logs' / 'sentinel'
    plist_dir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)

    plist = {
        'Label':             _LAUNCHD_LABEL,
        'ProgramArguments':  cmd,
        'RunAtLoad':         True,
        'KeepAlive':         True,
        'StandardOutPath':   str(log_dir / 'agent.log'),
        'StandardErrorPath': str(log_dir / 'agent.log'),
        'EnvironmentVariables': {'PATH': '/usr/local/bin:/usr/bin:/bin'},
    }
    with open(plist_path, 'wb') as f:
        _plist.dump(plist, f)

    # Unload first in case an old version is running, then load
    subprocess.run(['launchctl', 'unload', str(plist_path)],
                   capture_output=True)
    result = subprocess.run(['launchctl', 'load', str(plist_path)],
                            capture_output=True, text=True)
    if result.returncode != 0:
        log.error('launchctl load failed: %s', result.stderr.strip())
        sys.exit(1)

    log.info('Service installed and started.')
    log.info('  Plist : %s', plist_path)
    log.info('  Logs  : %s', log_dir / 'agent.log')
    log.info('  Stop  : launchctl unload %s', plist_path)
    log.info('  Status: launchctl list %s', _LAUNCHD_LABEL)


def _install_systemd(cmd: list[str]) -> None:
    """Create and enable a systemd user unit."""
    unit_dir  = Path.home() / '.config' / 'systemd' / 'user'
    unit_path = unit_dir / f'{_SYSTEMD_UNIT}.service'
    unit_dir.mkdir(parents=True, exist_ok=True)

    exec_start = ' '.join(cmd)
    unit_text = f"""[Unit]
Description=M.A.R.K. Sentinel Agent
After=network.target

[Service]
ExecStart={exec_start}
Restart=on-failure
RestartSec=30

[Install]
WantedBy=default.target
"""
    unit_path.write_text(unit_text)
    subprocess.run(['systemctl', '--user', 'daemon-reload'], check=True)
    subprocess.run(['systemctl', '--user', 'enable', '--now', _SYSTEMD_UNIT], check=True)

    log.info('Service installed and started.')
    log.info('  Unit  : %s', unit_path)
    log.info('  Status: systemctl --user status %s', _SYSTEMD_UNIT)
    log.info('  Logs  : journalctl --user -u %s -f', _SYSTEMD_UNIT)
    log.info('  Stop  : systemctl --user disable --now %s', _SYSTEMD_UNIT)


def _uninstall_service() -> None:
    """Stop and remove the installed service."""
    import platform as _platform
    system = _platform.system()

    if system == 'Darwin':
        plist_path = Path.home() / 'Library' / 'LaunchAgents' / f'{_LAUNCHD_LABEL}.plist'
        if plist_path.exists():
            subprocess.run(['launchctl', 'unload', str(plist_path)], capture_output=True)
            plist_path.unlink()
            log.info('Service removed: %s', plist_path)
        else:
            log.info('No service found at %s', plist_path)

    elif system == 'Linux':
        unit_path = Path.home() / '.config' / 'systemd' / 'user' / f'{_SYSTEMD_UNIT}.service'
        subprocess.run(['systemctl', '--user', 'disable', '--now', _SYSTEMD_UNIT],
                       capture_output=True)
        if unit_path.exists():
            unit_path.unlink()
        subprocess.run(['systemctl', '--user', 'daemon-reload'], capture_output=True)
        log.info('Service removed.')
    else:
        log.error('Service uninstall not supported on %s', system)
        sys.exit(1)


def main() -> None:
    _set_process_name()
    ap = argparse.ArgumentParser(
        description='M.A.R.K. Sentinel Agent',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument('--config',    type=Path, help='Config file (default: agent_config.json)')
    ap.add_argument('--server',    help='Central server URL (e.g. http://10.0.1.50:7331)')
    ap.add_argument('--token',     help='Agent auth token (overrides SENTINEL_AGENT_TOKEN env)')
    ap.add_argument('--target',    default=None, help='Scan target directory (default: .)')
    ap.add_argument('--profile',   default=None, help='Audit profile (default: default)')
    ap.add_argument('--scan-only', action='store_true', help='Run scan but do not report to server')
    ap.add_argument('--daemon',    action='store_true', help='Run on a repeating schedule')
    ap.add_argument('--interval',  type=int, default=None,
                    help='Seconds between daemon scans (default: 3600)')
    ap.add_argument('--once',      action='store_true',
                    help='Run one scan and exit (default without --daemon)')
    ap.add_argument('--install-service',   action='store_true',
                    help='Install as a background launchd service (macOS) or systemd unit (Linux)')
    ap.add_argument('--uninstall-service', action='store_true',
                    help='Remove the installed background service')
    args = ap.parse_args()

    cfg = load_config(args.config)

    if args.server:     cfg['server']   = args.server
    if args.token:      cfg['token']    = args.token
    if args.target:     cfg['target']   = args.target
    if args.profile:    cfg['profile']  = args.profile
    if args.scan_only:  cfg.pop('server', None)
    if args.interval:   cfg['interval'] = args.interval

    if args.install_service:
        _install_service(args, cfg)
        return
    if args.uninstall_service:
        _uninstall_service()
        return

    interval = cfg.get('interval', 3600)
    RETRY_INTERVAL = 300  # retry failed deliveries every 5 minutes

    if args.daemon:
        POLL_INTERVAL = 30  # seconds between command polls
        device_id = _device_id()
        log.info('Daemon mode — scan interval %ds, command poll every %ds', interval, POLL_INTERVAL)
        last_scan = 0.0
        last_success = 0.0
        while True:
            now = time.time()
            # Run full scan when interval has elapsed OR retry a failed delivery every 5 min
            due = (now - last_scan >= interval) or (last_success < last_scan and now - last_scan >= RETRY_INTERVAL)
            if due:
                try:
                    ok = run_cycle(cfg)
                except Exception as e:
                    log.error('Unhandled error in scan cycle: %s', e)
                    ok = False
                last_scan = time.time()
                if ok:
                    last_success = last_scan

            # Poll for on-demand command
            cmd = poll_for_command(cfg, device_id)
            if cmd == 'scan_now':
                log.info('On-demand scan triggered by server')
                try:
                    ok = run_cycle(cfg)
                except Exception as e:
                    log.error('Unhandled error in on-demand scan: %s', e)
                    ok = False
                last_scan = time.time()
                if ok:
                    last_success = last_scan

            time.sleep(POLL_INTERVAL)
    else:
        ok = run_cycle(cfg)
        sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
