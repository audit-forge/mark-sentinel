#!/usr/bin/env python3
"""
M.A.R.K. Sentinel Agent — distributed device scanner

Runs local AI security checks on a schedule and reports results to a
central Sentinel server. Designed to be installed as a system service
(systemd, launchd, Windows Service, Intune) on every device you want
to audit.

Usage:
  python3 agent.py --server http://10.0.1.50:7331 --token <tok>
  python3 agent.py --daemon --interval 7200
  python3 agent.py --config /etc/sentinel/agent_config.json --once
  python3 agent.py --scan-only          # local scan, no reporting

Config file (agent_config.json):
  {
    "server":   "http://10.0.1.50:7331",
    "token":    "your-secret-token",
    "target":   ".",
    "profile":  "default",
    "interval": 7200
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
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

import argparse
import hashlib
import io
import json
import logging
import os
import platform
import socket
import subprocess
import tarfile
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

def _hardware_seed() -> str:
    """Return a stable platform hardware identifier that survives network changes."""
    # macOS: IOPlatformUUID — motherboard UUID, never changes
    if sys.platform == 'darwin':
        try:
            out = subprocess.run(
                ['ioreg', '-rd1', '-c', 'IOPlatformExpertDevice'],
                capture_output=True, text=True, timeout=5,
            ).stdout
            for line in out.splitlines():
                if 'IOPlatformUUID' in line and '=' in line:
                    val = line.split('=', 1)[1].strip().strip('"')
                    if val:
                        return val
        except Exception:
            pass

    # Windows: MachineGuid from registry (written at OS install, stable)
    if sys.platform == 'win32':
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                 r'SOFTWARE\Microsoft\Cryptography')
            guid, _ = winreg.QueryValueEx(key, 'MachineGuid')
            if guid:
                return guid
        except Exception:
            pass

    # Linux: /etc/machine-id (systemd, written at first boot)
    for mid_path in ('/etc/machine-id', '/var/lib/dbus/machine-id'):
        try:
            val = Path(mid_path).read_text().strip()
            if val:
                return val
        except OSError:
            pass

    # Fallback: MAC address (may change between interfaces — last resort)
    try:
        import uuid as _uuid
        node = _uuid.getnode()
        if not (node & (1 << 40)):
            return ':'.join(f'{(node >> i) & 0xff:02x}' for i in range(0, 48, 8))
    except Exception:
        pass
    return socket.gethostname()


def _device_id() -> str:
    """Stable 16-char hex ID. Persisted to disk so containers/VMs get a consistent ID."""
    # Explicit override for containers and K8s — set SENTINEL_DEVICE_ID to a stable
    # value (e.g. derived from pod name or container name) to avoid ID churn on restart.
    explicit = os.environ.get('SENTINEL_DEVICE_ID', '').strip()
    if explicit:
        return hashlib.sha256(explicit.encode()).hexdigest()[:16]

    id_file = ROOT / 'output' / '.device_id'
    if id_file.exists():
        try:
            stored = id_file.read_text().strip()
            if len(stored) == 16 and stored.isalnum():
                return stored
        except OSError:
            pass
    # SENTINEL_HOSTNAME lets K8s/containers pass a stable name (e.g. NODE_NAME)
    # into the hardware seed so the generated ID is deterministic even without a
    # persistent volume.
    seed_hint = os.environ.get('SENTINEL_HOSTNAME', '').strip()
    seed = f'{seed_hint}:{_hardware_seed()}' if seed_hint else _hardware_seed()
    new_id = hashlib.sha256(seed.encode()).hexdigest()[:16]
    try:
        id_file.parent.mkdir(parents=True, exist_ok=True)
        id_file.write_text(new_id)
    except OSError:
        pass
    return new_id


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
            cmd, capture_output=True, text=True, encoding='utf-8',
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

    # Find the first '{' — audit.py should only write JSON to stdout when --output json
    # is set, but guard against any stray preamble lines.
    json_start = stdout.find('{')
    if json_start > 0:
        log.debug('Stripping %d bytes of non-JSON preamble from audit stdout', json_start)
        stdout = stdout[json_start:]
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as e:
        log.error('Could not parse scan JSON (exit %d): %s\nOutput: %s\nStderr: %s',
                  proc.returncode, e, stdout[:300], (proc.stderr or '')[-200:])
        return None


# ── Reporting ──────────────────────────────────────────────────────────────────

def report_discovery(results: list, config: dict, device_id: str, hostname: str) -> bool:
    """POST subnet discovery results to the central server."""
    server = config.get('server', '').rstrip('/')
    if not server:
        return True
    token = config.get('token', '')
    payload = json.dumps({
        'device_id': device_id,
        'hostname':  hostname,
        'results':   results,
    }).encode()
    headers: dict[str, str] = {
        'Content-Type':   'application/json',
        'Content-Length': str(len(payload)),
        'User-Agent':     f'sentinel-agent/{VERSION}',
    }
    if token:
        headers['Authorization'] = f'Bearer {token}'
    url = f'{server}/api/agent/discovery'
    try:
        req = _urlreq.Request(url, data=payload, headers=headers, method='POST')
        with _urlreq.urlopen(req, timeout=30) as resp:
            if 200 <= resp.status < 300:
                log.info('Discovery report accepted (%d results)', len(results))
                return True
            log.warning('Discovery report: server returned HTTP %s', resp.status)
    except _urlerr.URLError as e:
        log.warning('Discovery report connection error: %s', e.reason)
    except Exception as e:
        log.warning('Discovery report error: %s', e)
    return False


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
                    try:
                        body = json.loads(resp.read())
                        warn = body.get('warning')
                        if warn:
                            log.warning('SERVER WARNING: %s', warn.get('message', warn))
                    except Exception:
                        pass
                    log.info('Report accepted (HTTP %s)', resp.status)
                    return True
                log.warning('Server returned HTTP %s (attempt %d/3)', resp.status, attempt)
        except _urlerr.HTTPError as e:
            if e.code == 429:
                log.warning('Rate limited by server — waiting 65s before retry')
                time.sleep(65)
                continue
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
            cmd = data.get('command')
            if cmd:
                log.info('Command received from server: %s', cmd)
            return cmd
    except _urlerr.HTTPError as e:
        log.warning('Command poll HTTP %s from %s', e.code, server)
        return None
    except _urlerr.URLError as e:
        log.warning('Command poll connection error: %s', e.reason)
        return None
    except Exception as e:
        log.warning('Command poll error: %s', e)
        return None


# ── Self-update ────────────────────────────────────────────────────────────────

def self_update(config: dict) -> bool:
    """Download bundle.tar.gz from the server and overwrite local files, then restart."""
    server = config.get('server', '').rstrip('/')
    if not server:
        log.error('self_update: no server configured')
        return False
    token = config.get('token', '')
    url = f'{server}/bundle.tar.gz'
    headers: dict[str, str] = {'User-Agent': f'sentinel-agent/{VERSION}'}
    if token:
        headers['Authorization'] = f'Bearer {token}'
    try:
        log.info('self_update: downloading bundle from %s', url)
        req = _urlreq.Request(url, headers=headers)
        with _urlreq.urlopen(req, timeout=60) as resp:
            expected_hash = resp.headers.get('X-Bundle-SHA256', '')
            data = resp.read()
        actual_hash = hashlib.sha256(data).hexdigest()
        if expected_hash and actual_hash != expected_hash:
            log.error('self_update: bundle hash mismatch (expected %s got %s)', expected_hash, actual_hash)
            return False
        with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as tar:
            for member in tar.getmembers():
                # strip leading 'sentinel/' prefix from archive paths
                parts = Path(member.name).parts
                if parts and parts[0] == 'sentinel':
                    rel = Path(*parts[1:]) if len(parts) > 1 else None
                else:
                    rel = Path(member.name)
                if rel is None or not member.isfile():
                    continue
                if (rel.is_absolute()
                        or any(p == '..' for p in rel.parts)
                        or member.issym()
                        or member.islnk()):
                    log.warning('self_update: skipping unsafe path %s', member.name)
                    continue
                dest = ROOT / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                with tar.extractfile(member) as src, open(dest, 'wb') as dst:
                    dst.write(src.read())
        log.info('self_update: bundle extracted — restarting')
        os.execv(sys.executable, [sys.executable] + sys.argv)
    except Exception as e:
        log.error('self_update failed: %s', e)
        return False


# ── Main scan cycle ────────────────────────────────────────────────────────────

def run_cycle(config: dict) -> bool:
    target      = config.get('target', '.')
    profile_raw = config.get('profile', 'default')
    profile     = profile_raw.split(',')[0].strip() or 'default'
    device_id   = _device_id()
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
    if cfg.get('server'):
        cmd += ['--server', cfg['server']]
    if cfg.get('token'):
        cmd += ['--token', cfg['token']]
    if cfg.get('target'):
        cmd += ['--target', cfg['target']]
    if cfg.get('profile'):
        cmd += ['--profile', cfg['profile']]
    if cfg.get('interval'):
        cmd += ['--interval', str(cfg['interval'])]

    if system == 'Darwin':
        _install_launchd(cmd)
    elif system == 'Linux':
        _install_systemd(cmd)
    elif system == 'Windows':
        _install_windows_task(cmd)
    else:
        log.error('Service install not supported on %s — run with --daemon manually.', system)
        sys.exit(1)


def _install_windows_task(cmd: list[str]) -> None:
    """Register the agent as a Windows Task Scheduler task that starts at logon."""
    task_name = 'SentinelAgent'
    log_dir   = ROOT / 'logs'
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file  = log_dir / 'agent.log'

    # .bat launcher — redirects stdout+stderr to the log file
    bat_path = ROOT / 'start_agent.bat'
    bat_lines = [
        '@echo off',
        f'cd /d "{ROOT}"',
        ' '.join(f'"{c}"' if ' ' in c else c for c in cmd) + f' >> "{log_file}" 2>&1',
    ]
    bat_path.write_text('\r\n'.join(bat_lines) + '\r\n', encoding='utf-8')

    # VBScript wrapper — runs the bat with window style 0 (completely hidden)
    vbs_path = ROOT / 'run_agent_hidden.vbs'
    vbs_path.write_text(
        f'Set sh = CreateObject("WScript.Shell")\r\n'
        f'sh.Run """{ bat_path }""", 0, False\r\n',
        encoding='utf-8',
    )

    # Delete any existing task before recreating
    subprocess.run(['schtasks', '/delete', '/f', '/tn', task_name],
                   capture_output=True)

    result = subprocess.run([
        'schtasks', '/create', '/f',
        '/tn', task_name,
        '/tr', f'wscript.exe "{vbs_path}"',
        '/sc', 'onlogon',
        '/rl', 'highest',
        '/delay', '0000:30',
    ], capture_output=True, text=True)

    if result.returncode != 0:
        log.error('Task Scheduler registration failed:\n%s',
                  result.stderr.strip() or result.stdout.strip())
        sys.exit(1)

    subprocess.run(['schtasks', '/run', '/tn', task_name], capture_output=True)

    log.info('Service installed and started (hidden).')
    log.info('  Task  : %s (Task Scheduler)', task_name)
    log.info('  Logs  : %s', log_file)
    log.info('  Watch : Get-Content "%s" -Wait', log_file)
    log.info('  Stop  : schtasks /end /tn %s', task_name)
    log.info('  Remove: python agent.py --uninstall-service')


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
    elif system == 'Windows':
        subprocess.run(['schtasks', '/end',   '/tn', 'SentinelAgent'], capture_output=True)
        result = subprocess.run(['schtasks', '/delete', '/f', '/tn', 'SentinelAgent'],
                                capture_output=True, text=True)
        if result.returncode == 0:
            log.info('Task Scheduler task removed.')
        else:
            log.warning('Could not remove task (may not exist): %s', result.stderr.strip())
        for f in ('start_agent.bat', 'run_agent_hidden.vbs'):
            p = ROOT / f
            if p.exists():
                p.unlink()
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
                    help='Seconds between daemon scans (default: 7200)')
    ap.add_argument('--once',      action='store_true',
                    help='Run one scan and exit (default without --daemon)')
    ap.add_argument('--install-service',   action='store_true',
                    help='Install as a background launchd service (macOS) or systemd unit (Linux)')
    ap.add_argument('--uninstall-service', action='store_true',
                    help='Remove the installed background service')
    args = ap.parse_args()

    cfg = load_config(args.config)

    if args.server:
        cfg['server'] = args.server
    if args.token:
        cfg['token'] = args.token
    if args.target:
        cfg['target'] = args.target
    if args.profile:
        cfg['profile'] = args.profile
    if args.scan_only:
        cfg.pop('server', None)
    if args.interval:
        cfg['interval'] = args.interval

    if args.install_service:
        _install_service(args, cfg)
        return
    if args.uninstall_service:
        _uninstall_service()
        return

    interval = cfg.get('interval', 7200)
    RETRY_INTERVAL = 300  # retry failed deliveries every 5 minutes

    if args.daemon:
        import random as _random
        POLL_INTERVAL = 15    # seconds between command polls
        POLL_JITTER   = 5     # ±5 s per poll — agents drift apart over time
        SCAN_JITTER   = 120   # ±2 min per scan — prevents thundering herd on large fleets

        device_id = _device_id()
        hostname  = socket.gethostname()

        log.info('Daemon mode — scan interval %ds, poll every %ds', interval, POLL_INTERVAL)

        last_scan = 0.0
        last_success = 0.0
        while True:
            now = time.time()
            # Apply per-scan jitter so the effective interval drifts ± SCAN_JITTER
            effective_interval = interval + _random.uniform(-SCAN_JITTER, SCAN_JITTER)
            due = (now - last_scan >= effective_interval) or (last_success < last_scan and now - last_scan >= RETRY_INTERVAL)
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
            elif cmd and cmd.startswith('scan_profile:'):
                profile_override = cmd[len('scan_profile:'):]
                log.info('On-demand scan with profile override: %s', profile_override)
                saved_profile = cfg.get('profile', 'default')
                cfg['profile'] = profile_override
                try:
                    ok = run_cycle(cfg)
                except Exception as e:
                    log.error('Profile scan failed: %s', e)
                    ok = False
                finally:
                    cfg['profile'] = saved_profile
                last_scan = time.time()
                if ok:
                    last_success = last_scan
            elif cmd == 'discover_network':
                log.info('Network discovery triggered by server')
                try:
                    sys.path.insert(0, str(ROOT))
                    from discovery import discover, expand_subnets, _local_subnet_hosts
                    extra = cfg.get('extra_subnets', '').strip()
                    if extra:
                        seen: set[str] = set()
                        merged: list[str] = []
                        for h in _local_subnet_hosts() + expand_subnets(extra):
                            if h not in seen:
                                seen.add(h)
                                merged.append(h)
                        found = discover(hosts=merged)
                    else:
                        found = discover()
                    send_results = []
                    for r in found:
                        src = r.get('source', '')
                        if src == 'network_probe':
                            send_results.append({
                                'source':  'network',
                                'host':    r.get('host', ''),
                                'port':    r.get('port', 0),
                                'service': r.get('service', ''),
                                'models':  r.get('models', []),
                                'detail':  '',
                            })
                        elif src == 'env_var':
                            vendor_list = list(r.get('model_vendors', {}).keys())
                            vendor = vendor_list[0] if vendor_list else ''
                            send_results.append({
                                'source':  'cloud_api',
                                'host':    device_id,
                                'port':    0,
                                'service': r.get('service', ''),
                                'models':  r.get('models', []),
                                'detail':  f"{r.get('env_var','')}{' (' + vendor + ')' if vendor else ''}",
                            })
                        elif src == 'process_scan':
                            send_results.append({
                                'source':  'process',
                                'host':    device_id,
                                'port':    0,
                                'service': r.get('service', ''),
                                'models':  r.get('models', []),
                                'detail':  r.get('process_sig', ''),
                            })
                        elif src == 'docker_container':
                            c_ips = r.get('container_ips', [])
                            host = c_ips[0] if c_ips else device_id
                            port = r.get('port', 0)
                            send_results.append({
                                'source':  'docker',
                                'host':    host,
                                'port':    port,
                                'service': r.get('service', ''),
                                'models':  r.get('models', []),
                                'detail':  f"{r.get('container_name','')} ({r.get('container_image','')})",
                            })
                    report_discovery(send_results, cfg, device_id, hostname)
                except Exception as e:
                    log.error('Network discovery error: %s', e)
            elif cmd == 'update_self':
                log.info('Remote update triggered by server')
                self_update(cfg)
            elif cmd and cmd.startswith('set_config:'):
                try:
                    updates = json.loads(cmd[len('set_config:'):])
                    config_path = DEFAULT_CONFIG
                    existing = json.loads(config_path.read_text(encoding='utf-8')) if config_path.exists() else {}
                    existing.update({k: v for k, v in updates.items() if k in ('profile', 'interval', 'extra_subnets')})
                    config_path.write_text(json.dumps(existing, indent=2), encoding='utf-8')
                    if 'profile' in updates:
                        cfg['profile'] = updates['profile']
                    if 'extra_subnets' in updates:
                        cfg['extra_subnets'] = updates['extra_subnets']
                    if 'interval' in updates:
                        new_interval = int(updates['interval'])
                        if new_interval < 60:
                            raise ValueError(f'interval must be >= 60, got {new_interval}')
                        cfg['interval'] = new_interval
                        interval = cfg['interval']
                    log.info('Config updated by server: %s', updates)
                except Exception as e:
                    log.error('set_config failed: %s', e)

            # Per-poll jitter: each sleep varies slightly so agents don't re-sync
            time.sleep(POLL_INTERVAL + _random.uniform(-POLL_JITTER, POLL_JITTER))
    else:
        ok = run_cycle(cfg)
        sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
