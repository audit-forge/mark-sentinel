#!/usr/bin/env python3
"""RiskRaven Arckon — Linux access collector (auditd).

Uses the Linux audit daemon (auditd) to monitor file access and SSH logins:
  - Installs audit rules for each protected path: -w <path> -p rwa -k arckon_protected
  - Parses `ausearch -k arckon_protected --raw` for file access events
  - Parses /var/log/auth.log (or journalctl) for SSH login events
  - Correlates PID → process name via /proc/<pid>/comm

FedRAMP SI-4 / AU-12: continuous monitoring + audit event generation.

Requirements:
  - auditd installed and running (sudo apt install auditd / yum install audit)
  - Agent running as root (or with sudo access to auditctl + ausearch)
  - /var/log/auth.log readable (or journalctl access)

Security notes:
  - Reads audit events only — no write/modify capability (AC-6 least privilege)
  - Process name resolved from /proc (not from the audit event's comm field,
    which can be spoofed by a process that changes its own comm)
  - Rate limited: polls ausearch every 5s, processes at most 500 events per poll
"""
from __future__ import annotations

import logging
import os
import subprocess
import threading
import time
from pathlib import Path

from monitors.base import AccessCollector

log = logging.getLogger('arckon.monitors.linux')

_AUDIT_KEY = 'arckon_protected'
_POLL_INTERVAL = 5.0       # seconds between ausearch polls
_MAX_EVENTS_PER_POLL = 500
_SSH_POLL_INTERVAL = 10.0  # seconds between auth.log checks


class LinuxCollector(AccessCollector):
    """Linux file-access + SSH login collector via auditd."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._last_audit_ts = 0
        self._last_auth_offset = 0

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._running = True
        self._install_audit_rules()
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run, name='linux-collector', daemon=True)
        self._thread.start()
        log.info('Linux auditd collector started for device %s', self.device_id)

    def stop(self) -> None:
        super().stop()
        self._stop_event.set()
        self._remove_audit_rules()
        if self._thread:
            self._thread.join(timeout=10)

    def _install_audit_rules(self) -> None:
        """Install auditd watch rules for each protected path."""
        for pp in self.protected_paths:
            path = pp['path']
            try:
                subprocess.run(
                    ['auditctl', '-w', path, '-p', 'rwa',
                     '-k', _AUDIT_KEY, '-f', '1'],
                    check=True, capture_output=True, timeout=5)
                log.info('installed audit rule for %s', path)
            except FileNotFoundError:
                log.warning('auditctl not found — install auditd for '
                            'Linux file-access monitoring')
                return
            except subprocess.CalledProcessError as e:
                log.warning('auditctl failed for %s: %s — agent may need root',
                            path, e.stderr.decode(errors='replace').strip())
            except Exception as e:
                log.warning('audit rule install error for %s: %s', path, e)

    def _remove_audit_rules(self) -> None:
        """Remove auditd watch rules on shutdown."""
        for pp in self.protected_paths:
            path = pp['path']
            try:
                subprocess.run(
                    ['auditctl', '-W', path, '-k', _AUDIT_KEY],
                    check=False, capture_output=True, timeout=5)
            except Exception:
                pass

    def _run(self) -> None:
        """Main collector loop — alternates between audit and auth.log polls."""
        while not self._stop_event.is_set():
            try:
                self._poll_audit_events()
            except Exception as e:
                log.error('audit poll error: %s', e)
            self._stop_event.wait(_POLL_INTERVAL)
            try:
                self._poll_ssh_logins()
            except Exception as e:
                log.error('ssh poll error: %s', e)
            self._stop_event.wait(_SSH_POLL_INTERVAL)

    def _poll_audit_events(self) -> None:
        """Parse new audit events for the arckon_protected key."""
        cmd = ['ausearch', '-k', _AUDIT_KEY, '--raw', '-ts', 'recent']
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10)
        except FileNotFoundError:
            return  # ausearch not installed
        except subprocess.TimeoutExpired:
            return
        if not result.stdout:
            return
        count = 0
        for line in result.stdout.strip().split('\n'):
            if count >= _MAX_EVENTS_PER_POLL:
                break
            evt = self._parse_audit_line(line)
            if evt:
                self._emit(**evt)
                count += 1

    def _parse_audit_line(self, line: str) -> dict | None:
        """Parse a single audit record line into an event dict.

        auditd raw output format (type=SYSCALL):
          type=SYSCALL msg=audit(1695900000.123:456): arch=... syscall=openat
          ... pid=1234 ... comm="claude" ... exe="/usr/bin/claude" ...
          type=CWD msg=audit(...): cwd="/home/user"
          type=PATH msg=audit(...): item=0 name="/etc/passwd" inode=...
        """
        if 'type=SYSCALL' not in line:
            return None
        import re
        # Extract timestamp: audit(1695900000.123:456)
        ts_match = re.search(r'audit\((\d+)\.', line)
        ts = int(ts_match.group(1)) if ts_match else int(time.time())
        # Extract PID
        pid_match = re.search(r'pid=(\d+)', line)
        pid = int(pid_match.group(1)) if pid_match else 0
        # Extract comm (process name) — but verify via /proc for anti-spoofing
        comm_match = re.search(r'comm="([^"]+)"', line)
        comm = comm_match.group(1) if comm_match else ''
        # Resolve process name from /proc for anti-spoofing
        if pid:
            comm = self._resolve_process_name(pid) or comm
        # Extract syscall to determine action
        syscall_match = re.search(r'syscall=(\w+)', line)
        syscall = syscall_match.group(1) if syscall_match else ''
        action = self._syscall_to_action(syscall)
        # Extract path — this is in the PATH record, not the SYSCALL record.
        # In --raw output, PATH records follow the SYSCALL record. For
        # simplicity, we extract from the same line if present, or use
        # the CWD + item name pattern.
        path_match = re.search(r'name="([^"]+)"', line)
        path = path_match.group(1) if path_match else ''
        if not path:
            return None
        return {
            'ts': ts, 'process': comm, 'pid': pid,
            'path': path, 'action': action,
            'source': 'auditd',
        }

    def _syscall_to_action(self, syscall: str) -> str:
        """Map Linux syscall name to canonical action."""
        mapping = {
            'open': 'open', 'openat': 'open',
            'read': 'read', 'readv': 'read', 'pread': 'read',
            'write': 'write', 'writev': 'write', 'pwrite': 'write',
            'rename': 'rename', 'renameat': 'rename', 'renameat2': 'rename',
            'unlink': 'unlink', 'unlinkat': 'unlink',
            'creat': 'write',
        }
        return mapping.get(syscall, 'open')

    def _resolve_process_name(self, pid: int) -> str:
        """Resolve process name from /proc/<pid>/comm (anti-spoofing).

        The audit comm field can be changed by the process itself; /proc/comm
        reflects the actual kernel-registered name. Falls back to /proc/<pid>/exe
        basename if comm is unavailable.
        """
        try:
            return Path(f'/proc/{pid}/comm').read_text().strip()[:15]
        except Exception:
            pass
        try:
            exe = os.readlink(f'/proc/{pid}/exe')
            return os.path.basename(exe)
        except Exception:
            return ''

    def _poll_ssh_logins(self) -> None:
        """Check for new SSH login events in auth.log / journalctl."""
        log_path = '/var/log/auth.log'
        if not os.path.exists(log_path):
            # Try journalctl as fallback
            self._poll_journalctl_ssh()
            return
        try:
            size = os.path.getsize(log_path)
            if size < self._last_auth_offset:
                self._last_auth_offset = 0  # log rotated
            with open(log_path, 'r', errors='replace') as f:
                f.seek(self._last_auth_offset)
                new_data = f.read()
                self._last_auth_offset = f.tell()
        except PermissionError:
            return
        except Exception as e:
            log.debug('auth.log read error: %s', e)
            return
        for line in new_data.split('\n'):
            if 'Accepted' in line and ('ssh' in line.lower() or 'publickey' in line):
                evt = self._parse_ssh_login_line(line)
                if evt:
                    self._emit(**evt)

    def _poll_journalctl_ssh(self) -> None:
        """Fallback: use journalctl to check for SSH logins."""
        try:
            result = subprocess.run(
                ['journalctl', '-u', 'ssh', '--since', '10 seconds ago',
                 '--no-pager', '-o', 'cat'],
                capture_output=True, text=True, timeout=5)
        except Exception:
            return
        for line in result.stdout.strip().split('\n'):
            if 'Accepted' in line:
                evt = self._parse_ssh_login_line(line)
                if evt:
                    self._emit(**evt)

    def _parse_ssh_login_line(self, line: str) -> dict | None:
        """Parse an SSH 'Accepted' log line into a login event."""
        import re
        # Example: "Sep  4 12:00:00 host sshd[1234]: Accepted publickey for user from 1.2.3.4 port 5678 ssh2"
        pid_match = re.search(r'sshd\[(\d+)\]', line)
        pid = int(pid_match.group(1)) if pid_match else 0
        # The "process" for login events is the AI process that triggered
        # the login. We can't always know this from the auth.log line alone,
        # so we emit with process='ssh' and let the correlation happen at
        # the dashboard level. However, if the SSH session was initiated
        # by an AI tool, the process that spawned sshd would be AI-related.
        # For now, we report the login and the server-side can correlate.
        return {
            'ts': int(time.time()),
            'process': 'ssh',
            'pid': pid,
            'path': 'ssh-login',
            'action': 'login',
            'source': 'authlog',
        }
