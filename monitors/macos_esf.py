#!/usr/bin/env python3
"""RiskRaven Arckon — macOS Endpoint Security collector bridge.

The native Swift ES daemon (arckon-es-collector, signed with the
com.apple.developer.endpoint-security.client entitlement) streams
newline-delimited JSON file-access + login events over a Unix domain socket.
This module is the Python consumer that:
  - Binds the Unix socket (0600 — only this user + root may connect)
  - Reads events from the ES daemon
  - Correlates against AI process names + protected paths
  - Queues events for the agent to report to the server

Architecture (same proven pattern as Pharaoh ESF):
  - Python agent (consumer) binds/listens; root ES daemon connects
  - A root process CAN connect to a user-owned 0600 socket, so non-root
    users can't inject forged events (security boundary)
  - If the ES daemon isn't installed, the agent works normally — purely
    additive. On non-macOS the caller never starts this.

FedRAMP SI-4 / AU-12: kernel-level monitoring with signed daemon.

Event schema from ES daemon (NDJSON, one per line):
  {"type":"file_access","timestamp":"...","process_name":"claude",
   "process_path":"/usr/local/bin/claude","process_id":1234,
   "path":"/Users/keith/secrets.pem","action":"read",
   "signing_id":"com.anthropic.claude","team_id":"XYZ","uid":501}
  {"type":"login","timestamp":"...","process_name":"sshd",
   "process_id":5678,"action":"login","uid":0}
"""
from __future__ import annotations

import json
import logging
import os
import socket
import threading
from monitors.base import AccessCollector

log = logging.getLogger('arckon.monitors.macos_esf')

DEFAULT_SOCKET = '/var/run/arckon-es-collector.sock'
_MAX_QUEUED = 5000


class MacOSESCollector(AccessCollector):
    """macOS Endpoint Security collector — reads from the Swift ES daemon."""

    def __init__(self, *args, socket_path: str | None = None, **kwargs):
        super().__init__(*args, **kwargs)
        self.socket_path = socket_path or os.environ.get(
            'ARCKON_ES_SOCKET', DEFAULT_SOCKET)
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._sock: socket.socket | None = None
        self._es_proc = None  # child ES daemon if we started it directly

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._running = True
        try:
            self._bind_socket()
        except OSError as e:
            log.warning('ES collector could not bind %s: %s — '
                        'real-time file monitoring disabled',
                        self.socket_path, e)
            return
        self._ensure_es_daemon()
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._serve, name='macos-es-collector', daemon=True)
        self._thread.start()
        log.info('macOS ES collector listening on %s', self.socket_path)

    def _ensure_es_daemon(self) -> None:
        """Ensure the native ES helper daemon is running.

        The daemon is normally managed by a LaunchDaemon
        (ai.mfdynamics.arckon-es-collector). If that daemon is dead (e.g.
        launchd penalty-box after a pre-FDA crash, or the plist was never
        installed), we start it directly as a root child process so
        monitoring works without manual intervention. We also re-check
        periodically via _watchdog so a daemon that dies later is revived.
        """
        import subprocess
        import shutil
        daemon_path = '/Library/Arckon/ArckonESCollector.app/Contents/MacOS/arckon-es-collector'
        if not os.path.exists(daemon_path):
            log.warning('ES helper not installed at %s — Protected Files '
                        'monitoring disabled on macOS. Install the '
                        'ArckonESCollector.pkg.', daemon_path)
            return
        # Already running? (launchd-managed or our own child)
        if self._is_daemon_running():
            return
        # Try to load the LaunchDaemon first (the proper, durable way)
        plist = '/Library/LaunchDaemons/ai.mfdynamics.arckon-es-collector.plist'
        if os.path.exists(plist):
            subprocess.run(
                ['launchctl', 'bootstrap', 'system', plist],
                capture_output=True, timeout=10)
            import time
            time.sleep(2)
            if self._is_daemon_running():
                log.info('ES daemon started via LaunchDaemon')
                return
        # Fallback: start it directly as a child process. We inherit the
        # agent's root privileges. If FDA isn't granted yet, the daemon
        # now sleeps-and-retries internally (see arckon-es-collector.swift),
        # so this child stays alive and auto-recovers once FDA is granted.
        try:
            env = os.environ.copy()
            env['ARCKON_ES_SOCKET'] = self.socket_path
            proc = subprocess.Popen(
                [daemon_path],
                stdout=open('/var/log/arckon-es-collector.log', 'a'),
                stderr=subprocess.STDOUT,
                env=env, start_new_session=True)
            self._es_proc = proc
            log.info('ES daemon started directly (pid %s) — LaunchDaemon '
                     'not running', proc.pid)
        except Exception as e:
            log.warning('Could not start ES daemon: %s — Protected Files '
                        'monitoring disabled', e)

    @staticmethod
    def _is_daemon_running() -> bool:
        import subprocess
        try:
            r = subprocess.run(
                ['pgrep', '-f', 'arckon-es-collector'],
                capture_output=True, timeout=5)
            return r.returncode == 0 and r.stdout.strip()
        except Exception:
            return False

    def stop(self) -> None:
        super().stop()
        self._stop_event.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        try:
            os.unlink(self.socket_path)
        except FileNotFoundError:
            pass
        if self._thread:
            self._thread.join(timeout=5)

    def _bind_socket(self) -> None:
        """Bind the Unix domain socket with 0600 permissions."""
        try:
            os.unlink(self.socket_path)
        except FileNotFoundError:
            pass
        os.makedirs(os.path.dirname(self.socket_path), exist_ok=True)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind(self.socket_path)
        os.chmod(self.socket_path, 0o600)
        s.listen(1)
        s.settimeout(1.0)
        self._sock = s

    def _serve(self) -> None:
        """Accept connections from the ES daemon and read events."""
        assert self._sock is not None
        while not self._stop_event.is_set():
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            log.info('ES daemon connected')
            with conn:
                self._read_conn(conn)
            log.info('ES daemon disconnected — awaiting reconnect')

    def _read_conn(self, conn: socket.socket) -> None:
        """Read NDJSON events from the ES daemon connection."""
        conn.settimeout(1.0)
        buf = b''
        while not self._stop_event.is_set():
            try:
                chunk = conn.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                return
            if not chunk:
                return  # peer closed
            buf += chunk
            *lines, buf = buf.split(b'\n')
            for line in lines:
                self._process_line(line)

    def _process_line(self, line: bytes) -> None:
        """Parse and process a single NDJSON event from the ES daemon."""
        line = line.strip()
        if not line:
            return
        try:
            evt = json.loads(line)
        except (ValueError, UnicodeDecodeError):
            return
        if not isinstance(evt, dict):
            return
        evt_type = evt.get('type')
        process = evt.get('process_name', '')
        pid = int(evt.get('process_id', 0) or 0)
        ts = self._parse_timestamp(evt.get('timestamp', ''))
        if evt_type == 'file_access':
            path = evt.get('path', '')
            action = evt.get('action', 'open')
            self._emit(ts=ts, process=process, pid=pid,
                       path=path, action=action, source='esf')
        elif evt_type == 'login':
            self._emit(ts=ts, process=process or 'sshd', pid=pid,
                       path='macos-login', action='login', source='esf')

    def _parse_timestamp(self, ts: str) -> int:
        """Parse ISO 8601 timestamp to epoch seconds."""
        import datetime
        try:
            dt = datetime.datetime.fromisoformat(
                ts.replace('Z', '+00:00'))
            return int(dt.timestamp())
        except Exception:
            import time
            return int(time.time())
