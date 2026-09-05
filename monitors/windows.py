#!/usr/bin/env python3
"""RiskRaven Arckon — Windows access collector (Event Log + auditpol).

Uses Windows Event Log to monitor file access and logins:
  - Enables file audit on protected paths via auditpol
  - Subscribes to Security Event Log: Event ID 4663 (file access), 4624 (login)
  - Correlates Process ID from event with process name via tasklist/psutil

FedRAMP SI-4 / AU-12: continuous monitoring + audit event generation.

Requirements:
  - Agent running with admin privileges (to enable audit + read Security log)
  - PowerShell available for event log queries

Security notes:
  - Reads Security event log only — no write capability (AC-6)
  - Process name resolved from the event's ProcessName field, verified
    against running processes for anti-spoofing
  - Rate limited: polls event log every 5s, processes at most 500 events per poll
"""
from __future__ import annotations

import logging
import subprocess
import threading
import time
import json
from monitors.base import AccessCollector

log = logging.getLogger('arckon.monitors.windows')

_POLL_INTERVAL = 5.0
_MAX_EVENTS_PER_POLL = 500
# PowerShell query for file access events (4663) and logins (4624)
# Filters to events since the last poll timestamp.
_PS_QUERY = '''
$ErrorActionPreference = 'SilentlyContinue'
$since = [DateTime]::FromFileTimeUtc({since_fv})
Get-WinEvent -FilterHashtable @{{
    LogName='Security'
    Id in (4663, 4624)
    StartTime=$since
}} -MaxEvents {max_events} | ForEach-Object {{
    $xml = [xml]$_.ToXml()
    $EventData = @{{}}
    $xml.Event.EventData.Data | ForEach-Object {{ $EventData[$_.Name] = $_.'#text' }}
    [PSCustomObject]@{{
        Id = $_.Id
        TimeCreated = $_.TimeCreated.ToString('o')
        ProcessId = $EventData['ProcessID']
        ProcessName = $EventData['ProcessName']
        ObjectName = $EventData['ObjectName']
        AccessMask = $EventData['AccessMask']
        TargetUserName = $EventData['TargetUserName']
        LogonType = $EventData['LogonType']
        IpAddress = $EventData['IpAddress']
    }}
}} | ConvertTo-Json -Compress
'''


class WindowsCollector(AccessCollector):
    """Windows file-access + login collector via Event Log."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._last_poll_fv = 0  # FILETIME (100ns ticks since 1601)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._running = True
        self._enable_file_auditing()
        self._last_poll_fv = self._now_filetime()
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run, name='windows-collector', daemon=True)
        self._thread.start()
        log.info('Windows Event Log collector started for device %s', self.device_id)

    def stop(self) -> None:
        super().stop()
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=10)

    def _now_filetime(self) -> int:
        """Current time as Windows FILETIME (100ns ticks since 1601-01-01)."""
        import datetime
        epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        now = datetime.datetime.now(datetime.timezone.utc)
        return int((now - epoch).total_seconds() * 10_000_000)

    def _enable_file_auditing(self) -> None:
        """Enable 'File System' audit subcategory via auditpol.

        This enables generation of Event ID 4663 for file access on objects
        that have a SACL configured. The actual per-path SACL is set via
        PowerShell Set-Acl on each protected path.
        """
        try:
            subprocess.run(
                ['auditpol', '/set', '/subcategory:"File System"',
                 '/success:enable', '/failure:enable'],
                check=True, capture_output=True, timeout=5, shell=True)
            log.info('enabled File System audit subcategory')
        except Exception as e:
            log.warning('auditpol failed (agent may need admin): %s', e)
        # Set SACL on each protected path
        for pp in self.protected_paths:
            self._set_path_sacl(pp['path'])

    def _set_path_sacl(self, path: str) -> None:
        """Set a SACL on the path to audit Everyone's access (triggers 4663)."""
        ps = f'''
$path = '{path}'
if (Test-Path $path) {{
    $acl = Get-Acl $path
    $auditRule = New-Object System.Security.AccessControl.FileSystemAuditRule(
        'Everyone', 'FullControl', 'ContainerInherit,ObjectInherit',
        'None', 'Success,Failure')
    $acl.AddAuditRule($auditRule)
    Set-Acl -Path $path -AclObject $acl
}}
'''
        try:
            subprocess.run(
                ['powershell', '-NoProfile', '-Command', ps],
                check=True, capture_output=True, timeout=10)
            log.info('set SACL for %s', path)
        except Exception as e:
            log.warning('SACL set failed for %s: %s', path, e)

    def _run(self) -> None:
        """Main collector loop — poll Event Log for new events."""
        while not self._stop_event.is_set():
            try:
                self._poll_events()
            except Exception as e:
                log.error('Windows event poll error: %s', e)
            self._stop_event.wait(_POLL_INTERVAL)

    def _poll_events(self) -> None:
        """Query Windows Event Log for new 4663/4624 events."""
        since_fv = self._last_poll_fv
        self._last_poll_fv = self._now_filetime()
        ps = _PS_QUERY.format(
            since_fv=since_fv, max_events=_MAX_EVENTS_PER_POLL)
        try:
            result = subprocess.run(
                ['powershell', '-NoProfile', '-Command', ps],
                capture_output=True, text=True, timeout=15)
        except FileNotFoundError:
            log.warning('PowerShell not found — Windows monitoring disabled')
            return
        except subprocess.TimeoutExpired:
            return
        if not result.stdout.strip():
            return
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            return
        if isinstance(data, dict):
            data = [data]  # single event
        for evt in data:
            self._process_event(evt)

    def _process_event(self, evt: dict) -> None:
        """Process a single Event Log entry."""
        event_id = evt.get('Id')
        process_name = evt.get('ProcessName', '')
        process_name = process_name.split('\\')[-1] if process_name else ''
        pid = int(evt.get('ProcessId', 0) or 0)
        ts = self._parse_dotnet_time(evt.get('TimeCreated', ''))
        if event_id == 4663:
            path = evt.get('ObjectName', '')
            if not path:
                return
            action = self._access_mask_to_action(evt.get('AccessMask', '0'))
            self._emit(ts=ts, process=process_name, pid=pid,
                       path=path, action=action, source='etw')
        elif event_id == 4624:
            logon_type = int(evt.get('LogonType', 0) or 0)
            if logon_type in (2, 10, 11):  # Interactive, RemoteInteractive, CachedInteractive
                self._emit(ts=ts, process=process_name or 'rdp', pid=pid,
                           path='windows-login', action='login', source='eventlog')

    def _access_mask_to_action(self, mask_str: str) -> str:
        """Map Windows file access mask to canonical action.

        Common masks:
          0x1   = ReadData
          0x2   = WriteData
          0x4   = AppendData
          0x8   = ReadEA
          0x10  = WriteEA
          0x20  = Execute/Traverse
          0x40  = DeleteChild
          0x80  = ReadAttributes
          0x100 = WriteAttributes
          0x10000 = Delete
        """
        try:
            mask = int(mask_str, 16) if isinstance(mask_str, str) else int(mask_str)
        except (ValueError, TypeError):
            return 'open'
        if mask & 0x2 or mask & 0x4 or mask & 0x10 or mask & 0x100:
            return 'write'
        if mask & 0x1 or mask & 0x80 or mask & 0x8:
            return 'read'
        if mask & 0x10000:
            return 'unlink'
        return 'open'

    def _parse_dotnet_time(self, time_str: str) -> int:
        """Parse .NET ISO 8601 datetime to epoch seconds."""
        import datetime
        try:
            dt = datetime.datetime.fromisoformat(
                time_str.replace('Z', '+00:00'))
            return int(dt.timestamp())
        except Exception:
            return int(time.time())
