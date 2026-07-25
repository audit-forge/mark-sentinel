# HASH_SIEM_P03 — IBM QRadar Connector (CEF/Syslog)

## File to modify
`connectors/siem_connector.py` — class `QRadarConnector`

## What to implement

### `send(self, finding: ArckonFinding) -> tuple[bool, str]`
Send one finding as a CEF syslog message.

1. Build the CEF string: `finding.to_cef()` — already returns correct CEF format
2. Wrap in syslog envelope:
   ```
   <{priority}>{timestamp} {hostname} Arckon: {cef_string}\n
   ```
   Where priority = `(1 * 8) + 5` (user facility, notice severity = 13)
   Timestamp = `time.strftime('%b %d %H:%M:%S')`
   Hostname = `socket.gethostname()`

3. Send via TCP or UDP based on `cfg.get('protocol', 'tcp')`:
   - TCP: `socket.SOCK_STREAM`, connect, sendall, close
   - UDP: `socket.SOCK_DGRAM`, sendto

4. Return `(True, "sent via {protocol}")` on success, `(False, str(e))` on error.

### `test(self) -> tuple[bool, str]`
Send a minimal test CEF message:
```
CEF:0|RiskRaven|Arckon|1.0|TEST|Arckon Connectivity Test|1|msg=test
```
Return `(True, "QRadar syslog reachable at {host}:{port}")` on success.

## Config keys
```
syslog_host  str   QRadar syslog receiver hostname or IP
syslog_port  int   default 514
protocol     str   'tcp' or 'udp', default 'tcp'
```

## Notes
- CEF string already built by `ArckonFinding.to_cef()` — do not rebuild it
- TCP syslog: connect with 5s timeout, send, close immediately
- UDP syslog: max message size 1024 bytes — truncate if longer
- QRadar DSM XML for parsing is a separate task (not needed for basic ingestion)
