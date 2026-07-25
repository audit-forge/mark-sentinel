# HASH_SIEM_P05 — Exabeam Connector (CEF/Syslog)

## File to modify
`connectors/siem_connector.py` — class `ExabeamConnector`

## What to implement

### `send(self, finding: ArckonFinding) -> tuple[bool, str]`
Identical implementation to `QRadarConnector.send()` — same CEF/syslog approach.
Default protocol is UDP (Exabeam's Universal CEF parser expects UDP by default).

Reuse `finding.to_cef()` for the CEF string.
Syslog envelope format: same as HASH_SIEM_P03.

Return `(True, "sent via {protocol}")` on success.

### `test(self) -> tuple[bool, str]`
Send a minimal CEF test message (same as QRadar test).
Return `(True, "Exabeam syslog reachable at {host}:{port}")` on success.

## Config keys
```
syslog_host  str   Exabeam syslog listener hostname or IP
syslog_port  int   default 514
protocol     str   'udp' or 'tcp', default 'udp'
```

## Notes
- This connector is intentionally a thin wrapper over the QRadar syslog logic
- The CEF string from `to_cef()` is compatible with Exabeam's Universal CEF parser out of the box
- No additional Exabeam-specific formatting required
- Consider extracting shared syslog send logic into a `_send_syslog(host, port, protocol, message)` helper used by both QRadar and Exabeam connectors
