# HASH_SIEM_P01 — Splunk HEC Connector

## File to modify
`connectors/siem_connector.py` — class `SplunkHECConnector`

## What to implement

### `send(self, finding: ArckonFinding) -> tuple[bool, str]`
POST one finding to Splunk HTTP Event Collector.

- URL: `{cfg['hec_url']}/services/collector/event`
- Auth header: `Authorization: Splunk {cfg['hec_token']}`
- Content-Type: `application/json`
- Body: `finding.to_splunk_event()` — already returns the correct HEC envelope
- Override `index` and `sourcetype` from cfg if set
- Respect `cfg.get('verify_ssl', True)` for SSL verification
- Return `(True, "sent")` on 200, `(False, "<status> <body>")` on error
- Use `urllib.request` only (no external deps)

### `test(self) -> tuple[bool, str]`
POST a minimal health-check event to HEC.

- Use the same endpoint and token
- Body: `{"event": "arckon-test", "sourcetype": "arckon:finding"}`
- Return `(True, "Splunk HEC reachable — index: {index}")` on 200
- Return `(False, "HTTP {status}: {body[:200]}")` on error

## Config keys available in `self.cfg`
```
hec_url     str   HEC base URL e.g. https://splunk.example.com:8088
hec_token   str   HEC token
index       str   target index (default: arckon)
sourcetype  str   sourcetype (default: arckon:finding)
verify_ssl  bool  default True
```

## Notes
- Splunk HEC returns HTTP 200 even for some auth errors — check `response["code"]` in JSON body
- If `verify_ssl` is False, use `ssl.create_default_context()` with `check_hostname=False`
- Do not use `requests` library — stdlib urllib only
