# HASH_SIEM_P02 — Microsoft Sentinel Connector

## File to modify
`connectors/siem_connector.py` — class `SentinelConnector`

## What to implement

### `send(self, finding: ArckonFinding) -> tuple[bool, str]`
POST one finding to Azure Monitor HTTP Data Collector API.

Endpoint:
```
POST https://{workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01
```

Required headers:
```
Content-Type:  application/json
Log-Type:      {cfg.get('log_type', 'ArckonFindings')}
x-ms-date:     {RFC 1123 UTC timestamp}
Authorization: SharedKey {workspace_id}:{signature}
```

HMAC-SHA256 signature construction:
```python
import hmac, hashlib, base64
string_to_sign = f"POST\n{content_length}\napplication/json\nx-ms-date:{date_string}\n/api/logs"
signature = base64.b64encode(
    hmac.new(base64.b64decode(shared_key), string_to_sign.encode('utf-8'), hashlib.sha256).digest()
).decode()
```

Body: JSON array containing `[finding.to_sentinel_record()]`

Return `(True, "sent to {log_type}")` on HTTP 200, `(False, "HTTP {status}")` on error.

### `test(self) -> tuple[bool, str]`
POST a minimal test record:
```json
[{"TimeGenerated": "<now>", "CheckId": "TEST", "Title": "Arckon connectivity test"}]
```
Return `(True, "Sentinel workspace reachable — table: {log_type}")` on success.

## Config keys
```
workspace_id  str   Log Analytics workspace GUID
shared_key    str   primary or secondary workspace key (base64)
log_type      str   custom table name, default ArckonFindings
```

## Notes
- No external dependencies — use `urllib.request` and `hmac`/`hashlib` from stdlib
- Sentinel appends `_CL` to the log_type automatically (ArckonFindings becomes ArckonFindings_CL)
- Data appears in Sentinel within 2–5 minutes of ingestion
