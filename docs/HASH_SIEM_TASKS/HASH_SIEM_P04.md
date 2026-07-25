# HASH_SIEM_P04 — Elastic Security Connector

## File to modify
`connectors/siem_connector.py` — class `ElasticConnector`

## What to implement

### `send(self, finding: ArckonFinding) -> tuple[bool, str]`
POST one finding to Elasticsearch using the Index API.

Endpoint: `PUT {endpoint}/{index}/_doc/{check_id}-{device_id}-{timestamp}`
Headers:
```
Content-Type:  application/json
Authorization: ApiKey {api_key}
```
Body: `finding.to_ecs()` — already returns ECS-mapped dict.

Return `(True, "indexed to {index}")` on HTTP 200/201, `(False, "HTTP {status}")` on error.

### `test(self) -> tuple[bool, str]`
GET `{endpoint}/_cluster/health` with the same auth header.
Return `(True, "Elasticsearch reachable — cluster: {cluster_name}, status: {status}")` on success.
Return `(False, "HTTP {status}: {body[:200]}")` on error.

## Config keys
```
endpoint    str   Elasticsearch base URL e.g. https://elasticsearch.example.com:9200
api_key     str   base64-encoded API key in format "id:api_key"
index       str   target index, default arckon-findings
verify_ssl  bool  default True
```

## Notes
- No external dependencies — urllib.request only
- `api_key` format is `id:api_key` base64 encoded — use as-is in `Authorization: ApiKey {api_key}`
- ECS document is already built by `ArckonFinding.to_ecs()` — do not rebuild
- Index will be auto-created if it doesn't exist (Elasticsearch default behaviour)
- For Elastic Cloud: endpoint is `https://{deployment-id}.es.{region}.aws.elastic-cloud.com`
