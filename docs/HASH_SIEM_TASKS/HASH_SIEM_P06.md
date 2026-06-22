# HASH_SIEM_P06 — Kaseya Connector (VSA / BMS / IT Glue)

## File to modify
`connectors/siem_connector.py` — class `KaseyaConnector`

## Three sub-integrations

---

### 1. `send(self, finding: ArckonFinding) -> tuple[bool, str]`
Create a BMS service ticket from a CRITICAL or HIGH finding.

Endpoint: `POST {bms_url}/api/v1/servicetickets`
Headers: `Authorization: Bearer {bms_api_key}`, `Content-Type: application/json`
Body:
```json
{
  "summary":     "Arckon: {finding.title} on {finding.hostname}",
  "description": "{finding.details}\n\nRemediation:\n{finding.remediation}",
  "priority":    "Critical" or "High" based on finding.severity,
  "queue":       "{cfg.get('ticket_queue', 'Security')}",
  "source":      "Arckon by RiskRaven",
  "customFields": {
    "CheckID":   finding.check_id,
    "Customer":  finding.customer_id,
    "RiskScore": finding.risk_score
  }
}
```
Return `(True, "ticket created: {ticket_id}")` on 200/201.

---

### 2. `test(self) -> tuple[bool, str]`
GET `{bms_url}/api/v1/queues` with auth header.
If BMS URL not configured, test VSA instead: GET `{vsa_url}/api/v1.0/system/sessionId`.
Return `(True, "Kaseya BMS reachable")` or appropriate error.

---

### 3. `sync_inventory(self, inventory: list[dict]) -> tuple[bool, str]`
Sync Arckon's AI asset inventory to IT Glue as a Flexible Asset per client.

Steps:
1. Find or create a Flexible Asset Type called "AI Inventory" in IT Glue:
   `GET {itglue_base}/flexible_asset_types?filter[name]=AI+Inventory`
   If not found, POST to create with fields: Service, Vendor, Risk, Status, First Seen, Last Seen

2. For each item in `inventory`:
   `POST {itglue_base}/flexible_assets` with:
   - `organization_id`: cfg['itglue_org_id']
   - `flexible_asset_type_id`: from step 1
   - `traits`: mapped inventory fields

IT Glue base URL: `https://api.itglue.com`
Auth header: `x-api-key: {itglue_api_key}`

Return `(True, "synced {n} assets to IT Glue")` on success.

---

## Config keys
```
vsa_url         str   Kaseya VSA base URL
vsa_api_key     str   VSA REST API key
bms_url         str   Kaseya BMS base URL
bms_api_key     str   BMS REST API key
itglue_api_key  str   IT Glue API key
itglue_org_id   str   IT Glue organisation ID
ticket_queue    str   BMS queue name, default 'Security'
```

## Notes
- All three sub-integrations are optional — test which config keys are present
- BMS API docs: https://developer.kaseya.com/bms
- IT Glue API docs: https://api.itglue.com/developer
- VSA REST API: https://helpdesk.kaseya.com/hc/en-gb/categories/201973008
- stdlib urllib only — no external dependencies
