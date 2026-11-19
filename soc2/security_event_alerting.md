# Security Event Alerting

## Purpose
Document the security event alerting configuration for SOC 2 criteria CC7.2
(Monitoring Activities) and CC7.3 (Security Incident Response).

## Current Alert Configuration

### Alert Triggers (verified 2026-11-19)
| Trigger | Enabled | Description |
|---|---|---|
| `new_critical` | Yes | Fires when a new CRITICAL-severity finding is detected |
| `new_high` | Yes | Fires when a new HIGH-severity finding is detected |
| `new_shadow_ai` | Yes | Fires when a new unauthorized AI tool is discovered on an endpoint |
| `ai_accessed_protected_file` | Yes (default) | Fires when an AI tool accesses a protected file |
| `protected_cloud_asset_access` | Yes (default) | Fires when any identity accesses a protected cloud asset |
| `protected_cloud_asset_access` (alert modes) | All / Automation only / Human only | Configurable per policy |

### Alert Channels (verified 2026-11-19)
| Channel | Configured | Destination |
|---|---|---|
| Google Chat | Yes | Configured webhook URL |
| Email | Yes | Configured recipient list |
| PSA (ConnectWise/Autotask/Jira) | Yes | Ticket creation on critical events |

### Alert Event Types
The following security-relevant events generate alerts:
1. **AI tool accesses protected file** — CRITICAL severity
2. **Any identity accesses protected cloud asset** — CRITICAL severity
3. **New CRITICAL finding detected** — from security checks
4. **New HIGH finding detected** — from security checks
5. **New shadow AI tool discovered** — unauthorized AI on an endpoint
6. **Rate limiting triggered** — repeated failed login attempts

### Alert Content
Each alert includes:
- Event type and severity
- Actor identity (email or service account)
- Actor classification (User vs AI/automation)
- Source IP address (when available from Google audit API)
- Geolocation (state/region, when available)
- Google AI-agent classification (when available from Google audit API)
- Affected resource (file path or cloud asset URI)
- Timestamp
- Link to Arckon dashboard for remediation

## Monitoring Infrastructure

### Log Aggregation
| Component | Status | Purpose |
|---|---|---|
| Google Cloud Ops Agent (fluent-bit) | Running | Aggregates system and application logs |
| rsyslog | Running | Centralized syslog on production VM |
| Arckon application audit log | Running | All security-relevant application events |
| GCP Cloud Audit Logs | Active | IAM changes, access attempts, infrastructure changes |
| Cloudflare logs | Active | WAF events, DDoS mitigation, access patterns |

### Alert Delivery Verification
Alerts are verified end-to-end by:
1. Triggering a test alert from the Arckon dashboard (Settings → Send Test Alert)
2. Confirming receipt on Google Chat, email, and PSA
3. Documenting the test result

Last test: 2026-11-17 (Google Chat alert received for protected cloud asset access)

## Gaps and Recommendations

### Current Gaps
1. **No GCP Cloud Monitoring alert policies** — recommend adding alerts for:
   - VM CPU/memory exhaustion
   - Disk space low
   - Unusual network traffic patterns
2. **No Cloudflare alerting** — recommend enabling Cloudflare notifications for:
   - DDoS attack detected
   - WAF rule triggered at high rate
   - SSL certificate expiration approaching

### Recommended Additions (low effort)
1. Add GCP Cloud Monitoring alert for disk space > 80%
2. Add GCP Cloud Monitoring alert for CPU > 90% for 5 minutes
3. Enable Cloudflare email notifications for security events
4. Document a weekly log review practice (even if automated alerts exist)

## Related Documents
- Information Security Policy
- Incident Response Plan
- Evidence Collection Tracker
