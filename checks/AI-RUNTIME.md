# AI-RUNTIME — Runtime Behavioral Monitoring Checks

**Category:** Runtime Behavioral Monitoring
**Check IDs:** AI-RUNTIME-001 through AI-RUNTIME-005
**Count:** 5 checks

Framework references: OWASP Agentic OAGNT-05, OAGNT-06 | NIST AI RMF GOVERN 6.1, MANAGE 4.1 | FedRAMP AU-2, AU-6, AU-9, AU-11, AU-12, SI-4, AC-6, IR-4, SC-5, CM-6

---

## AI-RUNTIME-001: Inference Activity Logging Enabled

**Severity:** CRITICAL
**Check type:** Static config scan

### Description
Verifies that every inference call made through the AI runtime is logged with sufficient detail to reconstruct what happened. Without activity logging, there is no way to detect abuse, investigate incidents, audit costs, or prove compliance.

Logging must persist to a durable store (database or file) — in-memory-only logging does not satisfy this control.

### SMB Explanation
Every time your AI answers a question, it should write that down somewhere. If something goes wrong — your AI says something it shouldn't, someone tricks it into sharing private information, or your bill suddenly spikes — you need a record to figure out what happened. Without logs, you're flying blind.

### PASS Criteria
- `monitoring.enabled = true` found in config
- A persistent log path (`db_path`, `log_path`, or `activity_db`) is configured
- Activity log database file exists on disk (indicates the runtime is actively logging)

### FAIL Criteria
- No monitoring configuration found
- `monitoring.enabled = false` or absent
- No log path configured (logs not persisted)

### Remediation
Add to your AI runtime config (`hash.json` or equivalent):
```json
"monitoring": {
  "enabled": true,
  "db_path": "workspace/memory/.activity.db",
  "retention_days": 30
}
```

### Framework Mappings
| Framework | Control |
|---|---|
| OWASP Agentic Top 10 | OAGNT-05 — Insufficient Monitoring and Audit Trails |
| NIST AI RMF | GOVERN 6.1 — Risk monitoring; MANAGE 4.1 — Incident response |
| FedRAMP / NIST 800-53 | AU-2 — Event Logging; AU-12 — Audit Record Generation; SI-4 — System Monitoring |
| CMMC 2.0 | AU.L2-3.3.1 — Create audit logs |

---

## AI-RUNTIME-002: Anomaly Detection Configured

**Severity:** HIGH
**Check type:** Static config scan

### Description
Checks whether the AI runtime has automated anomaly detection enabled to flag unusual behavior — token usage spikes, off-hours agentic activity, unexpected tool calls, or unusual model escalations.

Anomaly detection is the difference between discovering an attack during the incident and discovering it months later in a billing review.

### SMB Explanation
Your AI should automatically notice if something weird is happening — like if it suddenly starts sending 10 times more messages than usual, or starts running at 3am when no one is in the office. These could be signs that something has gone wrong or that someone is misusing your system.

### PASS Criteria
- `anomaly_detection.enabled = true` found in monitoring config

### WARN Criteria
- Activity logging is on but no explicit anomaly detection block found

### FAIL Criteria
- No anomaly detection configuration found

### Remediation
```json
"monitoring": {
  "enabled": true,
  "anomaly_detection": { "enabled": true }
}
```

### Framework Mappings
| Framework | Control |
|---|---|
| OWASP Agentic Top 10 | OAGNT-06 — Prompt Injection via Indirect Channels (detection side) |
| NIST AI RMF | MANAGE 4.1 — Monitor deployed AI for performance and risk |
| FedRAMP / NIST 800-53 | SI-4 — System Monitoring; IR-4 — Incident Handling |
| CMMC 2.0 | SI.L2-3.14.6 — Monitor for anomalous activity |

---

## AI-RUNTIME-003: Human Oversight Checkpoint for Autonomous Tasks

**Severity:** HIGH
**Check type:** Static config scan

### Description
Verifies that autonomous AI agents operating in the runtime have human-in-the-loop (HITL) controls configured for high-impact actions. Without approval gates, an agent can take irreversible actions — deleting files, sending emails, pushing code, making purchases — without any human review.

### SMB Explanation
If your AI can take actions on its own — send emails, delete files, place orders — it should have to ask for permission first before doing anything that can't be undone. This is like requiring a manager's signature before writing a big check.

### PASS Criteria
- `human_oversight: true` found in agent config
- `require_confirmation` list includes high-impact action types (deploy, send_email, delete_file, git_push)

### FAIL Criteria
- Agent block present in config but no human oversight setting found

### WARN Criteria
- No agent configuration found at all (oversight policy undefined)

### Remediation
```json
"agents": {
  "human_oversight": true,
  "require_confirmation": ["deploy", "send_email", "delete_file", "git_push"]
}
```

### Framework Mappings
| Framework | Control |
|---|---|
| OWASP Agentic Top 10 | OAGNT-05 — Insufficient Monitoring; OAGNT-06 — Excessive Agency |
| NIST AI RMF | GOVERN 6.1 — Human oversight of AI decisions |
| FedRAMP / NIST 800-53 | AC-6 — Least Privilege; IR-4 — Incident Handling |
| CMMC 2.0 | AC.L2-3.1.5 — Least privilege |

---

## AI-RUNTIME-004: Token Budget Limits Enforced

**Severity:** HIGH
**Check type:** Static config scan

### Description
Verifies that per-session, per-model, or global token budget limits are configured. Without limits, a runaway loop, adversarial prompt, or misconfigured agent can exhaust the entire API quota in a single incident — resulting in service disruption and unexpected charges.

### SMB Explanation
Your AI charges money every time it processes text. Without a spending limit, a single glitch could run up a massive bill overnight. This check verifies you've set a cap on how much your AI can process in a given period — the same way you'd set a spending limit on a corporate credit card.

### PASS Criteria
- `max_tokens`, `token_budget`, `token_limit`, or equivalent per-model or global limit found in config

### FAIL Criteria
- No token limits of any kind found in config

### Remediation
Set limits per provider in your AI runtime config:
```json
"providers": {
  "openai":    { "max_tokens": 4096 },
  "anthropic": { "max_tokens": 8192 }
}
```
Or a global daily budget:
```json
"monitoring": { "token_budget_daily": 500000 }
```

### Framework Mappings
| Framework | Control |
|---|---|
| NIST AI RMF | MANAGE 4.1 — Resource management for deployed AI |
| FedRAMP / NIST 800-53 | SC-5 — Denial of Service Protection; CM-6 — Configuration Settings |
| CMMC 2.0 | CM.L2-3.4.2 — Enforce security configuration settings |

---

## AI-RUNTIME-005: Prompt Audit Trail Retained

**Severity:** HIGH
**Check type:** Static config scan

### Description
Verifies that a durable record of prompts (or prompt hashes) is retained for a sufficient period to support forensic investigation. After a security incident — prompt injection, data exfiltration, policy violation — investigators need to reconstruct the exact sequence of prompts and responses.

A retention period of less than 7 days is insufficient for most incident response timelines. 30 days is the recommended minimum; 90 days for regulated environments.

### SMB Explanation
If your AI ever says something it shouldn't, or if someone uses it to access information they shouldn't have, you need a record of what was asked and what it said. Without that, there's no way to know what happened or to prove to a regulator or customer that you took it seriously.

### PASS Criteria
- Explicit `prompt_audit: true` or `prompt_logging: true` found in config, OR
- Activity logging enabled with `retention_days >= 7` (prompt hashes stored in activity log)

### WARN Criteria
- Activity logging on but `retention_days < 7` (too short for incident response)
- Activity logging on but no explicit retention period configured

### FAIL Criteria
- No prompt logging, audit trail, or activity retention policy found

### Remediation
```json
"monitoring": {
  "enabled": true,
  "retention_days": 30,
  "prompt_audit": true
}
```

### Framework Mappings
| Framework | Control |
|---|---|
| OWASP Agentic Top 10 | OAGNT-05 — Insufficient Monitoring and Audit Trails |
| NIST AI RMF | GOVERN 6.1 — Accountability; MANAGE 4.1 — Post-incident review |
| FedRAMP / NIST 800-53 | AU-9 — Protection of Audit Information; AU-11 — Audit Record Retention; SI-12 — Information Management |
| CMMC 2.0 | AU.L2-3.3.2 — Retain audit logs |
