# M.A.R.K. Sentinel — AI Governance & Human Oversight Policy

## Human Oversight Mechanisms

M.A.R.K. Sentinel operates as an audit tool, not a decision-making agent. All findings are
surfaced to human operators who make final remediation decisions. Sentinel does not autonomously
remediate or alter any system configuration.

### Human Review Requirements

- All CRITICAL and HIGH findings require human review before remediation action is taken.
- Scan reports are delivered to human operators via the dashboard or PDF export.
- No automated enforcement actions are performed — Sentinel only reads and reports.
- Alert notifications (email, Slack, webhook) inform humans; humans decide next steps.

### Human-in-the-Loop Controls

Sentinel enforces human-in-the-loop by design:

- The audit agent is read-only; it has no write access to scanned systems.
- Agent configuration enforces `read_only: true` and `require_confirmation: true` for any
  action that would modify a scanned target.
- All agent actions are logged in `.sentinel-server.log` and the dashboard activity feed.
- Findings are never auto-applied; they produce a report, not a patch.

### Oversight Contacts

| Role | Responsibility |
|------|----------------|
| Security Lead | Review CRITICAL findings within 24 hours |
| System Owner | Approve remediation actions |
| Compliance Officer | Sign off on policy exceptions |

### AI Usage Scope

Sentinel uses AI models (Anthropic Claude, OpenAI GPT) only for:
- Comparative analysis between scan profiles
- Natural-language summary of findings in reports
- Recommendation generation (advisory only, not enforced)

AI recommendations are labeled as advisory and reviewed by a human before any action.

### Override Mechanisms

Any AI-generated recommendation can be overridden by the responsible human operator.
Overrides are logged with operator ID, timestamp, and justification.

## Review Cadence

- Weekly: automated scans run and results stored in timeseries DB
- Monthly: human review of trend data and open findings
- Quarterly: governance policy review and update
