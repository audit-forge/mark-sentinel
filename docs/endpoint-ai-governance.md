# Endpoint AI Governance

In Endpoint AI, administrators can select a status in a tool's Governance
column and click Save. Available statuses are Sanctioned, Tolerated, Shadow,
and Restricted. Use Agent Default removes the server override.

## Scope And Meaning

- A policy applies to an exact, case-sensitive tool name across endpoints in
  that tool's client organization. Unassigned endpoints form a separate scope.
- A customer-wide view does not create a global policy: the selected tool's
  device determines the target organization. Session-pinned organizations and
  the current client-org filter constrain which rows may be changed.
- Only admin, customer_admin, and super_admin may change policies. Viewers
  see effective statuses without editing controls.
- Restricted is a governance classification, not a process or model block.
  This feature manages discovered tools, not individual model identifiers.
- Risk scores and risk bands remain agent-reported; changing governance does
  not recalculate those scores or imply a new risk assessment.

## Persistence And Audit

Agent observations remain separate from server-owned policy. Subsequent
reports cannot overwrite a policy. Inventory, summary counts, and CSV exports
resolve the effective status using that policy. Resetting to Agent Default
uses the latest reported status, not the original status at override time.

The database initializes two additive tables: endpoint_ai_governance_overrides
and endpoint_ai_governance_audit. Policy writes and audit records share one
transaction. Audit history includes tool, org, actor/role, time, and previous
and new override values. Admins can expand Recent Governance Changes on the
page; this shows the latest 50 records in their current scope. This ordinary
audit table is not a cryptographic tamper-evident ledger.

POST /api/fleet/ai-inventory/governance accepts only an inventory id and
governance_status (or null to reset). Customer, actor, and target organization
are derived from the authenticated session and scoped inventory row. Browser
origin checks apply before mutation dispatch.

## Deployment

This is a server-only change; no agent update is required. Initialization is
additive and old server images ignore the new tables, so a container rollback
does not require restoring customer databases. Preserve the tables on rollback
to avoid losing policy decisions or audit history.

The 2026-11-02 hotfix source/build definition, private database backups, and
per-tenant rollout manifests are stored on the host under
/opt/sentinel-prod-snapshots/endpoint-ai-governance-20261102. Containers now
load server.py and storage.py from the image, not a server.py bind overlay.
Source changes must still be committed/reviewed before a regular release;
the host snapshots are recovery evidence, not a substitute for git history.
