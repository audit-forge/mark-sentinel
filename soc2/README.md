# Arckon SOC 2 Readiness Program

## Overview
This folder contains all documentation, evidence, and procedures related to
Arckon's SOC 2 Type II compliance program.

## Trust Services Criteria Scope
- **Security** (Common Criteria CC1-CC9) — mandatory
- **Availability** (A1) — included
- **Confidentiality** (C1) — included
- Processing Integrity and Privacy — not in scope (revisit if customer contracts require)

## Documents

| Document | Purpose | Status |
|---|---|---|
| `README.md` | This file — program overview | Active |
| `backup_restore_test.md` | Backup restore test evidence | First test: 2026-11-19 PASS |
| `access_review_q4_2026.md` | Quarterly access review | First review: 2026-11-19 |
| `vulnerability_management_program.md` | Vuln scan cadence and pentest program | Active |
| `vendor_inventory.md` | Subprocessor inventory and compliance | Active |
| `evidence_collection_tracker.md` | Observation period evidence checklist | Active |
| `compliance_platform_comparison.md` | Vanta/Drata/Secureframe evaluation | Pending decision |

## Policy Documents (Google Docs)
Policy documents are stored as Google Docs, shared with authorized reviewers:

- Information Security Policy
- Access Control Policy
- Incident Response Plan
- Change Management Policy
- Vendor Risk Management Policy
- Data Classification and Retention Policy
- Business Continuity and Disaster Recovery Plan

## Control Mapping
Arckon's security checks are mapped to SOC 2 Trust Services Criteria in:
`profiles/soc2_controls.json`

## Observation Period
The observation period clock starts once:
1. All policies are reviewed and approved by the business owner
2. All controls are operating as designed
3. The compliance platform (if selected) is connected and collecting evidence

Target start date: TBD (after policy approval)
Duration: 3-6 months (typical for first-time SOC 2)
