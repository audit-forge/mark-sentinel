# Sentinel — Session Handoff
**Overwrite this file at the end of every session. Do not append.**

---

## Last updated: 2026-06-03

## Current state
Phase 4 (SMB polish + packaging) in progress. Core scan engine is complete.
31 checks across 7 categories. All deployed on GCP.

## What's working
- Full check suite: INP, OUT, AGENT, SUPPLY, GOV, RUNTIME, DEPLOY
- Adversarial probe engine (live API + local Ollama modes)
- Presidio PII scanning integration
- Config-mode static analysis (no live AI needed)
- PDF report generation
- SMB quickstart guide
- One-command installer script scaffolded

## Known gaps
- AI-INP-003 (indirect injection via RAG) — not implemented, returns SKIP
- AI-AGENT-003 (memory/context poisoning) — not implemented, returns SKIP
- These two gaps mean Sentinel cannot test for the Google Gemini-class indirect injection attacks
- No runtime interception — point-in-time scanner only

## What's next
Implement AI-INP-003 and AI-AGENT-003.
These require: a test harness that feeds malicious documents/content to an agent
and verifies whether the injected instructions execute.

## Active gotchas
- Sentinel is a SCANNER not a runtime blocker — do not confuse with CNAPP's EDR
- Check results: PASS/FAIL/WARN/SKIP/NA — SKIP means "not implemented or not applicable"
- Config mode skips all live probe checks (INP-001, INP-002, INP-004, OUT-001 through OUT-004)
- Each check returns a CheckResult object with check_id, status, severity, evidence, remediation
