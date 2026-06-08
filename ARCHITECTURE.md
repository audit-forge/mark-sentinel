# Sentinel (M.A.R.K.) — Current Architecture
**Last updated: 2026-06-03**
**M.A.R.K. = Machine Assisted Real-time Knowledge**

## What it is
AI security audit tool. Scans any LLM or agentic AI deployment for vulnerabilities
and compliance gaps. Point-in-time scanner — NOT a runtime monitor.
Two audiences: SMBs (plain English, web UI) and regulated environments (NIST/OWASP/FedRAMP).

## What it does vs. what it doesn't
**Does:** Fires adversarial probes at AI endpoints, analyzes config files, checks governance
docs, produces compliance reports. Tells you if your AI system is CONFIGURED to resist attack.

**Does NOT:** Sit in-path, intercept live traffic, block attacks in real-time.
Sentinel finds the unlocked door. CNAPP is the alarm system.

## 31 checks across 7 categories

| Category | File | Checks | Status |
|---|---|---|---|
| AI-INP (Input Safety) | `checks/input_safety.py` | INP-001 to INP-005 | INP-003 (indirect/RAG) = SKIP — not built |
| AI-OUT (Output Safety) | `checks/output_safety.py` | OUT-001 to OUT-005 | All implemented |
| AI-AGENT (Agentic Safety) | `checks/agentic.py` | AGENT-001 to AGENT-006 | AGENT-003 (memory poisoning) = SKIP — not built |
| AI-SUPPLY (Supply Chain) | `checks/supply_chain.py` | SUPPLY-001 to SUPPLY-006 | All implemented |
| AI-GOV (Governance) | `checks/governance.py` | GOV-001 to GOV-005 | All implemented |
| AI-RUNTIME (Runtime Monitor) | `checks/runtime.py` | RUNTIME-001 to RUNTIME-005 | All implemented |
| AI-DEPLOY (Deployment) | `checks/deploy.py` | DEPLOY-001 to DEPLOY-006 | All implemented |

## Known gaps (not implemented)
- **AI-INP-003** — Indirect prompt injection via RAG/external content (the Gemini attack class)
- **AI-AGENT-003** — Agent memory/context poisoning via adversarial input
- No proxy/interception mode — can't block, only report
- No connectors for hosted AI services (Gemini Workspace, Copilot, etc.)

## How it runs
Three scan modes:
- `--mode config` — static analysis of config files only (no live AI needed)
- `--mode api` — sends adversarial probes to a live API endpoint
- `--mode local` — sends adversarial probes to a local Ollama model

## Connectors available
`api`, `claude`, `gemini`, `vertex`, `ollama`, `hash`, `docker`, `kubectl`, `presidio`, `defectdojo`

## Tech stack
Python CLI. FastAPI admin panel. Docker. GCP VM at 35.255.19.236.
Admin panel: `http://admin.35.255.19.236.nip.io`
SSH: `ssh neepai@35.255.19.236`
Local code: `/Users/keithferguson/sentinel/`

## Current phase
Phase 4 — SMB polish and packaging (one-command installer, PDF reports, Docker/PyPI publishing).
See CHANGELOG.md for what's been added.

## What's next (planned)
- Implement AI-INP-003 (indirect injection via RAG)
- Implement AI-AGENT-003 (memory poisoning)
- These are the gaps that would catch the Google Gemini-class attacks
