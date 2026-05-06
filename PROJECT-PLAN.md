# M.A.R.K. Sentinel — Project Plan
## AI Security Audit Tool — Powered by Hash

**Created:** 2026-04-27
**Owner:** Keith Ferguson
**Status:** ACTIVE — Phase 5 complete — Phase 6 in progress (Phases 0–5 complete)

---

## What This Is

A self-contained AI security audit tool that scans any LLM or agentic AI deployment for
known vulnerabilities, misconfigurations, and compliance gaps — and explains what it found
in plain English that anyone can understand.

Built for two audiences that have never had a tool like this:
1. **Regulated environments** — FedRAMP, CMMC, NIST AI RMF, EU AI Act compliance evidence
2. **SMBs and everyday businesses** — the pizza shop, the law office, the small clinic using
   ChatGPT or a local AI tool, who have no idea if it's safe or leaking their data

The positioning angle: this is the only AI security audit tool that works the same way
whether you're a DoD contractor or a mom-and-pop shop. One tool, two output modes.

---

## Market Context

**What's currently on the market:**
- Lakera Guard — acquired by Check Point for $300M. Cloud SaaS, per-API-call pricing.
  Not affordable for SMBs. Sends your prompts to a third-party vendor.
- Mindgard — enterprise automated red teaming. "Pricing on request." Not accessible to SMBs.
- Garak — open source scanner, good for engineers. No compliance output, no plain English,
  no framework mappings. Not usable by non-technical users.
- HiddenLayer / Protect AI — enterprise ML model protection. Not SMB-accessible.

**The gap nobody fills:**
- No self-hosted tool that doesn't require sharing your data with a vendor
- No benchmark-style audit with CIS/NIST/FedRAMP-mapped findings
- No tool designed for SMBs and non-technical users
- No coverage of local LLM deployments (Ollama, self-hosted models)
- OWASP Agentic Top 10 2026 just published — zero tooling exists against it yet

**Critical stat:** 83% of organizations plan to deploy agentic AI but only 29% feel ready
to secure it. The SMB market has essentially 0% coverage.

---

## Two Output Modes — One Tool

### Mode A: Plain English (SMB / Mom & Pop)

Target user: A restaurant owner, a small law firm, a local clinic using ChatGPT or a
simple AI chatbot. They don't know what prompt injection is. They just want to know:
"Is this safe? Are my customers' data at risk? What do I do?"

Output example:
```
AI Safety Check — Your Results
================================
Overall: ⚠️  Some issues found (3 of 12 checks flagged)

🔴 RISK: Your AI can be tricked into ignoring its rules
   What this means: Someone could type a special message that makes your AI say or do
   things it shouldn't — including revealing private information.
   What to do: Add an input filter. We'll show you how. (15 minutes to fix)

🟡 WARNING: No logging enabled
   What this means: If something goes wrong, you have no record of what happened.
   What to do: Turn on conversation logging in your AI provider settings.

✅ PASS: Your API key is stored safely
✅ PASS: Your AI is not sharing data with unauthorized services
...
```

### Mode B: Compliance Report (Regulated / Enterprise)

Target user: A FedRAMP system owner, a CMMC assessor, a CISO preparing for an ATO.
They need framework-mapped findings, SARIF output, evidence bundles, and control citations.

Output: Same as the existing STIG audit tools — terminal, SARIF, JSON, Wiz JSON, GCP SCC.
Framework mappings: OWASP LLM Top 10, OWASP Agentic Top 10, NIST AI RMF, FedRAMP,
CMMC 2.0, EU AI Act.

---

## What It Scans

### Target Types (Connection Modes)
- `--mode api` — any OpenAI-compatible endpoint (OpenAI, Anthropic, Groq, together.ai)
- `--mode local` — local Ollama or vLLM instance
- `--mode docker` — AI service running in a Docker container
- `--mode kubectl` — AI service running in Kubernetes
- `--mode config` — static config scan only (no live connection needed — good for SMBs
  who just want to check their setup files and environment)

### Check Categories (v1.0 baseline)

#### Category 1 — Deployment Security (AI-DEPLOY)
- AI-DEPLOY-001: API keys not exposed in environment, code, or logs
- AI-DEPLOY-002: No hardcoded credentials in model config
- AI-DEPLOY-003: Logging enabled and retained
- AI-DEPLOY-004: Access controls on AI endpoint (not publicly open)
- AI-DEPLOY-005: TLS/HTTPS enforced on all AI connections
- AI-DEPLOY-006: Rate limiting configured to prevent abuse

#### Category 2 — Prompt Injection & Input Safety (AI-INP)
- AI-INP-001: System prompt cannot be overridden by user input
- AI-INP-002: Direct prompt injection resistance (basic adversarial inputs)
- AI-INP-003: Indirect prompt injection resistance (injected via retrieved content/RAG)
- AI-INP-004: Jailbreak resistance (DAN, role-play bypass, encoding tricks)
- AI-INP-005: Input length and token limits enforced

#### Category 3 — Output & Data Safety (AI-OUT)
- AI-OUT-001: Model does not return training data on request
- AI-OUT-002: PII not leaked in responses
- AI-OUT-003: System prompt not disclosed on request
- AI-OUT-004: Model refusals work for harmful content categories
- AI-OUT-005: Output sanitization before passing to downstream systems

#### Category 4 — Agentic & Tool Use Safety (AI-AGENT)
- AI-AGENT-001: Tool/function permissions follow least privilege
- AI-AGENT-002: Agent cannot take destructive actions without confirmation
- AI-AGENT-003: Agent memory/context cannot be poisoned by external input
- AI-AGENT-004: Inter-agent trust not implicitly granted
- AI-AGENT-005: Agent action logs captured and auditable
- AI-AGENT-006: Agent cannot exfiltrate data to unapproved endpoints

#### Category 5 — Model & Supply Chain Integrity (AI-SUPPLY)
- AI-SUPPLY-001: Model provenance known and documented
- AI-SUPPLY-002: Model source verified (not a tampered/poisoned variant)
- AI-SUPPLY-003: Dependencies and plugins from approved sources only
- AI-SUPPLY-004: No shadow AI / unsanctioned model in use
- AI-SUPPLY-005: Model version pinned (not floating latest)

#### Category 6 — Governance & Compliance Posture (AI-GOV)
- AI-GOV-001: AI usage policy documented
- AI-GOV-002: Data retention and deletion policy covers AI interactions
- AI-GOV-003: AI incident response plan exists
- AI-GOV-004: Human oversight mechanisms in place for high-stakes decisions
- AI-GOV-005: AI system documented in asset inventory

**Total v1.0 baseline: 31 checks across 6 categories**

---

## Framework Mappings

| Check Category | OWASP LLM Top 10 | OWASP Agentic Top 10 | NIST AI RMF | FedRAMP/CMMC |
|---|---|---|---|---|
| AI-DEPLOY | LLM07, LLM08 | — | GOVERN 1.1, MANAGE 2.2 | AC-3, SC-8 |
| AI-INP | LLM01, LLM05 | OAGNT-01, OAGNT-03 | MEASURE 2.6 | SI-10, SI-3 |
| AI-OUT | LLM02, LLM06, LLM09 | OAGNT-02 | MEASURE 2.5 | AC-4, SC-28 |
| AI-AGENT | LLM06 | OAGNT-01 through OAGNT-06 | GOVERN 6.1, MANAGE 1.3 | AC-6, AU-2 |
| AI-SUPPLY | LLM03, LLM04 | OAGNT-08 | GOVERN 2.2, MAP 1.5 | CM-7, SA-12 |
| AI-GOV | LLM10 | OAGNT-09, OAGNT-10 | GOVERN 1.1-6.2 | PL-1, IR-1 |

---

## Technical Architecture

Same proven pattern as the existing STIG audit suite.

```
ai-stig-audit/
├── audit.py                  # Main entry point
├── checks/
│   ├── deploy.py             # AI-DEPLOY checks
│   ├── input_safety.py       # AI-INP checks
│   ├── output_safety.py      # AI-OUT checks
│   ├── agentic.py            # AI-AGENT checks
│   ├── supply_chain.py       # AI-SUPPLY checks
│   └── governance.py         # AI-GOV checks
├── connectors/
│   ├── api_connector.py      # OpenAI-compatible API
│   ├── ollama_connector.py   # Local Ollama
│   ├── docker_connector.py   # Docker mode
│   └── config_connector.py   # Static config scan
├── output/
│   ├── plain_english.py      # SMB-friendly plain text
│   ├── sarif.py              # SARIF 2.1.0
│   ├── json_report.py        # Structured JSON
│   └── compliance.py         # Framework-mapped compliance doc
├── profiles/
│   ├── smb.json              # SMB profile (subset of checks, plain English)
│   ├── fedramp.json          # FedRAMP High profile
│   ├── cmmc.json             # CMMC Level 2 profile
│   └── default.json          # Full check suite
├── benchmarks/
│   └── AI_Security_Benchmark_v1.0.md   # Community-draft benchmark document
├── test/
│   ├── fixtures/             # Safe test targets
│   └── run_tests.sh
├── docs/
│   ├── QUICKSTART.md
│   ├── SMB_GUIDE.md          # Plain English setup guide for non-technical users
│   ├── V1_RELEASE_BOUNDARY.md
│   └── PILOT_TESTER_HANDOFF.md
└── README.md
```

### Usage Examples

```bash
# SMB quick check — plain English output
python audit.py --mode config --profile smb --output plain

# Full API scan with compliance report
python audit.py --mode api --endpoint https://api.openai.com/v1 \
  --profile fedramp --output sarif,json,compliance

# Local Ollama scan
python audit.py --mode local --ollama-host http://localhost:11434 \
  --model llama3 --output plain,json

# Docker container scan
python audit.py --mode docker --container my-ai-service --output sarif

# Kubernetes pod scan
python audit.py --mode kubectl --namespace ai-prod --pod ai-inference-0 \
  --output sarif,compliance
```

---

## Two-Market Strategy

### SMB / Mom & Pop Path

**The pitch:** "One command tells you if your AI is safe. No technical knowledge needed."

Target buyers:
- Small businesses using ChatGPT, Claude, Gemini, or a local AI tool
- Professional services firms (law, accounting, medical) using AI for client work
- Any business that handles customer data and uses AI in any form

Delivery:
- Free/open-source tier: basic config scan, plain English output
- Paid tier ($49–$199/month): scheduled scans, email reports, remediation guidance,
  SMB-friendly dashboard

Positioning: "The AI version of a home security check. Know what's unlocked."

### Regulated / Enterprise Path

**The pitch:** "The only self-hosted AI security audit tool with NIST AI RMF and FedRAMP mappings."

Target buyers:
- DoD contractors (CMMC 2.0 requirement)
- Federal agencies and their vendors (FedRAMP)
- Healthcare (HIPAA AI usage)
- Financial services (SOC 2, PCI AI scope)

Delivery:
- Self-hosted only (data never leaves your environment)
- Priced per audit or annual license ($2,500–$12,000/year)
- Compliance evidence bundles for auditors

---

## Phased Roadmap

### Phase 0 — Research & Benchmark ✅ COMPLETE — 2026-04-28
- [x] Document all 32 checks with full descriptions and remediation steps → `checks/AI-DEPLOY.md`, `AI-INP.md`, `AI-OUT.md`, `AI-AGENT.md`, `AI-SUPPLY.md`, `AI-GOV.md`
- [x] Write community-draft AI Security Benchmark v1.0 document → `benchmarks/AI_Security_Benchmark_v1.0.md`
- [x] Map all checks to OWASP LLM Top 10, OWASP Agentic Top 10, NIST AI RMF → embedded in benchmark doc; full coverage of all 10+10 categories
- [x] Define test fixture specs for each check category → `test/fixtures/README.md`
- Done boundary: **MET** — benchmark written, all 32 checks designed with PASS/FAIL criteria, framework mappings, remediation steps, and fixture specs

### Phase 1 — Core Engine ✅ COMPLETE — 2026-04-28
- [x] Build `audit.py` entry point with mode/profile/output flags
- [x] Implement `config_connector.py` (static scan — no live AI needed)
- [x] Implement all 6 check modules for config mode
- [x] Build plain English output formatter
- [x] Build JSON output formatter
- [x] Build SARIF output formatter → `output/sarif.py`
- [x] Fixture validation tests → `test/run_fixture_validation.py` (21 tests, 21 passing)
- Done boundary: **MET** — `python audit.py --mode config --profile smb` works end-to-end; hardened fixture passes, baseline fixture fails as expected; SARIF output valid

### Phase 2 — Live API & Local Scanning ✅ COMPLETE — 2026-04-28
- [x] Implement `api_connector.py` (OpenAI-compatible) — 11 adversarial probes across 6 check categories
- [x] Implement `ollama_connector.py` (local Ollama via /v1 OpenAI-compatible endpoint)
- [x] Live probe checks: AI-INP-001/002/004, AI-OUT-001/002/003/004 — run real adversarial probes in api/local mode
- [x] Integration tests → `test/test_live_probes.py` (22 tests, 22 passing — safe + vulnerable mock server)
- Done boundary: **MET** — `python audit.py --mode api --endpoint <url> --model <model>` produces SARIF; live checks transition from SKIP to PASS/FAIL; 43 total tests passing

### Phase 3 — Compliance Output & Docker/K8s ✅ COMPLETE — 2026-04-30
- [x] Build compliance report formatter → `output/compliance.py`
- [x] Implement `docker_connector.py`
- [x] Implement `kubectl_connector.py`
- [x] FedRAMP and CMMC profile definitions → `profiles/fedramp.json`, `profiles/cmmc.json`
- [x] `docs/PILOT_TESTER_HANDOFF.md` and `docs/V1_RELEASE_BOUNDARY.md`
- [x] Kyverno ClusterPolicy output → `output/kyverno.py`
- [x] OPA Rego policy output → `output/rego.py`
- [x] Gemini + Vertex AI connectors → `connectors/gemini_connector.py`, `connectors/vertex_connector.py`
- [x] DefectDojo integration → `connectors/defectdojo_connector.py`
- [x] Presidio PII connector → `connectors/presidio_connector.py`
- Done boundary: **MET** — v1.0 pilot-ready with all modes, output formats, and extended provider coverage

### Phase 4 — SMB Polish & Packaging ✅ COMPLETE — 2026-05-01
- [x] `docs/SMB_GUIDE.md` — plain English setup guide for non-technical users
- [x] `docs/SMB_QUICKSTART.md` — quick-start for non-technical users
- [x] One-command install → `scripts/install.sh`, `scripts/install.ps1`, `scripts/install.bat`
- [x] Sample SMB report (PDF-ready) → `scripts/generate_pdf.sh`
- [x] README targeting both audiences
- [x] CI smoke test workflow → `.github/workflows/ci-smoke.yml`
- [x] Docker build workflow → `.github/workflows/docker-build.yml`
- [x] PyPI publish workflow → `.github/workflows/pypi-publish.yml`
- [x] `pyproject.toml` packaging
- [x] `Dockerfile`
- Done boundary: **MET** — non-technical install in under 10 minutes; CI/CD scaffolded; PyPI + Docker publish gated on secrets

### Phase 5 — Web Dashboard / UI ✅ COMPLETE
- [x] Self-hosted web interface served from `audit.py --serve` (or standalone `dashboard.py`)
- [x] Executive summary view — overall risk score, CRITICAL/HIGH/WARN/PASS counts
- [x] Per-category breakdown cards (AI-DEPLOY, AI-INP, AI-OUT, AI-AGENT, AI-SUPPLY, AI-GOV)
- [x] Finding detail panel — description, evidence, remediation steps
- [x] Multi-provider comparison table (visual, color-coded, like demo output but interactive)
- [x] Framework mapping view — filter findings by NIST/FedRAMP/CMMC/OWASP
- [x] Remediation priority queue — ranked action list
- [x] Wiz-inspired design: dark sidebar, color-coded risk cards, clean data tables
- [x] Loads from existing JSON output — no re-scan needed to view
- [x] Export to PDF from UI
- Done boundary: a non-technical user can open a browser, see their scan results, and click through to understand and fix every finding

### Phase 6 — Multi-Provider Comparison + Scheduled Scans ✅ COMPLETE
- [x] `--compare` mode — run same audit against multiple providers side-by-side, produce comparison report
- [x] Scheduled scan support — cron-style recurring audits, results stored with timestamps (done — agent.py --daemon)
- [x] Trend view — Dashboard/Trend tab in Command Center; SVG line chart (fail/warn/pass over time) fed by `/fleet/device/<id>/timeseries.json`
- [x] Alert/notification on new findings — `alerts.py` (email + Slack + webhook); wired into `_api_agent_report` on every report ingestion; configured via `alerts_config.json`
- [x] `audit history` CLI subcommand — `audit_history.py` (list-devices, device, trends, summary); delegated from `audit.py history ...`
- [x] Distributed agent fleet (agent.py, storage.py, fleet dashboard, full deployment tooling)
- Done boundary: enterprises can track AI security posture over time, not just point-in-time

### Phase 7 — AI Runtime Monitoring + Behavioral Audit
- [ ] `monitoring/interceptor.py` — async logging middleware; intercepts every inference call passing through hash-ai gateway (port 8400); logs: timestamp, model, task_type, tool_calls[], tokens_in, tokens_out, duration_ms
- [ ] `monitoring/activity_log.py` — SQLite-backed structured activity log; configurable retention (7/30/90 days); queryable via CLI and dashboard
- [ ] `monitoring/anomaly.py` — baseline builder + threshold-based anomaly detection; flags token spikes, off-hours agentic activity, unexpected tool calls, unusual model escalations
- [ ] `checks/runtime.py` — 5 new STIG-style controls:
  - AI-RUNTIME-001: Inference activity logging enabled (CRITICAL if absent)
  - AI-RUNTIME-002: Anomaly detection configured
  - AI-RUNTIME-003: Human oversight checkpoint for autonomous agent tasks
  - AI-RUNTIME-004: Token budget limits enforced
  - AI-RUNTIME-005: Prompt audit trail retained
- [ ] `checks/AI-RUNTIME.md` — benchmark spec doc for new category
- [ ] Dashboard integration — live activity feed, anomaly alerts panel
- [ ] Framework mappings: NIST AI RMF GOVERN 6.1, MANAGE 4.1; OWASP Agentic OAGNT-05/06
- **Prerequisite:** Phase 4 of Hash-AI Pro (Sentinel integration into Hash runtime) must ship first
- Done boundary: Sentinel detects and reports on runtime AI behavior, not just static config — prompt injection attempts, agentic overreach, and token anomalies all surface as findings

---

## Done Boundary — v1.0

v1.0 is complete when:
- All 31 checks implemented and passing in unit tests
- Config mode and API mode live-validated against real targets
- Plain English and SARIF outputs both clean
- SMB and FedRAMP profiles both produce correct filtered outputs
- `docs/V1_RELEASE_BOUNDARY.md` written
- `docs/PILOT_TESTER_HANDOFF.md` written
- README covers both audiences

---

## Decisions — Locked

1. **Product name** — **M.A.R.K. Sentinel** (under the M.A.R.K. brand, powered by Hash)
2. **License model** — **Hybrid** — OSS core (check engine, all 31 checks), closed compliance profiles and SMB dashboard
3. **SMB delivery** — **Web UI** — simple one-page web interface for non-technical users, plus CLI for power users
4. **Priority order** — **SMB-first** — faster iteration, faster revenue, enterprise follows

---

## Current Status

**Status:** ACTIVE — Phase 6 complete — Phase 7 next.
**Phase 0 completed:** 2026-04-28 — benchmark written, 32 checks documented, framework mappings, fixture specs.
**Phase 1 completed:** 2026-04-28 — core engine, 6 check modules, plain/JSON/SARIF output, 21 fixture tests passing.
**Phase 2 completed:** 2026-04-28 — api_connector (11 probes), ollama_connector, live INP/OUT checks, 43 tests passing.
**Phase 3 completed:** 2026-04-30 — compliance/kyverno/rego output, docker/kubectl/gemini/vertex/presidio/defectdojo connectors, FedRAMP+CMMC profiles, pilot docs.
**Phase 4 completed:** 2026-05-01 — SMB guide, one-command install (sh/ps1/bat), PDF report, CI/CD workflows, pyproject.toml, Dockerfile.
**Phase 5 completed:** 2026-05-01 — Wiz-inspired web dashboard, executive summary, per-category cards, finding detail, comparison table, framework view, remediation queue, PDF export.
**Phase 6 completed:** 2026-05-03 — trend view (SVG chart, Dashboard/Trend tabs in Command Center), alerts wired into report ingestion (email/Slack/webhook), audit history CLI (list-devices/device/trends/summary).
**Next step:** Phase 7 — AI Runtime Monitoring + Behavioral Audit
**Restart point:** This file. Read top to bottom. Start at Phase 7.
