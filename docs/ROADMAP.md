# M.A.R.K. Sentinel — Product Roadmap

This document captures planned features and the reasoning behind them.
Items are organised by phase and theme. Priorities shift based on
customer feedback from live deployments — this roadmap reflects direction,
not a fixed schedule.

---

## Currently Shipped

### Shadow AI Discovery (May 2026)
Agents installed on endpoints scan their local network, process list, DNS
cache, environment variables, config files, and Docker containers to surface
AI running anywhere in the environment — including tools and services the
customer's IT team does not know about. Findings are reported back to the
Command Center and displayed by category:

- 🌐 **Network** — unmanaged devices running server-mode AI (Ollama, LM Studio,
  vLLM, HuggingFace TGI, etc.) identified by IP, port, service, and exact
  model names
- ☁️ **Cloud API** — API keys and config files indicating cloud AI usage
  (Anthropic Claude, OpenAI, Google Gemini, Azure OpenAI, AWS Bedrock, etc.)
- ☁️ **DNS Cache** — outbound AI connections detected via local DNS cache
  inspection; catches Claude CLI, Gemini CLI, ChatGPT browser sessions, and
  GitHub Copilot on agent-installed machines even when no API key is set
- ⚙️ **Process** — AI tools actively running as local processes
- 🐳 **Container** — AI running inside Docker containers on the host, detected
  by image name and targeted port probing without scanning the full bridge
  network

### Life Sciences Compliance Profile (May 2026)
Dedicated audit profile for pharmaceutical and regulated life sciences
environments. Maps all checks to FDA 21 CFR Part 11, HIPAA 45 CFR §164,
ICH E6(R2), GxP ALCOA+, FDA AI/ML SaMD Action Plan, and EU MDR Annex I.
Includes nine life-sciences-specific checks (AI-LS-001 through AI-LS-009)
covering audit trail controls, PHI leakage, medical misinformation refusal,
CGMP document generation, regulatory compliance guarantees, and process
validation awareness.

---

## Phase 1 — Near Term (0–60 Days)
*Low-lift additions that build directly on existing infrastructure.*

### AI Asset Inventory
Shadow AI discovery already surfaces every AI tool and service running in
the environment. This feature converts that data into a formal, auditable
**AI inventory** — the foundational artifact required by every major AI
governance framework (NIST AI RMF, ISO 42001, EU AI Act).

The dashboard gains a dedicated Inventory view showing all discovered AI
assets with three states: **Approved**, **Under Review**, and **Unapproved**.
Security teams can approve items directly from the dashboard; approvals are
timestamped and attributed to the reviewer for audit trail purposes.

This positions Sentinel directly against Credo AI, Govix, and ModelOp in the
AI inventory category without adding new discovery infrastructure.

### Compliance Evidence Package Export
Every compliance audit requires the same artifacts: scan history, framework
mappings, finding details, and a signed attestation. Today those exist in
Sentinel but require manual assembly. This feature bundles them into a
single downloadable ZIP containing:

- All reports for the selected date range (PDF format)
- Framework mapping summary (CSV)
- Risk score trend chart
- Cover letter with organization name, scan profile, and date range

One click from the fleet dashboard. Targeted directly at customers preparing
for FedRAMP ATOs, HIPAA assessments, and SOC 2 audits.

### MITRE ATLAS & ISO 42001 Framework Mappings
Two high-value framework additions added to existing check definitions:

- **MITRE ATLAS** — the adversarial ML threat framework maintained by MITRE,
  analogous to MITRE ATT&CK for AI systems. Maps Sentinel checks to specific
  ATLAS tactics and techniques. Directly competitive with Ducara's ATLAS
  positioning.
- **ISO/IEC 42001** — the international AI management system standard.
  Completes existing partial mapping and adds article references to all
  relevant checks.

These are data additions to check definitions, not code changes. Both
appear in report output and framework mapping columns automatically.

### Open Findings Risk Register
A persistent, deduplicated list of every open FAIL and WARN across the
entire fleet — the equivalent of a CVE tracker but for AI security posture.

Each entry shows:
- Check ID, title, and severity
- Affected devices (count and names)
- Status trend: **New** (first seen this week), **Recurring** (present in
  last 3+ scans), or **Resolved** (was failing, now passing)
- Days open

Exportable as CSV or PDF. Gives compliance teams a living remediation
backlog rather than a point-in-time snapshot. Directly competitive with
the risk register functionality in OneTrust and Holistic AI.

### Scan Scheduling via Dashboard UI
Allow security teams to configure recurring automated scans on a cadence
(daily, weekly, monthly) directly from the dashboard — without touching
cron or Task Scheduler on individual devices. The server dispatches scan
instructions to enrolled agents on schedule. Results appear automatically.

The agent communication infrastructure already supports on-demand scans;
this adds scheduling state to the server and a simple UI configuration form.

### Cryptographic Report Signing
Reports exported from Sentinel (PDF and HTML) are signed with a
server-generated key. The signature is embedded in the document footer and
verifiable against a published public key. This gives exported compliance
evidence tamper-evidence — the document proves it came from Sentinel and has
not been altered since export.

Directly addresses the "cryptographic audit trails" capability from Claw GRC,
which positions this as a premium differentiator for regulated industries.

---

## Phase 2 — Mid Term (60–180 Days)
*Meaningful new capabilities that expand the product's competitive surface.*

### AI SBOM (Software Bill of Materials)
Export a complete inventory of AI components — models, APIs, SDKs, and
dependencies — in CycloneDX or SPDX format. An AI SBOM is to AI systems
what a traditional SBOM is to software: a machine-readable artifact proving
what's running and where it came from.

Directly competitive with Protect AI's ML supply chain security offering.
Increasingly required for FedRAMP and DoD procurements following CISA SBOM
guidance.

### RAG / Retrieval Pipeline Checks
When a customer indicates their AI deployment uses document retrieval
(RAG — Retrieval-Augmented Generation), additional checks become active that
test for data leakage from the retrieval store, context poisoning
vulnerabilities, and access control on indexed documents. Currently surfaced
as "Coming Soon" in the probe tester; check infrastructure and UI are in place.

### Vendor AI Assessment Questionnaire
A structured assessment workflow for evaluating the AI security posture of
third-party vendors and AI service providers. The customer distributes a
questionnaire; responses are scored against the AI-STIG framework and stored
in Sentinel alongside internal scan data.

This directly addresses Govix's "vendor AI assessment" capability and is a
critical gap in the market — most organizations use AI APIs from third parties
but have no structured way to assess those vendors' AI security practices.

### Alert Integrations
Extend the existing alerts framework to support Slack, Microsoft Teams,
PagerDuty, and generic webhooks — so Shadow AI discoveries and critical
findings trigger notifications in the tools compliance and security teams
already live in. Directly competitive with standard GRC platform integration
capabilities.

### Per-Device Compliance Report Scheduling
Allow customers to schedule automated compliance reports on a cadence
(daily, weekly, monthly) delivered by email or webhook. Reduces manual
pull-and-review overhead for teams running continuous compliance programmes.

---

## Phase 3 — Strategic (180+ Days)
*Platform-level capabilities that expand Sentinel's total addressable market.*

### AI Agent Identity Registry
As organizations deploy more autonomous AI agents, managing agent identities
and permissions becomes a governance problem in its own right. The agent
identity registry tracks every AI agent in the environment — its name,
purpose, permission set, MCP server access, and assigned owner.

Agents must be enrolled and approved before being granted production access.
Unapproved or overprivileged agents surface as findings. This is the "Okta
for AI agents" use case that Claw GRC is positioning toward — and the market
is moving here fast as AI agent sprawl becomes a documented enterprise problem.

### LLM Red Team / Active Prompt Injection Testing
A module that runs active prompt injection and adversarial input tests
against configured AI endpoints — not just checking whether defenses exist
(passive check), but actually probing them. Results show which defenses hold
and which fail under real attack conditions.

Competitive with Lakera, Protect AI, and Ducara. This moves Sentinel from
audit-and-governance into active security testing — a meaningfully larger
market.

### Network-Level DNS Query Integration
**What it solves:** Even with agents installed on every managed device, any
device without an agent is invisible to Sentinel — it can detect server-mode
AI via network probe, but cannot see outbound connections made by client-side
AI tools (Claude CLI, Gemini CLI, ChatGPT, Copilot, etc.) on unmanaged
machines.

**How it works:** Most enterprise networks run a central DNS server. Every
device on the network queries that DNS server before making any outbound
connection. Sentinel integrates with the DNS server to identify every device
that contacted a known AI endpoint in a configurable lookback window — even
devices with no Sentinel agent installed.

Supported integrations: Pi-hole, pfSense/OPNsense, Cisco Meraki, Ubiquiti
UniFi, Windows DNS Server, Cisco Umbrella.

**The compliance statement this enables:**
> "We can prove that in the last 30 days, no device on your network contacted
> an unauthorised AI API — not just the devices with our agent installed, but
> every device on the network."

### Continuous AI Assurance Dashboard
A real-time view of AI security posture across the fleet — not point-in-time
snapshots but a live stream of findings, trends, and anomalies. Integrates
with agent telemetry to show when AI system behavior changes (new models
deployed, new tool access requested, new shadow AI appeared).

This is the "continuous AI assurance" use case identified in current research
and a core positioning theme for next-generation AI governance platforms.

---

## Under Consideration

### Browser Extension (Shadow AI in the browser)
A lightweight browser extension that can detect active connections to AI
services from within the browser session — catching ChatGPT, Claude.ai,
Gemini, Copilot and other web-based AI tools that have no local process or
API key to detect. Reports back to the Sentinel agent on the same machine.
Requires user consent and is opt-in per device.

### Router/Firewall API Polling (Network Appliance Sensor)
Direct integration with enterprise router and firewall APIs to pull connection
tables and traffic summaries — a deeper version of the DNS query integration
that captures layer-4 traffic data, not just DNS lookups. Relevant for
customers with Palo Alto, Fortinet, or Cisco ASA infrastructure.

### Agentless Network Scan Scheduling
Allow the server to dispatch timed network probes through installed agents
on a schedule — not just on demand. Agents would scan their subnet nightly
and report any new Shadow AI devices that appeared since the last scan,
surfacing them as new findings automatically without a manual trigger.

---

*Roadmap updated May 2026. Priorities adjusted based on competitive landscape
analysis and customer deployment feedback. Phase 1 items are low-lift builds
on existing infrastructure. Phase 2 and 3 items require new development cycles.*
