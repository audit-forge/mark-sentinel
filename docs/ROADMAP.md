# M.A.R.K. Sentinel — Product Roadmap

This document captures planned features and the reasoning behind them.
Items are organised by theme, not by release date. Priorities shift based on
customer feedback from live deployments — this roadmap reflects direction,
not a fixed schedule.

---

## Currently Shipped

### Shadow AI Discovery (May 2026)
Agents installed on endpoints scan their local network, process list, DNS
cache, environment variables, config files, and Docker containers to surface
AI running anywhere in the environment — including tools and services the
customer's IT team does not know about. Findings are reported back to the
cloud Command Center and displayed by category:

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
validation awareness — incorporating findings from the April 2026 FDA Warning
Letter on inappropriate AI use in pharmaceutical manufacturing.

---

## Planned — Near Term

### RAG / Retrieval Pipeline Checks
When a customer indicates their AI deployment uses document retrieval
(RAG — Retrieval-Augmented Generation), additional checks become active that
test for data leakage from the retrieval store, context poisoning
vulnerabilities, and access control on indexed documents. Currently surfaced
as "Coming Soon" in the probe tester; check infrastructure and UI are in place.

### Per-Device Compliance Report Scheduling
Allow customers to schedule automated compliance reports on a cadence
(daily, weekly, monthly) delivered by email or webhook. Reduces manual
pull-and-review overhead for teams running continuous compliance programmes.

### Alert Integrations
Extend the existing alerts framework to support Slack, Microsoft Teams,
PagerDuty, and generic webhooks — so Shadow AI discoveries and critical
findings trigger notifications in the tools compliance and security teams
already live in.

---

## Planned — Strategic

### Network-Level DNS Query Integration
**What it solves:** Even with agents installed on every managed device, any
device without an agent is invisible to Sentinel — it can detect server-mode
AI via network probe, but cannot see outbound connections made by client-side
AI tools (Claude CLI, Gemini CLI, ChatGPT, Copilot, etc.) on unmanaged
machines.

**How it works:** Most enterprise networks run a central DNS server — either
built into the router or a dedicated resolver (Pi-hole, dnsmasq, Windows DNS,
Cisco Umbrella, pfSense). Every device on the network queries that DNS server
before making any outbound connection. When a machine runs Claude CLI, it
looks up `api.anthropic.com`. That lookup is logged by the DNS server.

Sentinel will support a **Network Sensor** configuration — a lightweight
integration where the customer provides credentials or read-only API access
to one of the following:

| Integration | What it gives us |
|---|---|
| Pi-hole API | Full DNS query log with source IP per device |
| pfSense / OPNsense | DNS resolver query log via REST API |
| Cisco Meraki | DNS query log via dashboard API |
| Ubiquiti UniFi | DNS and traffic data via local controller API |
| Windows DNS Server | Event log query for DNS debug logging |
| Cisco Umbrella | Cloud-delivered DNS query log with device attribution |

**What the customer sees:** When Find Shadow AI is triggered, Sentinel queries
the configured DNS server alongside dispatching agent scans. The DNS query
returns a list of every device IP that contacted a known AI endpoint in the
configured lookback window (e.g. last 7 days). Those devices appear in Shadow
AI as findings tagged **Detected via Network DNS** — including devices with
no Sentinel agent installed.

**The compliance conversation this enables:**
> "We can prove that in the last 30 days, no device on your network contacted
> an unauthorised AI API — not just the devices with our agent installed, but
> every device on the network."

This is the statement a pharmaceutical compliance officer, a FedRAMP auditor,
or a CISO needs to make. No endpoint agent coverage on every device required.

**Why it is not built yet:** We need live customer deployments to understand
which DNS infrastructure is most common in target verticals (pharma, financial
services, federal). Building integrations for the wrong platforms first wastes
time. The first customer deployment will determine which integration to
prioritise.

**Design notes for implementation:**
- All DNS server credentials stored encrypted, never in plain text
- Query is read-only — Sentinel never writes to or modifies DNS configuration
- Lookback window is customer-configurable (default 7 days)
- Results are deduped against known agents — if a device IP is already a
  managed Sentinel agent, the DNS finding is suppressed (not double-counted)
- Source tagged as `dns_network` in shadow_devices table (distinct from
  `cloud_api` which is agent-local DNS cache)
- Dismissed findings are not re-surfaced within the lookback window

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
customers with Palo Alto, Fortinet, or Cisco ASA infrastructure. Requires
firewall API credentials and is a more invasive integration than DNS-only.

### Agentless Network Scan Scheduling
Allow the cloud C2 to dispatch timed network probes through installed agents
on a schedule — not just on demand. Agents would scan their subnet nightly
and report any new Shadow AI devices that appeared since the last scan,
surfacing them as new findings automatically without a manual trigger.

---

*Roadmap updated May 2026. Priorities are adjusted based on customer deployment
feedback. Items in "Planned — Strategic" and "Under Consideration" are subject
to change.*
