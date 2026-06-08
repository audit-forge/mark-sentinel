# M.A.R.K. Sentinel — Complete Demo Playbook & Learning Guide

---

## PART 1: WHAT IS M.A.R.K. SENTINEL?

M.A.R.K. Sentinel is a self-hosted AI security audit platform. It discovers, scores, and reports on AI services running in a customer's environment — whether they know about them or not.

**The core problem Sentinel solves:**
Most organizations have no idea how many AI tools are running across their teams. Employees are using ChatGPT, Copilot, custom agents, and dozens of SaaS tools with AI baked in — without security review, without governance, and without any visibility. Sentinel finds them all, audits them against industry frameworks (NIST AI RMF, OWASP LLM Top 10, FedRAMP, CMMC), and gives the organization a clear risk picture with actionable remediation steps.

**Who it's for:**
- IT consultants and MSPs who need to offer AI security as a service
- Organizations undergoing digital transformation who are adopting AI rapidly
- Companies in regulated industries (government, healthcare, finance) that need compliance artifacts
- SMBs who want plain-English results without hiring a security team
- Enterprise security teams who need fleet-wide AI visibility

---

## PART 2: CORE FEATURES

### 2.1 Shadow AI Discovery

Shadow AI = AI tools being used without IT or security team knowledge.

Sentinel's agent deploys to customer endpoints and scans for:
- Running AI processes (local models, agents, API clients)
- Browser extensions with AI capabilities
- Network traffic patterns indicating AI API calls
- Installed applications with embedded AI
- MCP (Model Context Protocol) servers exposing tool-call interfaces

**Why it matters:** You can't secure what you don't know exists. Shadow AI is the #1 AI risk for most organizations right now. Employees using unapproved AI tools may be sending sensitive data (customer records, financials, IP) to third-party AI providers without anyone knowing.

**What the customer sees:** A dashboard showing every AI asset discovered, when it was first seen, what data it may be touching, and a risk score.

### 2.2 Risk Register

Every discovered AI asset gets an entry in the Risk Register with:
- **Risk Score (0–100):** Calculated from exposure level, data sensitivity, authentication controls, logging status, and framework compliance
- **Severity level:** CRITICAL / HIGH / MEDIUM / LOW / INFO
- **Framework mappings:** Which NIST, OWASP, FedRAMP, CMMC controls are affected
- **Status tracking:** Open / In Remediation / Resolved

The Risk Register is the central source of truth for the organization's AI security posture. It updates automatically as new scans run and as the environment changes.

### 2.3 MCP Server Detection

Sentinel identifies Model Context Protocol (MCP) servers running across the fleet — the interfaces AI agents use to call tools like file systems, databases, APIs, and shell commands.

For each MCP server found, Sentinel shows:
- What tools it exposes and their risk level
- Which AI agents are connected to it
- Whether dangerous capabilities (file write, shell exec, network calls) are gated properly
- Compliance posture against agentic AI controls

**Why it matters:** AI agents with uncontrolled tool access are the fastest-growing attack surface in enterprise environments.

### 2.4 Compliance Assessment

Sentinel maps every finding to industry frameworks:

| Framework | Who it's for |
|---|---|
| NIST AI RMF | General AI risk management |
| OWASP LLM Top 10 | Application security teams |
| FedRAMP | US government contractors |
| CMMC 2.0 | Defense contractors |
| AI-STIG | DoD environments |

For each framework, Sentinel produces a compliance artifact showing which controls PASS, FAIL, or need review — ready to hand to an auditor.

### 2.5 Audit Check Categories

Sentinel runs checks across 7 categories:

**AI-DEPLOY — Deployment Security**
Is the AI deployed securely? Are API keys exposed? Are credentials hardcoded? Is the model config locked down?
*Example: Checks that API keys aren't hardcoded in source code or committed to version control.*

**AI-GOV — Governance**
Does the organization have AI policies? Is there human oversight? Are AI decisions auditable?
*Example: Checks for existence of an AI usage policy, data retention policy, and human-in-the-loop controls.*

**AI-INP — Input Safety**
Is the AI protected against prompt injection, jailbreaks, and malicious inputs?
*Example: Checks for input validation, prompt filtering, and rate limiting on AI endpoints.*

**AI-OUT — Output Safety**
Is the AI's output filtered? Can it leak sensitive data or produce harmful content?
*Example: Checks for output filtering, PII redaction, and content moderation.*

**AI-RUNTIME — Runtime Security**
Is the running AI environment secure? Are there controls on what the AI can access?
*Example: Checks for network isolation, resource limits, and access controls on AI processes.*

**AI-AGENT — Agentic AI Controls**
For AI agents with tool use — are dangerous capabilities gated? Is there confirmation before destructive actions?
*Example: Checks for require_confirmation flags, tool allowlists, and human approval workflows.*

**AI-SUPPLY — Supply Chain Security**
Where did the model come from? Is it verified? Are dependencies audited?
*Example: Checks for model provenance, signing, and dependency scanning.*

### 2.6 API Security Tester

Sentinel includes a live adversarial probe tool that tests any AI API endpoint directly:
- Supports OpenAI-compatible endpoints, Anthropic, and Google Gemini
- Runs 8 automated security checks covering prompt injection, jailbreaks, output safety, and data leakage
- Results include pass/fail/warn with severity ratings and remediation steps
- No agent installation required — tests any API with just a key and endpoint URL

**Why it matters:** If a customer is running their own AI API (custom model, internal chatbot, AI-powered product), this tells them exactly how vulnerable it is in under 5 minutes.

### 2.7 Reporting

Sentinel produces reports in multiple formats:
- **Dashboard:** Live web UI showing current posture, trends over time, and active findings
- **Executive Summary PDF:** Non-technical summary for business owners and leadership
- **CISO Report PDF:** Technical risk breakdown with severity analysis and framework mapping
- **Technical Findings PDF:** Full remediation steps with specific commands and verification steps (Plus plan)
- **Evidence Package:** Exportable compliance evidence bundle for auditors (Plus plan)

### 2.8 Remediation Guidance

Every finding includes:
1. What it means in plain English
2. Why it's a risk (business impact)
3. Step-by-step remediation (specific commands or configuration changes)
4. Verification — how to confirm the fix worked
5. Framework reference — which control is now satisfied

Sentinel does NOT auto-remediate. All fixes require human approval. This is by design — the tool is advisory, not autonomous.

---

## PART 3: HOW SENTINEL IS DEPLOYED

### Architecture Overview

```
Sentinel Agent  (runs on customer endpoints)
     → Scans locally for AI tools, shadow AI, and misconfigurations
     → Phones home securely using the customer agent token
          ↓
Sentinel Server  (cloud or on-premises)
     → Stores all findings in the per-customer isolated database
     → Runs risk scoring (0–100) and compliance assessments
     → Serves the customer dashboard
          ↓
Customer Dashboard  (web browser)
     → Full visibility into all discovered AI assets and risk scores
     → Remediation guidance, compliance reports, real-time alerts
```

### Deployment Options

- **Cloud-hosted (SaaS):** Customer installs the agent, data goes to your Sentinel server. Fastest to deploy.
- **On-premises:** Customer runs everything in their own environment. Required for high-security environments.
- **Hybrid:** Agent on-prem, dashboard cloud-hosted.

### Agent Installation

| Platform | Method |
|---|---|
| macOS / Linux | Single curl command → runs as background daemon |
| Windows | Single PowerShell command → installs as Windows service (auto-starts on reboot) |
| Server / Docker | Container deployment for server environments |

First findings appear within the first scan cycle. Full assessment report within 24 hours of first scan. Ongoing monitoring from day one.

### Multi-Tenancy

Sentinel is fully multi-tenant:
- Each customer has a completely isolated database — no data crossover is possible
- Each customer has their own unique agent token
- Per-customer plan, seat limits, and expiry are managed centrally
- Customers only ever see their own devices and findings

### Licensing

**Plans:**

| Plan | What's included |
|---|---|
| Demo | Full feature access, reports watermarked. For trials and evaluations. |
| Standard | Executive and CISO reports. Core discovery and risk register. |
| Plus | Full access — technical reports, evidence package, API tester, no watermarks. |

Seats = number of active agent endpoints (devices being monitored). 0 = unlimited.

---

## PART 4: DEMO FLOW (30–45 minutes)

### Step 1: The Problem Setup (5 min)

Open with a question:
> "How many AI tools do you think are running in your environment right now?"

Let them answer. Then:
> "Most organizations think it's 3–5. When we actually scan, it's usually 20–50. That's Shadow AI — and it's the #1 AI security risk right now."

**Key talking points:**
- Employees use AI tools without IT knowing
- Sensitive data goes to third-party AI providers with no oversight
- No visibility = no security
- Regulators are starting to require AI governance documentation

### Step 2: Live Discovery Demo (10 min)

Show the dashboard — specifically the Connected Devices view.

> "Every one of these machines has a Sentinel agent running. It checks in continuously and reports everything it finds. Let me show you what we discovered…"

Show:
- List of connected devices across platforms (Mac, Windows, Linux)
- Last seen timestamps — all live
- Risk dots (red = critical findings, yellow = warnings, green = clean)
- Shadow AI count and MCP Server count

> "Your team probably doesn't know half of these AI services are there."

### Step 3: The Risk Register (10 min)

Navigate to Risk Register.

> "Every finding goes into the Risk Register. Scored by severity — Critical, High, Medium, Low. Each one maps to the industry frameworks your compliance team needs."

Click a CRITICAL finding. Walk through:
- What the finding is (in plain English)
- Why it's a risk (business impact)
- The specific remediation steps
- Which compliance controls are affected

> "This is what an auditor would ask for. We generate this automatically, continuously."

### Step 4: MCP Servers (5 min)

Navigate to MCP Servers tab.

> "This is new territory for most security teams. MCP servers are the interfaces AI agents use to call tools — file systems, databases, APIs, shell commands. If these aren't locked down, an AI agent can be manipulated into doing almost anything."

Show the tool exposure breakdown and risk scores.

### Step 5: The Report (5 min)

Generate or open a PDF report.

> "This is what gets delivered to leadership. Plain English, prioritized by risk, specific next steps. The executive can read this without a security background."

Show the compliance section:
> "And if they need it for a compliance audit, here's the artifact. Mapped to whatever framework applies — NIST, CMMC, FedRAMP. Ready to hand to an auditor."

### Step 6: API Security Tester (5 min — if applicable)

Navigate to API Tester.

> "If you're running your own AI API — a custom model, an internal assistant, an AI-powered product — we can test it live right now. Enter the endpoint and key, and we'll run 8 adversarial probes against it in under 5 minutes."

Walk through what the 8 checks cover.

> "Most AI APIs fail at least 2 of these out of the box. Now you know before your customers find out the hard way."

### Step 7: Business Model Conversation (5–10 min)

> "Here's how this works for your business."

Options depending on who you're talking to:

- **Reseller:** License Sentinel, resell to your clients with margin. You own the customer relationship.
- **Assessment service:** Run AI security assessments as a billable service. Sentinel produces the deliverable.
- **Embedded:** Include AI Security Assessment in every project. Makes every engagement more complete.

> "You're not selling software. You're selling AI security assurance. Your clients pay for the peace of mind."

---

## PART 5: Q&A — QUESTIONS YOU'LL GET

**Q: How does the agent get installed on client endpoints?**
A: Single command install — curl on Mac/Linux, PowerShell on Windows. Runs silently as a background daemon or Windows service. Can also be deployed via Jamf, Intune, Ansible, SCCM, or any endpoint management tool. Takes about 10 minutes per machine.

**Q: What data does the agent send back?**
A: Only metadata — process names, network connection patterns, configuration findings. No file contents, no user data, no PII. The agent is read-only and reports findings; it never touches production data.

**Q: Can it be deployed in air-gapped or on-premises environments?**
A: Yes. On-premises deployment means everything stays inside the customer's environment. No data leaves their network.

**Q: What frameworks does it map to?**
A: NIST AI RMF, OWASP LLM Top 10, FedRAMP, CMMC 2.0, and the AI-STIG baseline. Custom frameworks available on request.

**Q: How is it priced?**
A: Per-agent (per endpoint) licensing with annual plans. Demo for trials, Standard for core use cases, Plus for full compliance and technical depth. Volume discounts for larger deployments.

**Q: What's the implementation timeline?**
A: Agent installed in under 10 minutes. First findings within the first scan. Full assessment report within 24 hours. Ongoing monitoring from day one.

**Q: Can multiple clients be on the same platform?**
A: Yes — fully multi-tenant. Each client has a completely isolated database and unique agent token. They can never see each other's data.

**Q: How does this compare to traditional security tools?**
A: Traditional tools (EDR, SIEM, vulnerability scanners) focus on traditional threats — malware, network intrusions, CVEs. Sentinel is purpose-built for AI-specific risks: what a prompt injection looks like, what AI supply chain risk means, how agentic AI can be exploited. There's nothing else that does this specifically.

**Q: Do you support on-premises deployment for government or high-security clients?**
A: Yes. The entire Sentinel stack can run on-premises. No cloud dependency required.

**Q: What happens if an agent goes offline?**
A: The dashboard flags it as stale after a configurable threshold. Alerts can be sent via webhook, Slack, email, or PagerDuty when a device goes silent.

---

## PART 6: KEY DIFFERENTIATORS

1. **Purpose-built for AI** — Not a general security tool retrofitted for AI. Built from the ground up to understand AI-specific risks.

2. **Shadow AI detection** — Finds what nobody approved. Most competitors assume you know what AI you have. Sentinel assumes you don't.

3. **MCP server visibility** — The only platform with dedicated visibility into agentic AI tool exposure.

4. **Live adversarial testing** — Not just configuration checks. Actually probes AI APIs with real attack techniques.

5. **Compliance-ready output** — Reports mapped to NIST, OWASP, FedRAMP, CMMC. Auditor-ready on day one.

6. **No auto-remediation** — Advisory only. Every fix requires human approval. Customers stay in control.

7. **Fully multi-tenant** — Built for MSPs and consultants managing multiple clients from one platform.

---

## PART 7: LEARNING CHECKLIST

### Foundation
- [ ] I can explain what Shadow AI is and why it's a risk (in 60 seconds)
- [ ] I can explain what Sentinel does at a high level (in 30 seconds)
- [ ] I can explain the difference between the agent and the server
- [ ] I know what the Risk Register is and how findings get scored
- [ ] I know the 7 check categories and can give one example for each

### Technical
- [ ] I can explain how the agent is deployed on Mac, Windows, and Linux
- [ ] I know what data the agent does and doesn't collect
- [ ] I can explain the three deployment models (cloud, on-prem, hybrid)
- [ ] I understand the licensing model (Demo / Standard / Plus, seats = active agents)
- [ ] I can explain what MCP servers are and why they're a risk

### Sales
- [ ] I can run the demo flow from memory
- [ ] I can answer all Q&A questions in Part 5
- [ ] I can explain the three business model options (reseller, service, embedded)
- [ ] I know Sentinel's key differentiators vs. general security tools
- [ ] I can explain the API Tester and when to use it in a demo

---

*Document maintained by M.A.R.K. AI Systems | Updated June 2026*
