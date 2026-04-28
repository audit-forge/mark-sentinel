# AI-GOV — Governance & Compliance Posture Checks

**Category:** Governance & Compliance Posture
**Check IDs:** AI-GOV-001 through AI-GOV-005
**Count:** 5 checks

Framework references: OWASP LLM10 | OWASP Agentic OAGNT-09, OAGNT-10 | NIST AI RMF GOVERN 1.1-6.2 | FedRAMP PL-1, IR-1

---

## AI-GOV-001: AI Usage Policy Documented

**Severity:** HIGH
**Check type:** Documentation audit

### Description
Verifies that the organization has a written AI usage policy that defines: which AI tools and services are approved for use, which categories of data may and may not be processed by AI, employee responsibilities around AI use, and consequences for policy violations. Without a policy, there is no basis for enforcement, no guidance for employees, and no compliance evidence.

This is the foundational governance control. Every other governance check depends on having a policy that defines the expected state. For regulated environments, a documented AI usage policy is increasingly a formal compliance requirement (EU AI Act requires written policies for high-risk AI; FedRAMP requires documented security plans covering all system components including AI).

### SMB Explanation
A written AI policy is your rulebook for how AI gets used in your business. It answers questions like: "Can employees paste customer data into ChatGPT?" "Which AI tools are we allowed to use?" "Who's responsible if something goes wrong?" Without this document, your team has no guidance and you have no way to hold anyone accountable. This check makes sure the policy exists.

### PASS Criteria
- Written AI usage policy exists and is accessible to all relevant employees
- Policy defines approved AI tools and services
- Policy defines prohibited uses (e.g., "no confidential client data in third-party AI tools without DPA")
- Policy addresses data classification — which data tiers may be processed by which AI tools
- Policy defines who is responsible for AI governance
- Policy reviewed and signed/acknowledged within the last 12 months
- Policy version-controlled with a last-updated date

### FAIL Criteria
- No written AI policy exists
- Policy exists but has never been communicated to employees
- Policy references specific tools that are no longer in use (stale)
- Policy does not address data classification for AI use
- Policy has not been reviewed in more than 12 months
- Policy does not assign accountability for AI governance

### Remediation
1. Draft a minimal AI policy (even one page is better than nothing) covering: approved tools, prohibited data types, responsible party
2. Have legal or compliance review the policy for any regulatory requirements specific to your industry (HIPAA, PCI, GDPR)
3. Communicate the policy to all employees via email + acknowledgment signature
4. Publish in your internal wiki or intranet so it's easily accessible
5. Set a 12-month review calendar reminder — policies go stale as the AI landscape changes rapidly
6. M.A.R.K. Sentinel provides a policy template in `docs/SMB_GUIDE.md` as a starting point

### Framework Mappings
| Framework | Control |
|---|---|
| OWASP LLM Top 10 | LLM10 — Unbounded Consumption (policy as the control layer) |
| OWASP Agentic Top 10 | OAGNT-10 — Inadequate Governance and Compliance Controls |
| NIST AI RMF | GOVERN 1.1 — Policies, processes, and accountability; GOVERN 1.2 — Accountability for AI risk management |
| FedRAMP / NIST 800-53 | PL-1 — Policy and Procedures; PL-2 — System Security and Privacy Plans |
| CMMC 2.0 | CA.L2-3.12.1 — Periodically assess security controls |
| EU AI Act | Article 9 — Risk management; Article 13 — Transparency obligations |

---

## AI-GOV-002: Data Retention and Deletion Policy Covers AI Interactions

**Severity:** HIGH
**Check type:** Documentation audit + config verification

### Description
Verifies that the organization's data retention and deletion policy explicitly covers AI interaction data — conversation logs, prompts, responses, embeddings, fine-tuning datasets, and any data processed by AI models. AI interaction data is often overlooked in data governance because it doesn't fit neatly into existing categories like "user records" or "financial data."

This is a compliance requirement in many jurisdictions: GDPR requires data minimization and defined retention periods; HIPAA requires knowing where PHI is stored (including AI logs); CCPA requires the ability to fulfill deletion requests that span all data including AI conversation logs.

### SMB Explanation
If a customer asks "delete all my data," do you know if that includes the conversations they had with your AI assistant? If your AI logs conversations (which it should, for security), you need a clear policy for how long you keep those logs, who can access them, and how to delete them when required. This check makes sure you've thought through the data lifecycle for AI-generated data.

### PASS Criteria
- Data retention policy explicitly includes AI interaction logs, conversation history, and embeddings
- Retention periods defined and technically enforced (not just documented aspirationally)
- Deletion process for AI interaction data defined and tested — including from vector stores, fine-tuning datasets, and backup systems
- Data subject rights requests (GDPR Article 17, CCPA deletion) process covers AI data
- Training data and fine-tuning datasets subject to retention/deletion policy

### FAIL Criteria
- Retention policy does not mention AI interaction data
- AI conversation logs retained indefinitely with no policy
- No deletion process for AI data when required (e.g., when a customer account is deleted)
- Fine-tuning dataset not covered by the policy — retained indefinitely
- Retention period defined in policy but not technically enforced (logs actually stored forever)

### Remediation
1. Audit where AI interaction data is stored: conversation logs, vector store embeddings, fine-tuning datasets, model provider's data retention settings
2. Add explicit AI data categories to your retention policy with defined retention periods
3. Configure technical enforcement: log rotation, vector store TTLs, provider data retention settings
4. Document the deletion process for AI data as part of your data subject rights procedure
5. Check your AI provider's data retention settings — OpenAI, Anthropic, and others have configurable retention periods; opt for minimum retention consistent with your operational needs

### Framework Mappings
| Framework | Control |
|---|---|
| OWASP LLM Top 10 | LLM02 — Sensitive Information Disclosure |
| OWASP Agentic Top 10 | OAGNT-10 — Inadequate Governance and Compliance Controls |
| NIST AI RMF | GOVERN 1.1 — Organizational AI policies; MAP 1.5 — Risk identification |
| FedRAMP / NIST 800-53 | SI-12 — Information Management and Retention; AU-11 — Audit Record Retention |
| CMMC 2.0 | AU.L2-3.3.1 — Create audit logs; MP.L2-3.8.3 — Sanitize or destroy media |
| GDPR | Article 5(1)(e) — Storage limitation; Article 17 — Right to erasure |
| CCPA | Section 1798.100 — Consumer right to deletion |

---

## AI-GOV-003: AI Incident Response Plan Exists

**Severity:** HIGH
**Check type:** Documentation audit

### Description
Verifies that the organization has a documented plan for responding to AI-specific security incidents. AI incidents are a distinct category from standard security incidents: they include prompt injection attacks, data leakage via model outputs, model misbehavior causing reputational harm, AI-enabled fraud, and supply chain compromises of model weights or AI dependencies.

Standard incident response plans (IR plans) typically don't cover: how to determine if a model has been compromised, how to quickly disable AI features while maintaining other services, how to assess the scope of a prompt injection attack across conversation logs, or who the AI vendor point of contact is for incident escalation.

### SMB Explanation
If something goes wrong with your AI — it starts saying inappropriate things, it leaks a customer's data, or someone hacks it — what do you do? Who do you call? How do you turn it off quickly? An incident response plan answers all these questions before the emergency happens. This check makes sure you have that plan written down before you need it.

### PASS Criteria
- Written AI incident response plan exists (can be an annex to an existing IR plan)
- Plan defines AI-specific incident categories (data leakage, injection attack, model misbehavior, supply chain compromise)
- Plan includes: detection triggers, immediate containment steps (how to disable AI quickly), investigation procedures, notification requirements, recovery steps
- Key contacts documented: AI vendor security contacts, internal response team, legal/compliance
- Plan tested or tabletop exercised in the last 12 months
- Escalation path for AI incidents that may involve regulatory reporting (GDPR breach notification, etc.)

### FAIL Criteria
- No IR plan covering AI incidents
- Standard IR plan does not address AI-specific scenarios
- No documented procedure to disable AI quickly if needed
- AI vendor security contact not documented
- Plan never tested or exercised

### Remediation
1. Start with the five questions: (1) What counts as an AI incident? (2) Who do I call first? (3) How do I disable AI quickly? (4) How do I preserve evidence? (5) Who needs to be notified?
2. Document the kill switch: how to disable the AI service in under 5 minutes without taking down other systems
3. Add AI vendor contacts: every AI provider has a security contact or abuse reporting address — document them
4. Identify regulatory notification requirements: if AI leaks PII, which privacy laws require breach notification and within what timeframe?
5. Schedule a tabletop exercise — even a 30-minute walkthrough of a hypothetical prompt injection incident is valuable

### Framework Mappings
| Framework | Control |
|---|---|
| OWASP LLM Top 10 | LLM10 — Unbounded Consumption; LLM02 — Sensitive Information Disclosure |
| OWASP Agentic Top 10 | OAGNT-09 — Insufficient Audit and Observability; OAGNT-10 — Inadequate Governance |
| NIST AI RMF | MANAGE 4.1 — AI incident response and recovery; MANAGE 3.1 — Risk mitigation feedback |
| FedRAMP / NIST 800-53 | IR-1 — Incident Response Policy and Procedures; IR-4 — Incident Handling; IR-6 — Incident Reporting |
| CMMC 2.0 | IR.L2-3.6.1 — Establish incident handling capability; IR.L2-3.6.2 — Track and report incidents |

---

## AI-GOV-004: Human Oversight Mechanisms in Place for High-Stakes Decisions

**Severity:** HIGH
**Check type:** Architecture + process review

### Description
Verifies that for AI systems making or influencing high-stakes decisions — hiring, credit, medical triage, legal advice, law enforcement, financial approvals — there is a human review process in place that provides meaningful oversight and the ability to override the AI recommendation. "Meaningful" oversight means a human who has enough information, context, and authority to actually override the AI, not just rubber-stamp it.

This is both a governance best practice and an emerging regulatory requirement: the EU AI Act prohibits fully automated high-risk AI decision-making without human oversight; NIST AI RMF requires documented human control mechanisms; many US state AI laws have notification and override requirements.

### SMB Explanation
If your AI is helping make important decisions — like whether to give someone a loan, whether to hire a job candidate, or whether to flag a transaction as fraud — a real human needs to be in the loop. The AI should inform the decision, not make it alone. This check makes sure high-stakes AI decisions always have a human review step with the authority to say "the AI got this wrong."

### PASS Criteria
- High-stakes decision categories identified and documented (what constitutes a high-stakes decision in this context)
- Human review step is mandatory before high-stakes AI recommendations are acted upon
- Human reviewers have access to enough context to evaluate AI recommendations critically (not just "approve/deny")
- Override mechanism exists and has been used at least once (indicates it's actually functional)
- Audit trail captures both AI recommendation and human decision (with divergence tracking)
- Human reviewers trained on how the AI makes recommendations and what its known failure modes are

### FAIL Criteria
- AI makes consequential decisions with no human review
- Human review exists in name but humans lack the information or authority to override
- No mechanism to override an AI decision after it has been executed
- Override events not logged (cannot assess whether human oversight is functioning)
- High-stakes use cases not identified — humans don't know which decisions need oversight

### Remediation
1. Map your AI use cases against a severity matrix: low-stakes (no special requirements) vs. high-stakes (mandatory human review)
2. For each high-stakes use case, define: who reviews, what information they see, how they override, and what the SLA is for review turnaround
3. Design the UX for human reviewers to surface AI reasoning, not just the recommendation
4. Create a quarterly report on AI-human divergence rate: how often do humans override the AI? A 0% override rate may indicate rubber-stamping
5. For regulated environments: document oversight mechanisms in your AI system documentation for auditors

### Framework Mappings
| Framework | Control |
|---|---|
| OWASP LLM Top 10 | LLM06 — Excessive Agency |
| OWASP Agentic Top 10 | OAGNT-06 — Unauthorized Actions / Lack of Human Oversight |
| NIST AI RMF | GOVERN 6.1 — Risk management accountability; MANAGE 1.3 — Risk mitigation; GOVERN 1.7 — AI risk tolerance |
| FedRAMP / NIST 800-53 | PL-1 — Policy and Procedures; AC-2 — Account Management (human oversight of automated decisions) |
| CMMC 2.0 | CA.L2-3.12.3 — Monitor security controls |
| EU AI Act | Article 14 — Human oversight; Article 9 — Risk management |

---

## AI-GOV-005: AI System Documented in Asset Inventory

**Severity:** MEDIUM
**Check type:** Documentation audit + discovery scan

### Description
Verifies that every AI system and model in use is catalogued in the organization's asset inventory, with sufficient detail to support security assessments, incident response, and compliance reporting. An AI system not in inventory cannot be managed, monitored, updated, or secured.

This is the "AI bill of materials" (AIBOM) requirement in practice: knowing what AI you have before you can manage its risks. It is also the prerequisite for almost every other governance check — you cannot assess or remediate risks in a system you don't know exists.

### SMB Explanation
Do you have a list somewhere of all the AI tools your business uses? Not just "we use ChatGPT" but exactly which account, which API key, which version, who set it up, and what it's used for? This is like a hardware inventory or a software license list, but for AI. Without it, you can't reliably find problems, respond to incidents, or know when something changes. This check makes sure that list exists.

### PASS Criteria
- Inventory exists listing all AI systems and models in use
- Each entry includes: AI system name, provider, model ID/version, purpose, owner, API keys used (reference only — not the actual key), data processed, date added, last reviewed date
- Inventory includes both externally-hosted AI (OpenAI, Anthropic, etc.) and any locally-hosted models
- Inventory includes AI features in approved software (Copilot, Gemini for Workspace, etc.)
- Inventory reviewed at least quarterly — new systems added within 30 days of deployment
- Inventory accessible to security/compliance team for incident response

### FAIL Criteria
- No AI asset inventory exists
- Inventory exists but is not maintained (last updated >6 months ago)
- Inventory covers only some AI systems (e.g., only the "official" AI, not employee-used tools)
- Inventory does not include locally-hosted models
- Inventory contains no information about what data each AI system processes

### Remediation
1. Start with a spreadsheet if nothing else: columns for System Name, Provider, Model ID, Purpose, Owner, Data Processed, Date Added
2. Populate it today with every AI system you currently know about
3. For discovery of unknown systems: query network logs for AI provider API endpoints (see AI-SUPPLY-004)
4. Include AI features in software you're already paying for — Microsoft Copilot, Google Gemini, Slack AI, Notion AI
5. Build inventory maintenance into your change management process: any new AI deployment requires an inventory entry before it goes live
6. Review quarterly: verify existing entries are still accurate, remove decommissioned systems, add newly discovered shadow AI

### Framework Mappings
| Framework | Control |
|---|---|
| OWASP LLM Top 10 | LLM10 — Unbounded Consumption (inventory as the prerequisite for all controls) |
| OWASP Agentic Top 10 | OAGNT-10 — Inadequate Governance and Compliance Controls |
| NIST AI RMF | GOVERN 2.2 — Roles and responsibilities; MAP 1.1 — Context establishment |
| FedRAMP / NIST 800-53 | CM-8 — System Component Inventory; PL-2 — System Security and Privacy Plans |
| CMMC 2.0 | CM.L2-3.4.1 — Establish configuration baselines; CA.L2-3.12.4 — Develop system security plans |
| EU AI Act | Article 60 — EU database for high-risk AI; Article 51 — Registration obligations |
