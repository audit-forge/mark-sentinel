CMMC Mappings — Draft

This document contains proposed CMMC (Level 2) mappings for each AI-STIG check.
The mappings below use CMMC practice families (high-level) as a starting point
for reviewers and auditors. After review we will replace family-level links with
specific practice identifiers (e.g., AC.1.001) where appropriate.

Mapping guidance:
- AC = Access Control
- IA = Identification & Authentication
- SI = System & Information Integrity
- CM = Configuration Management
- PL = Planning
- IR = Incident Response
- MP = Media Protection
- AU = Audit & Accountability
- SC = System & Communications Protection

Proposed mappings
- AI-DEPLOY-001: API Keys Not Exposed — CMMC: AC, IA, AU
- AI-DEPLOY-002: No Hardcoded Credentials — CMMC: CM, AC
- AI-DEPLOY-003: Logging Enabled and Retained — CMMC: AU, SI
- AI-DEPLOY-004: Access Controls on AI Endpoint — CMMC: AC, IA
- AI-DEPLOY-005: TLS/HTTPS Enforced — CMMC: SC, SI
- AI-DEPLOY-006: Rate Limiting Configured — CMMC: SC, SI

- AI-INP-001: System Prompt Cannot Be Overridden — CMMC: SI, PL
- AI-INP-002: Direct Prompt Injection Resistance — CMMC: SI, IA
- AI-INP-003: Indirect Prompt Injection (RAG) — CMMC: CM, SI
- AI-INP-004: Jailbreak Resistance — CMMC: SI
- AI-INP-005: Input Length/Token Limits — CMMC: SI

- AI-OUT-001: Model Does Not Return Training Data — CMMC: MP, SI
- AI-OUT-002: PII Not Leaked in Responses — CMMC: MP, AU, SI
- AI-OUT-003: System Prompt Not Disclosed on Request — CMMC: SI
- AI-OUT-004: Model Refusals Work — CMMC: SI, PL
- AI-OUT-005: Output Sanitization — CMMC: SI, CM

- AI-AGENT-001: Tool/Function Permissions Least Privilege — CMMC: AC, CM
- AI-AGENT-002: Agent Cannot Take Destructive Actions — CMMC: AC, IR
- AI-AGENT-003: Memory/Context Poisoning — CMMC: SI, CM
- AI-AGENT-004: Inter-Agent Trust — CMMC: AC, SI
- AI-AGENT-005: Agent Action Logs Captured — CMMC: AU, SI
- AI-AGENT-006: Agent Cannot Exfiltrate Data — CMMC: SC, SI, AU

- AI-SUPPLY-001: Model Provenance Documented — CMMC: CM, PL
- AI-SUPPLY-002: Model Source Verified — CMMC: CM, SI
- AI-SUPPLY-003: Dependencies from Approved Sources — CMMC: CM, SI
- AI-SUPPLY-004: No Shadow AI / Unsanctioned Model — CMMC: AC, AU
- AI-SUPPLY-005: Model Version Pinned — CMMC: CM

- AI-GOV-001: AI Usage Policy Documented — CMMC: PL
- AI-GOV-002: Data Retention Policy Covers AI — CMMC: PL, MP
- AI-GOV-003: AI Incident Response Plan Exists — CMMC: IR, AU
- AI-GOV-004: Human Oversight Mechanisms — CMMC: PL, AC
- AI-GOV-005: AI System Documented in Asset Inventory — CMMC: CM, PL

Notes:
- These are draft high-level mappings. Next step: map each to specific CMMC practice IDs (AC.1.001, AC.2.005, etc.) where an authoritative mapping exists.
- After review, update the 'frameworks' field in each CheckResult in the checks modules to include the concrete CMMC controls.

Request:
- If this draft looks correct, I will apply the mappings into the code (checks/*) and update tests to assert presence of CMMC mappings in the compliance output.
