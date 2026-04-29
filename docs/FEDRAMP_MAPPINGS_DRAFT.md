FedRAMP / NIST 800-53 Mappings — Draft

Purpose
This draft maps each AI-STIG check to relevant NIST 800-53/FedRAMP control families and example control identifiers. It parallels the CMMC families draft and is intended as the starting point for a precise control-ID pass.

Mapping guidance (families → examples)
- AC = Access Control (example: AC-2, AC-3)
- IA = Identification & Authentication (example: IA-2)
- AU = Audit and Accountability (example: AU-2, AU-6)
- SI = System and Information Integrity (example: SI-2, SI-10)
- SC = System and Communications Protection (example: SC-8, SC-7)
- CM = Configuration Management (example: CM-2, CM-6)
- PL = Planning (example: PL-2)
- IR = Incident Response (example: IR-4)
- MP = Media Protection (example: MP-6)

Proposed mappings (per-check)
- AI-DEPLOY-001: API Keys Not Exposed — FedRAMP/NIST: AC (AC-2/AC-3), IA (IA-5), AU (AU-2)
- AI-DEPLOY-002: No Hardcoded Credentials — FedRAMP/NIST: CM (CM-2, CM-6), AC (AC-3)
- AI-DEPLOY-003: Logging Enabled and Retained — FedRAMP/NIST: AU (AU-2, AU-6), SI (SI-4)
- AI-DEPLOY-004: Access Controls on AI Endpoint — FedRAMP/NIST: AC (AC-3), SC (SC-7), IA (IA-2)
- AI-DEPLOY-005: TLS/HTTPS Enforced — FedRAMP/NIST: SC (SC-8), SC-13, SI (SI-10)
- AI-DEPLOY-006: Rate Limiting Configured — FedRAMP/NIST: SC (SC-5/SC-7), SI (SI-4)

- AI-INP-001: System Prompt Cannot Be Overridden — FedRAMP/NIST: SI (SI-10), PL (PL-2)
- AI-INP-002: Direct Prompt Injection Resistance — FedRAMP/NIST: SI (SI-10), SC (SC-7)
- AI-INP-003: Indirect Prompt Injection (RAG) — FedRAMP/NIST: CM (CM-3), SI (SI-10)
- AI-INP-004: Jailbreak Resistance — FedRAMP/NIST: SI (SI-10)
- AI-INP-005: Input Length/Token Limits — FedRAMP/NIST: SI (SI-4), SC (SC-5)

- AI-OUT-001: Model Does Not Return Training Data — FedRAMP/NIST: MP (MP-6), SI (SI-12)
- AI-OUT-002: PII Not Leaked in Responses — FedRAMP/NIST: MP (MP-6), AU (AU-6), SI (SI-4)
- AI-OUT-003: System Prompt Not Disclosed on Request — FedRAMP/NIST: SI (SI-10)
- AI-OUT-004: Model Refusals Work — FedRAMP/NIST: PL (PL-2), SI (SI-10)
- AI-OUT-005: Output Sanitization — FedRAMP/NIST: SI (SI-10), CM (CM-6)

- AI-AGENT-001: Tool/Function Permissions Least Privilege — FedRAMP/NIST: AC (AC-6), CM (CM-6)
- AI-AGENT-002: Agent Cannot Take Destructive Actions — FedRAMP/NIST: AC (AC-6), IR (IR-4)
- AI-AGENT-003: Memory/Context Poisoning — FedRAMP/NIST: SI (SI-10), CM (CM-3)
- AI-AGENT-004: Inter-Agent Trust — FedRAMP/NIST: AC (AC-3), SI (SI-10)
- AI-AGENT-005: Agent Action Logs Captured — FedRAMP/NIST: AU (AU-2, AU-6), SI (SI-4)
- AI-AGENT-006: Agent Cannot Exfiltrate Data — FedRAMP/NIST: SC (SC-7), SI (SI-10), AU (AU-6)

- AI-SUPPLY-001: Model Provenance Documented — FedRAMP/NIST: CM (CM-2, CM-8), PL (PL-2)
- AI-SUPPLY-002: Model Source Verified — FedRAMP/NIST: CM (CM-2), SI (SI-7)
- AI-SUPPLY-003: Dependencies from Approved Sources — FedRAMP/NIST: CM (CM-2, CM-6), SI (SI-7)
- AI-SUPPLY-004: No Shadow AI / Unsanctioned Model — FedRAMP/NIST: AU (AU-6), AC (AC-2)
- AI-SUPPLY-005: Model Version Pinned — FedRAMP/NIST: CM (CM-2)

- AI-GOV-001: AI Usage Policy Documented — FedRAMP/NIST: PL (PL-2)
- AI-GOV-002: Data Retention Policy Covers AI — FedRAMP/NIST: MP (MP-6), PL (PL-2)
- AI-GOV-003: AI Incident Response Plan Exists — FedRAMP/NIST: IR (IR-4), AU (AU-6)
- AI-GOV-004: Human Oversight Mechanisms — FedRAMP/NIST: PL (PL-2), AC (AC-2)
- AI-GOV-005: AI System Documented in Asset Inventory — FedRAMP/NIST: CM (CM-2, CM-8), PL (PL-2)

Notes and next steps
- These are draft mappings using common NIST/FedRAMP control IDs as examples. The next pass will:
  1) Expand each family mapping to a small list of specific NIST control IDs (e.g., AC-2, AC-3) where applicable.
  2) Add machine-readable mapping in profiles/fedramp_controls.json to be consumed by the compliance formatter.
  3) Update CheckResult.frameworks entries in checks/* to include the FedRAMP control IDs.

- Rationale: mapping to NIST control IDs makes the compliance output immediately useful for FedRAMP assessments and NIST-aligned audits. It also allows automated cross-walks (e.g., feeding into an evidence tracker).

Request
- If this draft looks good, I will: create profiles/fedramp_controls.json, apply mappings into checks, update tests, and push commits to the phase3/compliance-artifacts branch.
