# AI-SUPPLY — Model & Supply Chain Integrity Checks

**Category:** Model & Supply Chain Integrity
**Check IDs:** AI-SUPPLY-001 through AI-SUPPLY-005
**Count:** 5 checks

Framework references: OWASP LLM03, LLM04 | OWASP Agentic OAGNT-08 | NIST AI RMF GOVERN 2.2, MAP 1.5 | FedRAMP CM-7, SA-12

---

## AI-SUPPLY-001: Model Provenance Known and Documented

**Severity:** HIGH
**Check type:** Config audit + documentation check

### Description
Verifies that the organization knows exactly which AI model they are using, where it came from, who created it, when it was trained, and what data it was trained on (to the extent disclosed by the provider). Provenance documentation is the foundation of AI supply chain security — you cannot manage a risk you haven't identified.

This is the AI equivalent of a software bill of materials (SBOM). Regulated environments increasingly require an "AI bill of materials" (AIBOM) documenting every AI model in the technology stack. Even for SMBs, knowing exactly what AI they're using is essential for incident response ("Was the vulnerability in the base model or our fine-tune?").

### SMB Explanation
Do you know exactly which AI model powers your assistant? Who made it? When was it last updated? This might seem like a technical detail, but if something goes wrong — if the AI starts behaving oddly, or if there's a security alert about a specific model — you need to know what you're running to know if you're affected. This check makes sure you have that basic information documented.

### PASS Criteria
- Model name, version, and provider are documented in system inventory
- Model training data sources documented to the extent available (from provider disclosure)
- Model architecture or API type documented (transformer, API-only, etc.)
- Known limitations and risk disclosures from provider documented
- Date of last model update or version check recorded
- For fine-tuned models: base model documented, fine-tuning dataset documented, fine-tune method documented

### FAIL Criteria
- No record of which specific model is in use (beyond "we use AI")
- Model version unknown ("latest" without pinning — covered in AI-SUPPLY-005)
- No documentation of base model when using a fine-tuned variant
- Fine-tuning dataset not inventoried or documented
- No record of when the model was last reviewed or updated

### Remediation
1. Create an AI asset inventory entry (see AI-GOV-005) for every model in use
2. For each model, record: provider, model ID, version, API endpoint, training data summary (from provider cards), known limitations
3. For fine-tuned models: document the base model, fine-tuning framework, dataset description, training date, and who performed the fine-tune
4. Set a quarterly calendar reminder to review model provenance — providers update models, publish new model cards, and issue security disclosures
5. Subscribe to provider security advisories (OpenAI, Anthropic, HuggingFace, Ollama all have security disclosure channels)

### Framework Mappings
| Framework | Control |
|---|---|
| OWASP LLM Top 10 | LLM03 — Supply Chain Vulnerabilities |
| OWASP Agentic Top 10 | OAGNT-08 — Compromised Third-Party Agents/Plugins |
| NIST AI RMF | GOVERN 2.2 — Roles and responsibilities for AI risk; MAP 1.5 — Risk identification |
| FedRAMP / NIST 800-53 | SA-12 — Supply Chain Protection; CM-8 — System Component Inventory |
| CMMC 2.0 | SR.L2-3.17.1 — Identify and prioritize supply chain risks |

---

## AI-SUPPLY-002: Model Source Verified (Not a Tampered or Poisoned Variant)

**Severity:** CRITICAL
**Check type:** Hash verification + source audit

### Description
Verifies that model weights and binaries have not been tampered with since being obtained from the original source. A backdoored or poisoned model looks and behaves normally in routine use but is triggered by specific inputs that activate adversarial behavior — returning attacker-controlled outputs, leaking data, or enabling bypasses.

Model weight poisoning is a real and documented threat: compromised models have been found on HuggingFace and other model hosting platforms. "Pickle exploits" in `.pkl` model files can execute arbitrary code on load. This check is essential for any deployment using downloaded model weights rather than a trusted API.

### SMB Explanation
If you downloaded an AI model from the internet to run on your own computer, there's a chance it could have been tampered with before you downloaded it — either at the source or in transit. A malicious model looks identical to a real one but has been secretly modified to behave badly under certain conditions, or even to run malicious code when it loads. This check verifies you have the authentic, unmodified version.

### PASS Criteria
- Model file hashes verified against official checksums published by the model provider
- Model obtained from the official source (not a mirror, fork, or re-upload)
- For HuggingFace models: model is from a verified organization or has a high community trust score
- Model files loaded using safe loaders (safetensors format, not raw pickle) or in a sandboxed environment
- Hash verification performed at deployment time, not just at initial download

### FAIL Criteria
- No hash verification performed on downloaded model files
- Model obtained from an unofficial source, re-upload, or unverified mirror
- Model loaded using `torch.load()` with `weights_only=False` on an untrusted file (pickle RCE risk)
- Model file hash does not match official checksum
- No record of where the model was obtained from

### Remediation
1. Only download models from official, verified sources (provider's official HuggingFace org, official website, official container registry)
2. Verify SHA256 checksums after download: `sha256sum model.bin` — compare against official checksum published by the provider
3. Use safetensors format when available — it cannot execute arbitrary code on load, unlike pickle-based `.bin` files
4. For safetensors: `pip install safetensors` and load with `safetensors.torch.load_file()` instead of `torch.load()`
5. Re-verify hashes any time the model file is moved, copied, or restored from backup

### Framework Mappings
| Framework | Control |
|---|---|
| OWASP LLM Top 10 | LLM03 — Supply Chain Vulnerabilities; LLM04 — Data and Model Poisoning |
| OWASP Agentic Top 10 | OAGNT-08 — Compromised Third-Party Agents/Plugins |
| NIST AI RMF | MAP 1.5 — Risk identification; GOVERN 2.2 — Risk accountability |
| FedRAMP / NIST 800-53 | SA-12 — Supply Chain Protection; SI-7 — Software, Firmware, and Information Integrity; CM-7 — Least Functionality |
| CMMC 2.0 | SR.L2-3.17.2 — Protect supply chain; SI.L2-3.14.3 — Monitor security alerts |

---

## AI-SUPPLY-003: Dependencies and Plugins from Approved Sources Only

**Severity:** HIGH
**Check type:** Dependency audit + config review

### Description
Verifies that all libraries, frameworks, plugins, and extensions used in the AI stack — the LLM orchestration library, embedding models, vector store clients, agent frameworks, model serving software — are obtained from approved sources and reviewed for security. AI application dependencies have the same supply chain attack surface as any software project, with additional risk from AI-specific packages that may have access to model outputs, user data, or tool execution.

This includes: LangChain, LlamaIndex, AutoGen, and similar orchestration frameworks (which have had CVEs); HuggingFace transformers and related libraries; vector database clients; model serving frameworks like vLLM, Ollama, and LM Studio.

### SMB Explanation
Your AI tool is built on top of other software — libraries, plugins, add-ons that make it work. If any of those are obtained from unofficial sources, haven't been checked for security problems, or haven't been updated in a long time, they can be a backdoor into your system just like the main AI can. This check audits the entire stack, not just the AI itself.

### PASS Criteria
- All AI-related packages installed from official package repositories (PyPI, npm, Docker Hub official images) or the vendor's official download
- Installed package versions match approved list (or are within approved version range)
- Known-vulnerable versions of AI frameworks not in use (check CVE database for installed versions)
- Third-party AI plugins, extensions, and add-ons reviewed and approved before installation
- Dependencies tracked in a lockfile (requirements.txt with pinned versions, package-lock.json)

### FAIL Criteria
- Dependencies installed from unofficial or unknown sources
- Packages installed without version pinning (latest-only installs)
- Known CVEs present in installed AI framework versions (LangChain, transformers, vLLM, etc.)
- Third-party plugins installed without security review
- No dependency inventory — unknown what packages are installed

### Remediation
1. Run a dependency audit: `pip audit` (Python) or `npm audit` (Node.js) — fix or document all HIGH/CRITICAL findings
2. Pin all versions in requirements.txt or pyproject.toml — never use `langchain` without `langchain==0.x.x`
3. Use a software composition analysis (SCA) tool (Dependabot, Snyk, OWASP Dependency-Check) to monitor for new CVEs in installed packages
4. Review all third-party plugins: check GitHub stars, recent commits, issue tracker for security reports, and whether the package is maintained
5. Subscribe to security advisories for major AI frameworks used in your stack

### Framework Mappings
| Framework | Control |
|---|---|
| OWASP LLM Top 10 | LLM03 — Supply Chain Vulnerabilities |
| OWASP Agentic Top 10 | OAGNT-08 — Compromised Third-Party Agents/Plugins |
| NIST AI RMF | GOVERN 2.2 — Risk accountability; MAP 1.5 — Risk identification |
| FedRAMP / NIST 800-53 | SA-12 — Supply Chain Protection; CM-7 — Least Functionality; SA-15 — Development Process |
| CMMC 2.0 | SR.L2-3.17.1 — Identify supply chain risks; CM.L2-3.4.1 — Establish configuration baselines |

---

## AI-SUPPLY-004: No Shadow AI / Unsanctioned Model in Use

**Severity:** HIGH
**Check type:** Config audit + network scan + process inspection

### Description
Verifies that the organization's AI deployment does not include AI models or services that were installed or used without organizational knowledge or approval — "shadow AI." This includes: employees using personal AI API keys for work tasks, unauthorized local model installations, AI features embedded in approved software that were not reviewed, and AI-powered browser extensions or productivity tools used for work data.

Shadow AI is a significant risk in 2025-2026: AI features are embedded in productivity tools (Google Workspace, Microsoft 365, Slack, Notion) and may be processing work data without explicit awareness. Employees under productivity pressure may use unauthorized AI tools on work data.

### SMB Explanation
"Shadow AI" means AI tools that people in your organization are using without you knowing about it. Maybe an employee is pasting customer data into a personal ChatGPT account to save time, or installed an AI plugin on their work computer without asking. This can expose your customers' data to third-party services you haven't reviewed or agreed to. This check looks for AI usage that wasn't officially approved.

### PASS Criteria
- Inventory of all AI services, tools, and models in use — no unknown AI components running
- Network egress monitoring shows no connections to AI provider APIs outside the approved list
- Employee AI usage policy exists and has been communicated (see AI-GOV-001)
- AI features in approved tools (Office, Google Workspace, etc.) explicitly reviewed and configured per policy
- Process scan (for local deployments) shows no unauthorized model serving processes running

### FAIL Criteria
- Outbound connections to AI provider APIs not in the approved inventory (OpenAI, Anthropic, Cohere, etc.)
- Local Ollama, LM Studio, or similar model serving software running without authorization
- AI plugins in browsers or productivity tools processing work data without approval
- Employees acknowledging use of personal AI accounts for work data in surveys/assessments
- AI features in approved software enabled by default and never reviewed

### Remediation
1. Establish and communicate an AI use policy: which tools are approved, which are prohibited, what data may be processed by AI
2. Conduct a one-time shadow AI discovery: query your DNS/network logs for connections to ai.openai.com, api.anthropic.com, generativelanguage.googleapis.com, and other AI API endpoints — match against approved services
3. Review AI features in all approved software (Microsoft Copilot, Google Gemini for Workspace, Slack AI) — decide which to enable, which to disable
4. For regulated environments: deploy DNS filtering to block unauthorized AI API endpoints
5. Create an easy, approved AI request path — shadow AI thrives when the official path is slow or unavailable

### Framework Mappings
| Framework | Control |
|---|---|
| OWASP LLM Top 10 | LLM03 — Supply Chain Vulnerabilities |
| OWASP Agentic Top 10 | OAGNT-08 — Compromised Third-Party Agents/Plugins |
| NIST AI RMF | GOVERN 2.2 — Risk accountability; GOVERN 1.1 — Organizational AI policies |
| FedRAMP / NIST 800-53 | CM-7 — Least Functionality; CM-8 — System Component Inventory; PL-8 — Security and Privacy Architectures |
| CMMC 2.0 | CM.L2-3.4.6 — Employ principle of least functionality; CM.L2-3.4.7 — Restrict non-essential software |

---

## AI-SUPPLY-005: Model Version Pinned (Not Floating Latest)

**Severity:** MEDIUM
**Check type:** Config audit

### Description
Verifies that the AI deployment uses a pinned, specific model version rather than a floating "latest" or unversioned reference. Model providers silently update models under the same name (GPT-4o today is not the same model as GPT-4o in 6 months), and these updates can change behavior, safety posture, output format, and capability in ways that break existing deployments or introduce new risks.

Pinning model versions is the AI equivalent of pinning software dependency versions — it ensures consistent, testable, auditable behavior over time.

### SMB Explanation
When you say "use the latest version of GPT-4," the company can swap in a completely different model anytime they update. Your AI might behave very differently one day compared to the next because the model changed without warning. Pinning to a specific version means your AI behaves consistently and you know exactly what you're running — you only update when you decide to, after testing.

### PASS Criteria
- Model version specified by exact version identifier (e.g., `gpt-4o-2024-11-20`, not `gpt-4o`)
- Version identifier in config is not `latest`, `current`, or equivalent floating reference
- Local models (Ollama, vLLM) use a specific tagged version, not `model:latest`
- Version change process exists: when updating model version, test suite is run before deploying to production
- Model version documented in asset inventory alongside the deployment it powers

### FAIL Criteria
- Model configured as `gpt-4o` without a date-version suffix (floats to current)
- Ollama model config uses `:latest` tag
- No process for evaluating behavior changes when model provider updates the referenced version
- Model version in config different from model version in inventory (configuration drift)

### Remediation
1. Check your current model configuration — if it says `gpt-4o`, `claude-3-5-sonnet`, or similar without a version date, it is floating
2. Update to pinned version: `gpt-4o-2024-11-20`, `claude-3-5-sonnet-20241022`, etc. — provider docs list all available version identifiers
3. For Ollama: pull with a specific digest or tag rather than `:latest`; use `ollama pull model:version` and record the SHA in your inventory
4. Create a quarterly model review process: evaluate new versions against your test suite before upgrading
5. Document current pinned versions in your AI asset inventory (AI-GOV-005)

### Framework Mappings
| Framework | Control |
|---|---|
| OWASP LLM Top 10 | LLM03 — Supply Chain Vulnerabilities |
| NIST AI RMF | GOVERN 2.2 — Risk accountability; MAP 1.5 — Risk identification |
| FedRAMP / NIST 800-53 | CM-6 — Configuration Settings; CM-3 — Configuration Change Control; SA-12 — Supply Chain Protection |
| CMMC 2.0 | CM.L2-3.4.1 — Establish configuration baselines; CM.L2-3.4.2 — Establish and enforce security configuration settings |
