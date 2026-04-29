"""
AI-SUPPLY checks — Model & Supply Chain Integrity
Checks: AI-SUPPLY-001 through AI-SUPPLY-005
All checks are evaluable in config mode.
"""
import re
from . import CheckResult, PASS, FAIL, WARN, SKIP
from connectors.config_connector import ScanContext

CATEGORY = "AI-SUPPLY"

# Floating model version patterns (should be pinned)
_FLOATING_MODEL_RE = re.compile(
    r'(?i)"model"\s*:\s*"(?:'
    r'gpt-4o"'                          # Unpinned gpt-4o
    r'|gpt-4"'                          # Unpinned gpt-4
    r'|gpt-3\.5-turbo"'                 # Unpinned gpt-3.5-turbo
    r'|claude-[a-z0-9-]+-(?:latest|current)"'
    r'|claude-sonnet"'
    r'|claude-opus"'
    r'|claude-haiku"'
    r'|llama[23]?"'                     # Floating llama
    r'|mistral"'
    r'|gemini-pro"'
    r'|gemini-flash"'
    r'|command-r"'
    r'|[a-zA-Z0-9-]+:latest"'           # :latest tag
    r')'
)

_PINNED_MODEL_RE = re.compile(
    r'(?i)"model"\s*:\s*"(?:'
    r'gpt-4o-\d{4}-\d{2}-\d{2}"'       # gpt-4o-2024-11-20
    r'|gpt-4-\d{4}"'                   # gpt-4-turbo with date
    r'|gpt-3\.5-turbo-\d{4}"'
    r'|claude-[a-z0-9-]+-\d{8}"'       # claude-3-5-sonnet-20241022
    r'|claude-[a-z0-9-]+-\d{4}-\d{2}-\d{2}"'
    r'|llama[23]?(?:\.\d+)?:\w+(?:-\w+)*"'  # llama3.1:8b-instruct-q4
    r'|[a-zA-Z0-9-]+:[a-zA-Z0-9._-]+(?:sha256:[a-f0-9]+)?"'  # model:version-sha256:abc
    r')'
)

_LATEST_TAG_RE = re.compile(r'(?i):\s*"?latest"?|"model"\s*:\s*"[^"]+:latest"')

# Unpinned dependency patterns (no version == or >=X.X.X)
_UNPINNED_DEP_RE = re.compile(r'^([a-zA-Z0-9_-]+)\s*$|^([a-zA-Z0-9_-]+)\s*>=', re.MULTILINE)
_PINNED_DEP_RE = re.compile(r'^[a-zA-Z0-9_-]+\s*==\s*[\d.]+', re.MULTILINE)

# AI-specific packages that commonly appear unpinned
_AI_PACKAGES = {
    'langchain', 'langchain-core', 'langchain-community', 'langchain-openai',
    'openai', 'anthropic', 'transformers', 'torch', 'tensorflow', 'huggingface-hub',
    'llama-index', 'llama_index', 'llamaindex', 'autogen', 'crewai',
    'chromadb', 'pinecone', 'weaviate', 'qdrant-client', 'faiss-cpu',
    'vllm', 'ollama', 'litellm', 'guidance', 'instructor', 'dspy-ai',
}

# Shadow AI indicators
_SHADOW_AI_ENV_RE = re.compile(
    r'(?i)(?:OPENAI|ANTHROPIC|GROQ|COHERE|MISTRAL|TOGETHER|REPLICATE|HUGGINGFACE)[_-]?API[_-]?KEY\s*=\s*[^\s$]{10,}'
)
_SHADOW_AI_PACKAGE_RE = re.compile(
    r'(?i)^(?:openai|anthropic|langchain|ollama|transformers|litellm)\b',
    re.MULTILINE,
)

# Provenance documentation patterns
_PROVENANCE_RE = [
    re.compile(r'(?i)(?:model[_-]?(?:name|id|version|provider)|provider[_-]?name)\s*[=:]'),
    re.compile(r'(?i)"(?:model[_-]?)?(?:name|id|version|provider)"\s*:'),
    re.compile(r'(?i)training[_-]?data[_-]?(?:source|description)'),
    re.compile(r'(?i)model[_-]?card'),
    re.compile(r'(?i)base[_-]?model\s*[=:]'),
]

_AIBOM_RE = re.compile(
    r'(?i)(?:aibom|ai[_-]?(?:bill[_-]?of[_-]?materials?|bom)|'
    r'model[_-]?inventory|ai[_-]?asset[_-]?register)'
)


def check_supply_001(ctx: ScanContext) -> CheckResult:
    """AI-SUPPLY-001: Model Provenance Known and Documented"""
    # Check model_config for provenance info
    has_model_config = bool(ctx.model_config or ctx.model_config_raw)
    has_provenance = False
    ev = []

    if has_model_config:
        text = ctx.model_config_raw
        matches = [r for r in _PROVENANCE_RE if r.search(text)]
        if matches:
            has_provenance = True
            ev.append(f"model_config.json has provenance fields ({len(matches)} patterns matched)")

    # Check for AIBOM or inventory files
    for path in ctx.inventory_files:
        content = ctx.files.get(path, '')
        if _AIBOM_RE.search(content) or len(content) > 100:
            has_provenance = True
            ev.append(f"AI inventory found: {path}")

    # Check config.json for model info
    if ctx.config_json:
        text = ctx.config_json_raw
        if any(r.search(text) for r in _PROVENANCE_RE):
            has_provenance = True
            ev.append("config.json has model provenance fields")

    if not has_provenance and not ctx.inventory_files:
        return CheckResult(
            check_id="AI-SUPPLY-001",
            title="Model Provenance Known and Documented",
            status=FAIL,
            severity="HIGH",
            category=CATEGORY,
            details=(
                "No model provenance documentation found. "
                "You need a record of: which model, which version, who made it, and what it was trained on."
            ),
            evidence=[
                "No model_config.json or AI inventory file found",
                "No provenance fields (model_id, provider, base_model) detected in config files",
            ],
            remediation=(
                "1. Create an AI asset inventory (see AI-GOV-005) for every model in use.\n"
                "2. For each model, record: provider, model ID, version, training data summary, limitations.\n"
                "3. For fine-tuned models: document the base model, fine-tuning dataset, and training date.\n"
                "4. Subscribe to provider security advisories for models in use."
            ),
            frameworks={"OWASP LLM": "LLM03", "FedRAMP": "SA-12, CM-8", "NIST AI RMF": "GOVERN 2.2"},
        )
    elif has_provenance:
        return CheckResult(
            check_id="AI-SUPPLY-001",
            title="Model Provenance Known and Documented",
            status=PASS,
            severity="HIGH",
            category=CATEGORY,
            details="Model provenance documentation found.",
            evidence=ev,
            frameworks={"OWASP LLM": "LLM03", "FedRAMP": "SA-12", "NIST AI RMF": "GOVERN 2.2"},
        )
    else:
        return CheckResult(
            check_id="AI-SUPPLY-001",
            title="Model Provenance Known and Documented",
            status=WARN,
            severity="HIGH",
            category=CATEGORY,
            details="Partial provenance information found but no comprehensive AI asset inventory.",
            evidence=ev + ["Consider creating a dedicated AI inventory file (AI_Asset_Inventory.md)"],
            remediation="Create a dedicated AI asset inventory documenting all models in use.",
            frameworks={"OWASP LLM": "LLM03", "FedRAMP": "SA-12", "NIST AI RMF": "GOVERN 2.2"},
        )


def check_supply_002(ctx: ScanContext) -> CheckResult:
    """AI-SUPPLY-002: Model Source Verified (Not Tampered or Poisoned)"""
    # Check for checksum files
    has_checksums = bool(ctx.checksum_files)
    ev = []

    if has_checksums:
        ev.extend([f"Checksum file found: {f}" for f in ctx.checksum_files])

    # Check model_config for hash verification settings
    all_text = '\n'.join(ctx.files.values())
    has_hash_verify = bool(re.search(
        r'(?i)(?:sha256|md5|checksum|hash|verify[_-]?model|model[_-]?hash)',
        all_text,
    ))

    if has_hash_verify or has_checksums:
        if has_checksums:
            ev.append("Model checksum verification files present")
        if has_hash_verify:
            ev.append("Hash verification configuration detected")
        return CheckResult(
            check_id="AI-SUPPLY-002",
            title="Model Source Verified (Not Tampered or Poisoned)",
            status=PASS,
            severity="CRITICAL",
            category=CATEGORY,
            details="Model integrity verification (checksum/hash) found.",
            evidence=ev,
            frameworks={"OWASP LLM": "LLM03, LLM04", "FedRAMP": "SA-12, SI-7", "NIST AI RMF": "MAP 1.5"},
        )

    # Check if local model files exist (only then is verification truly needed)
    has_local_model = bool(re.search(
        r'(?i)(?:local[_-]?model|model[_-]?path|gguf|safetensors|\.bin|ollama)',
        all_text,
    ))

    if has_local_model:
        return CheckResult(
            check_id="AI-SUPPLY-002",
            title="Model Source Verified (Not Tampered or Poisoned)",
            status=FAIL,
            severity="CRITICAL",
            category=CATEGORY,
            details=(
                "Local model files referenced but no checksum verification found. "
                "Downloaded model weights can be tampered with — verification is essential."
            ),
            evidence=[
                "Local model file references found (gguf/safetensors/.bin/ollama)",
                "No checksum files (.sha256, checksums.txt) found",
                "No hash verification configuration detected",
            ],
            remediation=(
                "1. Download models only from official sources (HuggingFace official org, provider website).\n"
                "2. Verify SHA256 after download: sha256sum model.bin — compare to official checksum.\n"
                "3. Use safetensors format when available — it cannot execute code on load unlike .bin (pickle).\n"
                "4. Create a model_checksums.sha256 file and verify at deployment time."
            ),
            frameworks={"OWASP LLM": "LLM03, LLM04", "FedRAMP": "SA-12, SI-7", "NIST AI RMF": "MAP 1.5"},
        )
    else:
        return CheckResult(
            check_id="AI-SUPPLY-002",
            title="Model Source Verified (Not Tampered or Poisoned)",
            status=WARN,
            severity="CRITICAL",
            category=CATEGORY,
            details=(
                "No local model files or checksum verification detected. "
                "If using API-hosted models only, tampering verification is the provider's responsibility — document this."
            ),
            evidence=["No local model files detected", "No checksum verification found"],
            remediation=(
                "For API-hosted models (OpenAI, Anthropic): document that tampering verification is provider-managed.\n"
                "For local models: implement SHA256 verification of all model weight files."
            ),
            frameworks={"OWASP LLM": "LLM03, LLM04", "FedRAMP": "SA-12", "NIST AI RMF": "MAP 1.5"},
        )


def check_supply_003(ctx: ScanContext) -> CheckResult:
    """AI-SUPPLY-003: Dependencies and Plugins from Approved Sources Only"""
    if not ctx.requirements_txt:
        return CheckResult(
            check_id="AI-SUPPLY-003",
            title="Dependencies from Approved Sources Only",
            status=WARN,
            severity="HIGH",
            category=CATEGORY,
            details="No requirements.txt found. Cannot audit Python dependencies.",
            evidence=["No requirements.txt or requirements*.txt found in target directory"],
            remediation=(
                "Create a requirements.txt with pinned versions for all dependencies.\n"
                "For Node.js: ensure package-lock.json is committed.\n"
                "Run 'pip audit' or 'npm audit' to check for known vulnerabilities."
            ),
            frameworks={"OWASP LLM": "LLM03", "FedRAMP": "SA-12, CM-7", "NIST AI RMF": "GOVERN 2.2"},
        )

    lines = [l.strip() for l in ctx.requirements_txt.splitlines()
             if l.strip() and not l.strip().startswith('#')]

    pinned = []
    unpinned = []
    unpinned_ai = []

    for line in lines:
        pkg_name = re.split(r'[=<>!; \[\]]', line)[0].strip().lower()
        if not pkg_name:
            continue
        is_pinned = bool(re.match(r'^[a-zA-Z0-9_-]+==[0-9]', line))
        if is_pinned:
            pinned.append(pkg_name)
        else:
            unpinned.append(pkg_name)
            if pkg_name in _AI_PACKAGES:
                unpinned_ai.append(pkg_name)

    total = len(pinned) + len(unpinned)
    if total == 0:
        return CheckResult(
            check_id="AI-SUPPLY-003",
            title="Dependencies from Approved Sources Only",
            status=WARN,
            severity="HIGH",
            category=CATEGORY,
            details="requirements.txt found but appears empty or has no parseable packages.",
            frameworks={"OWASP LLM": "LLM03", "FedRAMP": "SA-12", "NIST AI RMF": "GOVERN 2.2"},
        )

    if unpinned_ai:
        return CheckResult(
            check_id="AI-SUPPLY-003",
            title="Dependencies from Approved Sources Only",
            status=FAIL,
            severity="HIGH",
            category=CATEGORY,
            details=(
                f"{len(unpinned_ai)} AI-specific package(s) are not version-pinned. "
                "Unpinned AI framework installs can silently pull in versions with known CVEs or breaking behavior changes."
            ),
            evidence=[f"Unpinned AI packages: {', '.join(unpinned_ai[:10])}",
                      f"Total unpinned packages: {len(unpinned)} of {total}"],
            remediation=(
                "1. Pin all AI packages: langchain==0.3.0, openai==1.50.0, etc.\n"
                "2. Run 'pip audit' to check for known CVEs in installed versions.\n"
                "3. Use 'pip freeze > requirements.txt' to capture current pinned state.\n"
                "4. Set up Dependabot or Snyk to monitor for new CVEs in pinned versions."
            ),
            frameworks={"OWASP LLM": "LLM03", "FedRAMP": "SA-12, CM-7", "NIST AI RMF": "GOVERN 2.2"},
        )
    elif unpinned:
        return CheckResult(
            check_id="AI-SUPPLY-003",
            title="Dependencies from Approved Sources Only",
            status=WARN,
            severity="HIGH",
            category=CATEGORY,
            details=f"{len(unpinned)} of {total} packages are unpinned (none are AI-specific).",
            evidence=[f"Unpinned packages: {', '.join(unpinned[:8])}",
                      f"{len(pinned)} pinned packages detected"],
            remediation="Pin all dependencies with exact versions (==) to ensure reproducible and auditable deployments.",
            frameworks={"OWASP LLM": "LLM03", "FedRAMP": "SA-12", "NIST AI RMF": "GOVERN 2.2"},
        )
    else:
        return CheckResult(
            check_id="AI-SUPPLY-003",
            title="Dependencies from Approved Sources Only",
            status=PASS,
            severity="HIGH",
            category=CATEGORY,
            details=f"All {total} packages in requirements.txt are version-pinned.",
            evidence=[f"{total} pinned packages found",
                      f"AI packages detected: {', '.join(p for p in pinned if p in _AI_PACKAGES)[:5] or 'none'}"],
            frameworks={"OWASP LLM": "LLM03", "FedRAMP": "SA-12", "NIST AI RMF": "GOVERN 2.2"},
        )


def check_supply_004(ctx: ScanContext) -> CheckResult:
    """AI-SUPPLY-004: No Shadow AI / Unsanctioned Model in Use"""
    shadow_indicators = []

    # Look for multiple/unexpected API keys (env files may have keys for unapproved providers)
    all_env_text = '\n'.join(ctx.files.get(p, '') for p in ctx.env_files)
    providers_found = set(re.findall(
        r'(?i)^(?:export\s+)?([A-Z]+)_API_KEY\s*=',
        all_env_text,
        re.MULTILINE,
    ))

    # Check requirements.txt for unexpected AI packages
    unexpected_ai = set()
    if ctx.requirements_txt:
        lines = ctx.requirements_txt.splitlines()
        for line in lines:
            pkg = re.split(r'[=<>!; \[\]]', line.strip())[0].strip().lower()
            if pkg in _AI_PACKAGES:
                unexpected_ai.add(pkg)

    # Check for personal/test API keys (keys in .env files that shouldn't be there)
    # This is best-effort: flag if many AI providers appear
    known_providers = {'OPENAI', 'ANTHROPIC', 'GROQ', 'COHERE', 'MISTRAL', 'TOGETHER',
                       'REPLICATE', 'HUGGINGFACE', 'GEMINI', 'GOOGLE', 'AZURE_OPENAI'}
    found_providers = providers_found & known_providers
    extra_providers = found_providers - {'OPENAI', 'ANTHROPIC'}  # flag non-primary providers

    if extra_providers:
        shadow_indicators.append(
            f"Multiple AI provider keys found: {', '.join(sorted(found_providers))} — verify all are approved"
        )

    # No shadow AI indicators — this check is hard to evaluate from config alone
    if shadow_indicators:
        return CheckResult(
            check_id="AI-SUPPLY-004",
            title="No Shadow AI / Unsanctioned Model in Use",
            status=WARN,
            severity="HIGH",
            category=CATEGORY,
            details=(
                "Multiple AI provider API keys detected. "
                "Verify that all providers are approved and inventoried — shadow AI often appears as unexpected API keys."
            ),
            evidence=shadow_indicators,
            remediation=(
                "1. Establish an approved AI provider list and communicate it to all staff.\n"
                "2. Query network logs for outbound connections to AI API endpoints — compare against approved list.\n"
                "3. Review AI features in approved software (Copilot, Gemini for Workspace) — they may be processing work data.\n"
                "4. Create an easy, approved AI request path to reduce pressure for shadow AI."
            ),
            frameworks={"OWASP LLM": "LLM03", "FedRAMP": "CM-7, CM-8", "NIST AI RMF": "GOVERN 2.2"},
        )
    else:
        return CheckResult(
            check_id="AI-SUPPLY-004",
            title="No Shadow AI / Unsanctioned Model in Use",
            status=WARN,
            severity="HIGH",
            category=CATEGORY,
            details=(
                "Cannot fully evaluate shadow AI from static config. "
                "This check requires network monitoring and employee surveys to fully assess."
            ),
            evidence=[
                "No obvious unsanctioned AI indicators in config files",
                f"AI packages in requirements.txt: {', '.join(sorted(unexpected_ai)) or 'none detected'}",
                "Shadow AI discovery requires network log analysis (DNS queries to AI API endpoints)",
            ],
            remediation=(
                "Run a shadow AI discovery by querying DNS/network logs for connections to:\n"
                "api.openai.com, api.anthropic.com, generativelanguage.googleapis.com, api.cohere.com\n"
                "Match against your approved AI service inventory."
            ),
            frameworks={"OWASP LLM": "LLM03", "FedRAMP": "CM-7", "NIST AI RMF": "GOVERN 2.2"},
        )


def check_supply_005(ctx: ScanContext) -> CheckResult:
    """AI-SUPPLY-005: Model Version Pinned (Not Floating Latest)"""
    all_text = '\n'.join(ctx.files.values())
    floating_hits = []
    pinned_hits = []

    # Only check actual config files, not docs or source code
    _config_exts = ('.json', '.yml', '.yaml', '.toml', '.cfg', '.ini', '.env', '.conf')
    for path, content in ctx.files.items():
        if not any(path.endswith(ext) for ext in _config_exts):
            continue
        for m in _FLOATING_MODEL_RE.finditer(content):
            floating_hits.append(f"{path} — {m.group(0).strip()}")
        for m in _PINNED_MODEL_RE.finditer(content):
            pinned_hits.append(f"{path} — {m.group(0).strip()}")

    # Also check for :latest in actual config files
    latest_hits = []
    for path, content in ctx.files.items():
        if not any(path.endswith(ext) for ext in _config_exts):
            continue
        if _LATEST_TAG_RE.search(content):
            latest_hits.append(f"{path} — uses ':latest' tag")

    if floating_hits or latest_hits:
        return CheckResult(
            check_id="AI-SUPPLY-005",
            title="Model Version Pinned (Not Floating Latest)",
            status=FAIL,
            severity="MEDIUM",
            category=CATEGORY,
            details=(
                f"{len(floating_hits + latest_hits)} floating model version reference(s) detected. "
                "Model providers silently update models — floating versions can change behavior without warning."
            ),
            evidence=(floating_hits + latest_hits)[:5],
            remediation=(
                "1. Pin to a specific version: 'gpt-4o-2024-11-20' not 'gpt-4o'.\n"
                "2. For Ollama: use a specific digest: 'ollama pull llama3.1:8b-instruct-q4_K_M'.\n"
                "3. Provider docs list all available pinned version identifiers.\n"
                "4. Create a quarterly review process to evaluate new model versions before upgrading."
            ),
            frameworks={"OWASP LLM": "LLM03", "FedRAMP": "CM-6, CM-3", "NIST AI RMF": "GOVERN 2.2"},
        )
    elif pinned_hits:
        return CheckResult(
            check_id="AI-SUPPLY-005",
            title="Model Version Pinned (Not Floating Latest)",
            status=PASS,
            severity="MEDIUM",
            category=CATEGORY,
            details="Model versions appear to be pinned to specific version identifiers.",
            evidence=pinned_hits[:3],
            frameworks={"OWASP LLM": "LLM03", "FedRAMP": "CM-6", "NIST AI RMF": "GOVERN 2.2"},
        )
    else:
        return CheckResult(
            check_id="AI-SUPPLY-005",
            title="Model Version Pinned (Not Floating Latest)",
            status=WARN,
            severity="MEDIUM",
            category=CATEGORY,
            details="No model version configuration found in scanned files. Cannot verify version pinning.",
            evidence=["No model version specification found in config files"],
            remediation="Add model version configuration to your deployment config and pin to a specific date-versioned identifier.",
            frameworks={"OWASP LLM": "LLM03", "FedRAMP": "CM-6", "NIST AI RMF": "GOVERN 2.2"},
        )


def run_all(ctx: ScanContext) -> list:
    return [
        check_supply_001(ctx),
        check_supply_002(ctx),
        check_supply_003(ctx),
        check_supply_004(ctx),
        check_supply_005(ctx),
    ]
