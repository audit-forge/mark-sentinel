"""
AI-RUNTIME checks — Runtime Behavioral Monitoring
Checks: AI-RUNTIME-001 through AI-RUNTIME-005

Platform-agnostic: detects monitoring signals across LangSmith, OpenTelemetry,
Datadog, Helicone, Langfuse, Sentry, Arize, MLflow, W&B, Hash, and generic
config/env patterns. Checks 003-005 also work across platforms.

When no AI/LLM provider, SDK, or configuration is detected anywhere in the
scan target, all checks return N/A — runtime monitoring requirements do not
apply to systems that do not use AI.
"""
import re
from . import CheckResult, PASS, FAIL, WARN, SKIP, NA
from connectors.config_connector import ScanContext

CATEGORY = "AI-RUNTIME"

# ── Shared patterns (used by multiple checks) ────────────────────────────────
_MON_ENABLED_RE = re.compile(r'(?i)"monitoring"\s*:\s*\{[^}]*"enabled"\s*:\s*true')
_RETENTION_RE   = re.compile(r'(?i)"retention[_-]?days"\s*:\s*([0-9]+)')
_BUDGET_RE    = re.compile(r'(?i)"(?:max[_-]?tokens?|token[_-]?budget|token[_-]?limit)"\s*:\s*[0-9]')
_HUMAN_LOOP_RE = re.compile(
    r'(?i)"(?:human[_-]?(?:in[_-]?(?:the[_-]?)?loop|oversight|review|approval)|'
    r'require[_-]?confirm(?:ation)?|hitl|approval[_-]?required)"\s*:\s*true'
)
_AUDIT_TRAIL_RE = re.compile(
    r'(?i)"(?:prompt[_-]?(?:audit|log|trail|hash)|audit[_-]?trail|log[_-]?prompts?'
    r'|prompt[_-]?logging)"\s*:\s*true'
)

# ── 001: Inference activity logging signals ───────────────────────────────────
# (pattern, label, is_strong)
# strong = definitively proves logging is active
# weak   = suggests it may be configured but not confirmed on
_001_SIGNALS: list[tuple[str, str, bool]] = [
    # LangSmith
    (r'LANGCHAIN_TRACING(?:_V2)?\s*[=:]\s*["\']?true', "LangSmith tracing enabled", True),
    (r'LANGCHAIN_API_KEY\s*[=:]\s*\S', "LangSmith API key present", False),
    # OpenTelemetry
    (r'OTEL_EXPORTER_[A-Z_]+_ENDPOINT\s*[=:]', "OpenTelemetry exporter endpoint configured", True),
    (r'OTEL_SERVICE_NAME\s*[=:]', "OpenTelemetry service name set", False),
    # Datadog APM
    (r'DD_TRACE_ENABLED\s*[=:]\s*["\']?true', "Datadog tracing enabled", True),
    (r'DD_APM_ENABLED\s*[=:]\s*["\']?true', "Datadog APM enabled", True),
    # Helicone — all traffic proxied, logging on by default when key present
    (r'HELICONE_API_KEY\s*[=:]', "Helicone AI logging proxy configured", True),
    (r'oai\.hconeai\.com|helicone\.ai', "Helicone proxy URL in config", True),
    # Langfuse
    (r'LANGFUSE_(?:PUBLIC|SECRET)_KEY\s*[=:]', "Langfuse tracing configured", True),
    # Braintrust
    (r'BRAINTRUST_API_KEY\s*[=:]', "Braintrust AI logging configured", True),
    # Arize / Phoenix
    (r'ARIZE_API_KEY\s*[=:]', "Arize AI observability configured", True),
    (r'PHOENIX_COLLECTOR_ENDPOINT\s*[=:]', "Arize Phoenix collector configured", True),
    # MLflow
    (r'MLFLOW_TRACKING_URI\s*[=:]', "MLflow tracking URI configured", False),
    # Weights & Biases
    (r'WANDB_(?:API_KEY|PROJECT)\s*[=:]', "Weights & Biases tracking configured", False),
    # New Relic
    (r'NEW_RELIC_LICENSE_KEY\s*[=:]', "New Relic APM configured", True),
    # Generic explicit inference-logging flags
    (r'"(?:log_requests|log_inference|capture_requests|request_logging)"\s*:\s*true',
     "Explicit inference logging flag set", True),
    # Hash native — strong only when paired with db_path (handled below)
    (r'"monitoring"\s*:\s*\{[^}]*"enabled"\s*:\s*true', "Hash monitoring enabled", False),
    (r'"(?:db_path|log_path|activity[_-]?db)"\s*:\s*"[^"]+\.db"', "Activity log DB path configured", False),
]

_001_IMPORTS: list[tuple[str, str]] = [
    (r'(?m)^(?:from|import)\s+langsmith\b', "langsmith"),
    (r'(?m)^(?:from|import)\s+opentelemetry\b', "opentelemetry"),
    (r'(?m)^(?:from|import)\s+ddtrace\b', "ddtrace"),
    (r'(?m)^(?:from|import)\s+langfuse\b', "langfuse"),
    (r'(?m)^(?:from|import)\s+arize\b', "arize"),
    (r'(?m)^(?:from|import)\s+phoenix\b', "arize-phoenix"),
    (r'(?m)^(?:from|import)\s+mlflow\b', "mlflow"),
    (r'(?m)^(?:from|import)\s+wandb\b', "wandb"),
    (r'(?m)^(?:from|import)\s+newrelic\b', "newrelic"),
]

# ── 002: Anomaly detection / alerting signals ─────────────────────────────────
_002_SIGNALS: list[tuple[str, str, bool]] = [
    # Hash native
    (r'"anomaly[_-]?detection"\s*:\s*\{[^}]*"enabled"\s*:\s*true', "Hash anomaly detection enabled", True),
    # Error monitoring (catches error-type anomalies)
    (r'SENTRY_DSN\s*[=:]', "Sentry error monitoring configured", True),
    (r'sentry_sdk\.init\s*\(', "Sentry SDK initialized", True),
    # Rate limiting (catches request-volume anomalies)
    (r'"rate_limit(?:ing)?"\s*:\s*(?:true|\{[^}]*"enabled"\s*:\s*true)', "Rate limiting configured", True),
    (r'MAX_REQUESTS_PER_(?:MINUTE|HOUR|DAY)\s*[=:]\s*[0-9]', "Request rate cap configured", True),
    (r'RATE_LIMIT(?:_REQUESTS)?\s*[=:]\s*[0-9]', "Rate limit env var set", True),
    # Circuit breakers
    (r'"circuit[_-]?breaker"\s*:\s*(?:true|\{)', "Circuit breaker configured", True),
    # Explicit alerting config
    (r'"alert(?:ing)?"\s*:\s*(?:true|\{[^}]*"enabled"\s*:\s*true)', "Explicit alerting configured", True),
    (r'"alerts"\s*:\s*\[', "Alert rules defined", True),
    # Datadog monitors
    (r'DD_MONITOR|datadog[._-](?:monitor|anomaly|alert)', "Datadog monitoring configured", True),
    # AWS CloudWatch
    (r'CLOUDWATCH_(?:NAMESPACE|ALARM_NAME)\s*[=:]', "CloudWatch monitoring configured", True),
    # API gateway spike protection
    (r'"spike[_-]?protection"\s*:\s*true', "Spike protection enabled", True),
    # Daily token budget (proactive anomaly cap)
    (r'"token[_-]?budget[_-]?daily"\s*:\s*[0-9]', "Daily token budget cap configured", True),
    # Prometheus — metrics present but alerting rules not guaranteed (weak)
    (r'PROMETHEUS_(?:HOST|URL|PORT)\s*[=:]', "Prometheus metrics endpoint configured", False),
    (r'"prometheus"\s*:\s*\{[^}]*"enabled"\s*:\s*true', "Prometheus exporter enabled", False),
]

_002_IMPORTS: list[tuple[str, str]] = [
    (r'(?m)^(?:from|import)\s+sentry_sdk\b', "sentry_sdk"),
    (r'(?m)^(?:from|import)\s+datadog\b', "datadog"),
    (r'(?m)^(?:from|import)\s+prometheus_client\b', "prometheus_client"),
]


# ── Helpers ──────────────────────────────────────────────────────────────────

def _all_text(ctx: ScanContext) -> str:
    return "\n".join(ctx.files.values())


# Patterns that indicate the scan target actually uses AI/LLM services.
# If none of these match, the runtime monitoring checks are not applicable —
# a system with no AI calls has nothing to log, budget, or audit.
# These patterns are intentionally specific to avoid false positives from
# system packages (botocore AWS SDK definitions, Google Ops Agent, etc.).

# AI package names as bare requirements (e.g. "openai==1.0", "langchain>=0.3").
_AI_PACKAGE_RE = re.compile(
    r'(?im)^\s*(?:openai|anthropic|langchain|langsmith|llama[-_]?index|litellm|'
    r'vertexai|google[-_]generativeai|haystack|autogen|crewai|dspy|'
    r'semantic[-_]?kernel|guidance|instructor|marvin|chatacter|transformers|'
    r'torch|tensorflow|huggingface[-_]hub|chromadb|pinecone|weaviate|'
    r'qdrant[-_]?client|faiss[-_]cpu|vllm|ollama|deepseek|zhipuai|moonshotai|'
    r'dashscope)\b'
)
_AI_PROVIDER_RE = re.compile(
    r'(?i)('
    # Provider SDK imports (anchored to line start for code files)
    r'^(?:from|import)\s+(?:openai|anthropic|langchain|langsmith|llama_index|'
    r'litellm|vertexai|google\.generativeai|haystack|autogen|crewai|'
    r'dspy|semantic_kernel|guidance|instructor|marvin|chatacter)\b'
    # Provider API key env vars (require _API_KEY or _TOKEN suffix — bare
    # service names like "bedrock" or "vertex" match AWS SDK schema files)
    r'|OPENAI_API_KEY|ANTHROPIC_API_KEY|GEMINI_API_KEY|GOOGLE_API_KEY'
    r'|COHERE_API_KEY|MISTRAL_API_KEY|GROQ_API_KEY|TOGETHER_API_KEY'
    r'|HF_TOKEN|HUGGINGFACE_TOKEN'
    # Provider API endpoints (specific hostnames, not bare service names)
    r'|api\.openai\.com|api\.anthropic\.com|generativelanguage\.googleapis\.com'
    r'|api\.cohere\.com|api\.mistral\.ai|api\.groq\.com|api\.together\.xyz'
    r'|api-inference\.huggingface\.co'
    # AI model references in config context (require "model": "gpt-..." pattern)
    r'|"model"\s*:\s*"(?:gpt|claude|gemini|llama|mistral|command|phi|mixtral)'
    # AI framework tracing/observability env vars (specific prefixes only)
    r'|LANGCHAIN_TRACING|LANGFUSE_PUBLIC_KEY|LANGFUSE_SECRET_KEY|HELICONE_API_KEY'
    r')',
    re.MULTILINE
)

# Config files that, if present, explicitly declare AI usage status.
# Only ai_inference_enabled=true counts as "AI in use" — a file that says
# false is an explicit declaration that AI is NOT in use, and the runtime
# checks should be N/A.
_AI_CONFIG_FILES = (
    'ai_runtime_config.json',
    'ai_config.json',
    'llm_config.json',
)

# System package directories to exclude from AI detection — installed packages
# (botocore, AWS SDKs, Google Ops Agent) contain service schemas and example
# JSON that reference AI services but are not actual AI usage declarations.
_SYSTEM_PATH_PREFIXES = (
    'usr/lib/', 'usr/share/', 'usr/local/lib/', 'usr/local/share/',
    'lib/python', 'site-packages/', 'dist-packages/', 'node_modules/',
    'Library/Python/', '.cache/pip/', '/opt/homebrew/',
    'google-cloud-ops-agent', 'opt/google',
)


def _ai_in_use(ctx: ScanContext) -> bool:
    """Return True if any AI/LLM provider, SDK, or config is detected.

    Tolerates test contexts that only expose a subset of ScanContext attributes.
    """
    files = getattr(ctx, 'files', {})
    if not files:
        # If we have no file content at all, fall back to AI-specific signals
        # that may be present directly on the context (e.g. requirements_txt).
        all_text = ""
        for attr in ('requirements_txt', 'docker_compose_raw'):
            val = getattr(ctx, attr, None)
            if val:
                all_text += "\n" + val
        if all_text and (_AI_PROVIDER_RE.search(all_text) or _AI_PACKAGE_RE.search(all_text)):
            return True
        return False
    # An ai_runtime_config.json with ai_inference_enabled=true counts as
    # explicit declaration that AI is in use. Explicit false means NOT in use.
    for rel_path in files:
        basename = rel_path.rsplit('/', 1)[-1].rsplit('\\', 1)[-1]
        if basename in _AI_CONFIG_FILES:
            content = ctx.files[rel_path]
            if re.search(r'"ai_inference_enabled"\s*:\s*true', content, re.IGNORECASE):
                return True
            if re.search(r'"ai_inference_enabled"\s*:\s*false', content, re.IGNORECASE):
                # Explicit declaration that AI is NOT in use — don't let
                # other system-file false positives override this.
                return False
    # Scan non-system files for AI provider references and AI package names.
    for rel_path, content in files.items():
        if any(p in rel_path for p in _SYSTEM_PATH_PREFIXES):
            continue
        if _AI_PROVIDER_RE.search(content) or _AI_PACKAGE_RE.search(content):
            return True
    return False


def _na(check_id: str, title: str, severity: str) -> CheckResult:
    """Return N/A for a runtime check when no AI is in use."""
    return CheckResult(
        check_id=check_id,
        title=title,
        status=NA,
        severity=severity,
        category=CATEGORY,
        details=(
            "No AI/LLM provider, SDK, or configuration detected in the scan "
            "target. Runtime monitoring checks are not applicable when the "
            "system does not make AI inference calls."
        ),
        remediation=(
            "If AI/LLM services are introduced, add the relevant provider "
            "config or SDK and re-run the scan — these checks will then "
            "evaluate the runtime monitoring posture."
        ),
    )


def _detect(
    all_text: str,
    signals: list[tuple[str, str, bool]],
    imports: list[tuple[str, str]] | None = None,
) -> tuple[list[str], list[str]]:
    """
    Scan all_text against signal definitions.
    Returns (strong_matches, weak_matches) as label lists.
    Import hits are always added as weak signals.
    """
    strong: list[str] = []
    weak: list[str]   = []
    for pattern, label, is_strong in signals:
        if re.search(pattern, all_text, re.IGNORECASE):
            (strong if is_strong else weak).append(label)
    for pattern, label in (imports or []):
        if re.search(pattern, all_text):
            weak.append(f"{label} imported")
    return strong, weak


# ── Check 001 ────────────────────────────────────────────────────────────────

def check_runtime_001(ctx: ScanContext) -> CheckResult:
    """AI-RUNTIME-001 — Inference activity logging enabled."""
    if not _ai_in_use(ctx):
        return _na("AI-RUNTIME-001", "Inference logging — no AI in use", "CRITICAL")
    all_text = _all_text(ctx)
    strong, weak = _detect(all_text, _001_SIGNALS, _001_IMPORTS)

    # Hash-specific promotion: monitoring.enabled + db_path together = strong
    hash_mon  = any("Hash monitoring" in s for s in weak)
    hash_db   = any("Activity log DB" in s for s in weak)
    if hash_mon and hash_db:
        strong.append("Hash monitoring enabled with persistent DB")
        weak = [s for s in weak if "Hash monitoring" not in s and "Activity log DB" not in s]

    # Also check for activity DB files on disk
    for rel_path in ctx.files:
        if ".activity.db" in rel_path or "activity_log.db" in rel_path:
            strong.append(f"Activity log DB file present ({rel_path})")
            break

    if strong:
        return CheckResult(
            check_id="AI-RUNTIME-001",
            title="Inference activity logging enabled",
            status=PASS,
            severity="CRITICAL",
            category=CATEGORY,
            details=f"Logging signals found: {', '.join(strong)}.",
            remediation="",
            evidence=strong + weak,
        )

    if weak:
        return CheckResult(
            check_id="AI-RUNTIME-001",
            title="Inference activity logging may be partially configured",
            status=WARN,
            severity="MEDIUM",
            category=CATEGORY,
            details=(
                f"Weak logging signals found ({', '.join(weak)}) but no definitive "
                "evidence that inference calls are being recorded. Confirm the "
                "observability tool is actually enabled and receiving data."
            ),
            remediation=(
                "Enable inference logging using one of:\n"
                "  • LangSmith: set LANGCHAIN_TRACING_V2=true + LANGCHAIN_API_KEY\n"
                "  • Helicone: set HELICONE_API_KEY and route via oai.hconeai.com\n"
                "  • OpenTelemetry: set OTEL_EXPORTER_OTLP_ENDPOINT\n"
                "  • Datadog: set DD_TRACE_ENABLED=true + DD_APM_ENABLED=true\n"
                "  • Langfuse: set LANGFUSE_PUBLIC_KEY + LANGFUSE_SECRET_KEY\n"
                '  • Hash: "monitoring": {"enabled": true, "db_path": "...activity.db"}'
            ),
            evidence=weak,
        )

    return CheckResult(
        check_id="AI-RUNTIME-001",
        title="No inference activity logging detected",
        status=FAIL,
        severity="CRITICAL",
        category=CATEGORY,
        details=(
            "No inference logging, tracing, or observability tool detected. "
            "Every AI call is untracked — no forensics, no usage visibility, "
            "no audit trail."
        ),
        remediation=(
            "Enable inference logging using one of:\n"
            "  • LangSmith: set LANGCHAIN_TRACING_V2=true + LANGCHAIN_API_KEY\n"
            "  • Helicone: route OpenAI calls via oai.hconeai.com with HELICONE_API_KEY\n"
            "  • OpenTelemetry: set OTEL_EXPORTER_OTLP_ENDPOINT + OTEL_SERVICE_NAME\n"
            "  • Datadog APM: set DD_TRACE_ENABLED=true + DD_APM_ENABLED=true\n"
            "  • Langfuse: set LANGFUSE_PUBLIC_KEY + LANGFUSE_SECRET_KEY\n"
            "  • Arize: set ARIZE_API_KEY or PHOENIX_COLLECTOR_ENDPOINT\n"
            '  • Hash: "monitoring": {"enabled": true, "db_path": "...activity.db", "retention_days": 30}\n'
            "Record the control in `compliance/ai_runtime_config.json` (template: "
            "`compliance_starter_kit/ai_runtime_config.json`) in the directory Arckon scans — but only enable a "
            "flag for a control you genuinely operate. Never declare a control you do not actually have."
        ),
        evidence=[],
    )


# ── Check 002 ────────────────────────────────────────────────────────────────

def check_runtime_002(ctx: ScanContext) -> CheckResult:
    """AI-RUNTIME-002 — Anomaly detection or alerting configured."""
    if not _ai_in_use(ctx):
        return _na("AI-RUNTIME-002", "Anomaly detection — no AI in use", "HIGH")
    all_text = _all_text(ctx)
    strong_002, weak_002 = _detect(all_text, _002_SIGNALS, _002_IMPORTS)

    # Determine whether any logging exists (from 001 perspective) for WARN context
    strong_001, weak_001 = _detect(all_text, _001_SIGNALS, _001_IMPORTS)
    has_any_logging = bool(strong_001 or weak_001)

    if strong_002:
        return CheckResult(
            check_id="AI-RUNTIME-002",
            title="Anomaly detection / alerting configured",
            status=PASS,
            severity="HIGH",
            category=CATEGORY,
            details=f"Anomaly/alerting signals found: {', '.join(strong_002)}.",
            remediation="",
            evidence=strong_002 + weak_002,
        )

    if weak_002:
        return CheckResult(
            check_id="AI-RUNTIME-002",
            title="Monitoring infrastructure present but anomaly alerting unconfirmed",
            status=WARN,
            severity="MEDIUM",
            category=CATEGORY,
            details=(
                f"Partial signals ({', '.join(weak_002)}) suggest monitoring is present "
                "but no explicit anomaly detection, rate limiting, or alerting rules were found. "
                "Token spikes and unexpected tool calls may go unnoticed."
            ),
            remediation=(
                "Add anomaly alerting using one of:\n"
                "  • Sentry: set SENTRY_DSN and call sentry_sdk.init()\n"
                "  • Rate limiting: set MAX_REQUESTS_PER_MINUTE or add rate_limiting config\n"
                "  • Datadog: configure DD_MONITOR with anomaly alert\n"
                '  • Hash: "monitoring": {"enabled": true, "anomaly_detection": {"enabled": true}}'
            ),
            evidence=weak_002,
        )

    if has_any_logging:
        return CheckResult(
            check_id="AI-RUNTIME-002",
            title="Activity logging present but no anomaly detection layer",
            status=WARN,
            severity="MEDIUM",
            category=CATEGORY,
            details=(
                "Inference logging appears to be configured (AI-RUNTIME-001) but no "
                "anomaly detection, alerting, or rate limiting layer was found on top of it. "
                "Logs are being collected but nothing is watching for abnormal patterns."
            ),
            remediation=(
                "Add an alerting layer over your existing logging:\n"
                "  • Sentry: add sentry_sdk.init(dsn=SENTRY_DSN) for error-type anomalies\n"
                "  • Rate limiting: enforce MAX_REQUESTS_PER_MINUTE in your API gateway\n"
                "  • LangSmith: configure usage alerts in the LangSmith dashboard\n"
                '  • Hash: add "anomaly_detection": {"enabled": true} under "monitoring"'
            ),
            evidence=[],
        )

    return CheckResult(
        check_id="AI-RUNTIME-002",
        title="No anomaly detection or alerting configured",
        status=FAIL,
        severity="HIGH",
        category=CATEGORY,
        details=(
            "No anomaly detection, rate limiting, circuit breakers, or error monitoring found. "
            "Token spikes, off-hours agentic activity, and unexpected tool calls will go "
            "undetected until damage is done."
        ),
        remediation=(
            "Add anomaly detection using one of:\n"
            "  • Sentry: set SENTRY_DSN — catches error anomalies immediately\n"
            "  • Rate limiting: set MAX_REQUESTS_PER_MINUTE=60 (or appropriate cap)\n"
            "  • Datadog: configure anomaly monitor on token usage metric\n"
            "  • AWS: add CloudWatch alarm on InvocationCount or TokenCount\n"
            '  • Hash: "monitoring": {"enabled": true, "anomaly_detection": {"enabled": true}}\n'
            "  • Generic: add circuit_breaker or spike_protection in your API gateway config\n"
            "Record the control in `compliance/ai_runtime_config.json` (template: "
            "`compliance_starter_kit/ai_runtime_config.json`) in the directory Arckon scans — but only enable a "
            "flag for a control you genuinely operate. Never declare a control you do not actually have."
        ),
        evidence=[],
    )


def check_runtime_003(ctx: ScanContext) -> CheckResult:
    """AI-RUNTIME-003 — Human oversight checkpoint for autonomous agent tasks."""
    if not _ai_in_use(ctx):
        return _na("AI-RUNTIME-003", "Human oversight — no AI in use", "HIGH")
    all_text = _all_text(ctx)

    if _HUMAN_LOOP_RE.search(all_text):
        return CheckResult(
            check_id="AI-RUNTIME-003",
            title="Human oversight / HITL configured for autonomous tasks",
            status=PASS,
            severity="HIGH",
            category=CATEGORY,
            details="Human-in-the-loop or approval requirement found in config.",
            remediation="",
        )

    has_agents = bool(re.search(r'(?i)"agents"\s*:\s*\{', all_text))
    if has_agents:
        return CheckResult(
            check_id="AI-RUNTIME-003",
            title="Autonomous agents configured without human oversight checkpoint",
            status=FAIL,
            severity="HIGH",
            category=CATEGORY,
            details="An agents block is present but no human-in-the-loop or approval "
                   "gate was found. Autonomous tasks can run and act without human review.",
            remediation=(
                'Add to your agent config:\n'
                '  "agents": {\n'
                '    "human_oversight": true,\n'
                '    "require_confirmation": ["deploy", "send_email", "delete_file"]\n'
                '  }\n'
                "Record the control in `compliance/ai_runtime_config.json` (template: "
                "`compliance_starter_kit/ai_runtime_config.json`) in the directory Arckon scans — but only enable a "
                "flag for a control you genuinely operate. Never declare a control you do not actually have."
            ),
            evidence=[],
        )

    return CheckResult(
        check_id="AI-RUNTIME-003",
        title="No human oversight policy found",
        status=WARN,
        severity="MEDIUM",
        category=CATEGORY,
        details="No human-in-the-loop configuration detected. If autonomous agents are "
               "used, add explicit approval gates for high-impact actions.",
        remediation='Add to hash.json:\n  "agents": {"human_oversight": true}',
    )


def check_runtime_004(ctx: ScanContext) -> CheckResult:
    """AI-RUNTIME-004 — Token budget limits enforced."""
    if not _ai_in_use(ctx):
        return _na("AI-RUNTIME-004", "Token budget — no AI in use", "HIGH")
    all_text = _all_text(ctx)

    matches = _BUDGET_RE.findall(all_text)
    if matches:
        return CheckResult(
            check_id="AI-RUNTIME-004",
            title="Token budget limits configured",
            status=PASS,
            severity="HIGH",
            category=CATEGORY,
            details=f"Found {len(matches)} token limit/budget setting(s) in config.",
            remediation="",
        )

    return CheckResult(
        check_id="AI-RUNTIME-004",
        title="No token budget limits configured",
        status=FAIL,
        severity="HIGH",
        category=CATEGORY,
        details="No max_tokens, token_budget, or token_limit found. A runaway loop or "
               "adversarial prompt could exhaust the entire API quota.",
        remediation=(
            'Add token limits per provider/model in config:\n'
            '  "providers": {\n'
            '    "openai": {"max_tokens": 4096},\n'
            '    "anthropic": {"max_tokens": 8192}\n'
            '  }\n'
            'Or set a global budget:\n'
            '  "monitoring": {"token_budget_daily": 500000}\n'
            "Record the control in `compliance/ai_runtime_config.json` (template: "
            "`compliance_starter_kit/ai_runtime_config.json`) in the directory Arckon scans — but only enable a "
            "flag for a control you genuinely operate. Never declare a control you do not actually have."
        ),
        evidence=[],
    )


def check_runtime_005(ctx: ScanContext) -> CheckResult:
    """AI-RUNTIME-005 — Prompt audit trail retained."""
    if not _ai_in_use(ctx):
        return _na("AI-RUNTIME-005", "Prompt audit trail — no AI in use", "HIGH")
    all_text = _all_text(ctx)

    if _AUDIT_TRAIL_RE.search(all_text):
        return CheckResult(
            check_id="AI-RUNTIME-005",
            title="Prompt audit trail configured",
            status=PASS,
            severity="HIGH",
            category=CATEGORY,
            details="Explicit prompt logging or audit trail setting found.",
            remediation="",
        )

    retention_match = _RETENTION_RE.search(all_text)
    if _MON_ENABLED_RE.search(all_text) and retention_match:
        days = int(retention_match.group(1))
        if days >= 7:
            return CheckResult(
                check_id="AI-RUNTIME-005",
                title="Prompt audit trail retained via activity log",
                status=PASS,
                severity="HIGH",
                category=CATEGORY,
                details=f"Activity logging enabled with {days}-day retention stores prompt hashes.",
                remediation="",
            )
        return CheckResult(
            check_id="AI-RUNTIME-005",
            title="Retention period too short for audit trail",
            status=WARN,
            severity="MEDIUM",
            category=CATEGORY,
            details=f"retention_days = {days} is below the recommended 30-day minimum.",
            remediation='Set "retention_days": 30 (or higher) under "monitoring" in config.',
        )

    if _MON_ENABLED_RE.search(all_text):
        return CheckResult(
            check_id="AI-RUNTIME-005",
            title="Activity logging on but no explicit retention policy",
            status=WARN,
            severity="MEDIUM",
            category=CATEGORY,
            details="No retention_days configured — log growth is unbounded and audit "
                   "trail duration is undefined.",
            remediation='Add "retention_days": 30 under "monitoring" in hash.json.',
        )

    return CheckResult(
        check_id="AI-RUNTIME-005",
        title="No prompt audit trail",
        status=FAIL,
        severity="HIGH",
        category=CATEGORY,
        details="No prompt logging, audit trail, or activity retention policy found. "
               "Forensic investigation after a security incident is not possible.",
        remediation=(
            'Enable monitoring with retention in hash.json:\n'
            '  "monitoring": {\n'
            '    "enabled": true,\n'
            '    "retention_days": 30,\n'
            '    "prompt_audit": true\n'
            '  }\n'
            "Record the control in `compliance/ai_runtime_config.json` (template: "
            "`compliance_starter_kit/ai_runtime_config.json`) in the directory Arckon scans — but only enable a "
            "flag for a control you genuinely operate. Never declare a control you do not actually have."
        ),
        evidence=[],
    )


def run_all(ctx: ScanContext) -> list[CheckResult]:
    return [
        check_runtime_001(ctx),
        check_runtime_002(ctx),
        check_runtime_003(ctx),
        check_runtime_004(ctx),
        check_runtime_005(ctx),
    ]
