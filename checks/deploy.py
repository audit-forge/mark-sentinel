"""
AI-DEPLOY checks — Deployment Security
Checks: AI-DEPLOY-001 through AI-DEPLOY-006
"""
import re
from . import CheckResult, PASS, FAIL, WARN, SKIP
from connectors.config_connector import ScanContext

CATEGORY = "AI-DEPLOY"

# API key patterns — only match values that look like real keys (long, opaque)
_API_KEY_RE = [
    (re.compile(r'sk-[a-zA-Z0-9_-]{20,}'), 'OpenAI API key'),
    (re.compile(r'sk-ant-api\d+-[a-zA-Z0-9_-]{20,}'), 'Anthropic API key'),
    (re.compile(r'AIza[a-zA-Z0-9_-]{35}'), 'Google/Gemini API key'),
    (re.compile(r'hf_[a-zA-Z0-9]{30,}'), 'HuggingFace token'),
    (re.compile(r'gsk_[a-zA-Z0-9]{40,}'), 'Groq API key'),
    (re.compile(
        r'(?i)(?:openai|anthropic|groq|cohere|mistral|together)[_-]?api[_-]?key\s*=\s*'
        r'(?!\$\{)(?!\$\()(?!your)(?!replace)(?!example)([a-zA-Z0-9_\-]{20,})'
    ), 'AI provider API key in config'),
]

_PLACEHOLDER_FRAGMENTS = (
    'xxx', '...', 'your-', 'your_', 'replace', 'placeholder', 'example',
    'changeme', 'insert', 'todo', 'sk-test', 'add_your', 'put_your',
    'enter_your', 'sk-xxxx', 'sk-proj-xxxx',
)

_CRED_RE = [
    (re.compile(r'(?im)^(?:export\s+)?(?:DB|DATABASE|MYSQL|POSTGRES|MONGODB)_PASSWORD\s*=\s*(?!\$\{)(?!\$\()(?!\s*$)(.+)$'), 'Database password'),
    (re.compile(r'(?im)^(?:export\s+)?REDIS_PASSWORD\s*=\s*(?!\$)(?!\s*$)(.+)$'), 'Redis password'),
    (re.compile(r'(?i)postgres(?:ql)?://[^:\s]+:([^@\s]{4,})@'), 'PostgreSQL URL with password'),
    (re.compile(r'(?i)mysql://[^:\s]+:([^@\s]{4,})@'), 'MySQL URL with password'),
    (re.compile(r'(?i)mongodb://[^:\s]+:([^@\s]{4,})@'), 'MongoDB URL with password'),
    (re.compile(r'(?i)"password"\s*:\s*"(?!\$\{)([^"$]{4,})"'), 'Password in JSON'),
]

_AUTH_POSITIVE_RE = [
    re.compile(r'(?i)auth(?:entication)?[_-]?(?:required|enabled)\s*[=:]\s*(?:true|yes|1)'),
    re.compile(r'auth_basic\s+'),
    re.compile(r'(?i)"auth(?:entication)?"\s*:\s*(?:true|"\w)'),
    re.compile(r'(?i)"api[_-]?key[_-]?required"\s*:\s*true'),
    re.compile(r'(?i)require[_-]?auth(?:entication)?'),
    re.compile(r'proxy_set_header\s+Authorization'),
    re.compile(r'(?i)"middleware"\s*:\s*\[.*(?:auth|jwt|oauth)'),
    re.compile(r'(?i)oauth2?\s*:\s*\{'),
]

_PORT_EXPOSED_RE = re.compile(r'(?m)^\s*-\s*["\']?(?:0\.0\.0\.0:)?(\d+):(\d+)["\']?')

_TLS_POSITIVE_RE = [
    re.compile(r'ssl_certificate\s+'),
    re.compile(r'listen\s+443\s+ssl'),
    re.compile(r'ssl_protocols\s+'),
    re.compile(r'(?i)tls[_-]?(?:enabled|verify)\s*[=:]\s*(?:true|yes|1)'),
    re.compile(r'(?i)"ssl"\s*:\s*true'),
    re.compile(r'(?i)"https"\s*:\s*true'),
    re.compile(r'(?i)HTTPS\s*=\s*(?:true|1|yes)'),
]

_HTTP_ONLY_RE = [
    re.compile(r'(?i)"(?:base[_-]?url|endpoint|api[_-]?url)"\s*:\s*"http://(?!localhost|127\.)'),
    re.compile(r'(?i)BASE_URL\s*=\s*http://(?!localhost|127\.)'),
    re.compile(r'(?i)API_ENDPOINT\s*=\s*http://(?!localhost|127\.)'),
]

_RATE_LIMIT_RE = [
    re.compile(r'limit_req(?:_zone)?\s'),
    re.compile(r'(?i)rate[_-]?limit(?:s|ing)?\s*[=:{]'),
    re.compile(r'(?i)"requests[_-]?per[_-]?(?:minute|hour|day|second)"\s*:'),
    re.compile(r'(?i)"max[_-]?requests(?:[_-]?per)?'),
    re.compile(r'(?i)throttl(?:e|ing)'),
    re.compile(r'(?i)RATE_LIMIT\s*='),
    re.compile(r'(?i)token[_-]?bucket'),
]

_LOG_RE = [
    re.compile(r'(?i)"log(?:ging|[_-]?level|[_-]?file|[_-]?path|[_-]?enabled)"\s*[=:{]'),
    re.compile(r'(?i)"logging"\s*:'),
    re.compile(r'access_log\s'),
    re.compile(r'error_log\s'),
    re.compile(r'logging\.basicConfig\s*\('),
    re.compile(r'logging\.getLogger\s*\('),
    re.compile(r'(?i)LOG_LEVEL\s*='),
    re.compile(r'(?i)LOG_FILE\s*='),
    re.compile(r'(?i)structured[_-]?log'),
    re.compile(r'(?i)"audit[_-]?log'),
]

_LOG_RETENTION_RE = re.compile(
    r'(?i)(?:retention|rotate|keep[_-]?days?|max[_-]?(?:age|days?)|log[_-]?(?:rotation|ttl))',
)

_INPUT_LIMIT_RE = [
    re.compile(r'(?i)max[_-]?(?:tokens|input[_-]?length|message[_-]?length|context)\s*[=:{]'),
    re.compile(r'(?i)"max[_-]?tokens"\s*:'),
    re.compile(r'client_max_body_size'),
    re.compile(r'(?i)MAX_TOKENS\s*='),
    re.compile(r'(?i)MAX_INPUT(?:_LENGTH)?\s*='),
    re.compile(r'(?i)token[_-]?(?:budget|limit)\s*[=:{]'),
    re.compile(r'(?i)"max[_-]?(?:input|context)[_-]?(?:length|tokens?)"\s*:'),
]


def _is_env_path(path: str) -> bool:
    name = path.split('/')[-1]
    return name == '.env' or name.startswith('.env.') or name.endswith('.env')


def _is_placeholder(val: str) -> bool:
    v = val.lower()
    return any(f in v for f in _PLACEHOLDER_FRAGMENTS) or len(val.strip()) < 8


def _scan(ctx: ScanContext, patterns: list, skip_env: bool = True) -> list:
    """Return list of (path, lineno, line) for matching lines."""
    hits = []
    for path, content in ctx.files.items():
        if skip_env and _is_env_path(path):
            continue
        for i, line in enumerate(content.splitlines(), 1):
            for regex in patterns:
                if regex.search(line):
                    hits.append((path, i, line.strip()[:120]))
                    break
    return hits


def _any_match(text: str, patterns: list) -> bool:
    return any(r.search(text) for r in patterns)


def _mask(line: str) -> str:
    line = re.sub(r'(sk-(?:ant-api\d+-)?[a-zA-Z0-9_-]{4})[a-zA-Z0-9_-]+', r'\1***', line)
    line = re.sub(r'(hf_[a-zA-Z0-9]{4})[a-zA-Z0-9]+', r'\1***', line)
    line = re.sub(r'(gsk_[a-zA-Z0-9]{4})[a-zA-Z0-9]+', r'\1***', line)
    line = re.sub(
        r'((?:password|token|secret|key)\s*[=:]\s*)[^\s"\'#\n]{6,}',
        r'\1***', line, flags=re.IGNORECASE,
    )
    return line


# ── Check implementations ──────────────────────────────────────────────────

def check_deploy_001(ctx: ScanContext) -> CheckResult:
    key_hits = []
    for regex, desc in _API_KEY_RE:
        for path, lineno, line in _scan(ctx, [regex], skip_env=True):
            if path.endswith('.py') or path.endswith('.md'):
                continue  # skip source/doc files — pattern strings match themselves
            m = regex.search(line)
            if m and not _is_placeholder(m.group(0)):
                key_hits.append((path, lineno, desc, line))

    gi_issues = []
    if not ctx.has_gitignore:
        gi_issues.append("No .gitignore found — .env files could be accidentally committed")
    else:
        if not any(p in ctx.gitignore_content for p in ('.env', '*.env')):
            gi_issues.append(".gitignore does not include .env or *.env patterns")

    if key_hits:
        ev = [f"{p}:{n} — {d}" for p, n, d, _ in key_hits[:5]]
        ev += gi_issues
        return CheckResult(
            check_id="AI-DEPLOY-001",
            title="API Keys Not Exposed",
            status=FAIL,
            severity="CRITICAL",
            category=CATEGORY,
            details=(
                f"{len(key_hits)} API key(s) detected in source files outside .env. "
                "Rotate these immediately — anyone with repo access can use them."
            ),
            evidence=[_mask(e) for e in ev],
            remediation=(
                "1. Rotate any exposed key at the provider dashboard NOW.\n"
                "2. Remove the key from the source file; add it to a .env file instead.\n"
                "3. Add '.env' and '*.env' to .gitignore.\n"
                "4. Check git history: git log --all -S 'sk-' -- ."
            ),
            frameworks={"OWASP LLM": "LLM07", "FedRAMP": "IA-5", "NIST AI RMF": "MANAGE 2.2"},
        )
    elif gi_issues:
        return CheckResult(
            check_id="AI-DEPLOY-001",
            title="API Keys Not Exposed",
            status=WARN,
            severity="CRITICAL",
            category=CATEGORY,
            details="No API keys found in source files, but .gitignore may not protect .env files from accidental commits.",
            evidence=gi_issues,
            remediation="Add '.env' and '*.env' to your .gitignore file.",
            frameworks={"OWASP LLM": "LLM07", "FedRAMP": "IA-5", "NIST AI RMF": "MANAGE 2.2"},
        )
    else:
        ev = []
        if ctx.has_gitignore:
            ev.append(".gitignore found with .env protection")
        if ctx.env_files:
            ev.append(f"{len(ctx.env_files)} .env file(s) present (correct storage location)")
        return CheckResult(
            check_id="AI-DEPLOY-001",
            title="API Keys Not Exposed",
            status=PASS,
            severity="CRITICAL",
            category=CATEGORY,
            details="No API keys detected in source files. .gitignore protects .env files.",
            evidence=ev,
            frameworks={"OWASP LLM": "LLM07", "FedRAMP": "IA-5", "NIST AI RMF": "MANAGE 2.2"},
        )


def check_deploy_002(ctx: ScanContext) -> CheckResult:
    hits = []
    for regex, desc in _CRED_RE:
        for path, lineno, line in _scan(ctx, [regex], skip_env=True):
            if path.endswith('.py') or path.endswith('.md'):
                continue  # skip source/doc files — credential patterns match regex strings
            m = regex.search(line)
            if m:
                captured = m.group(1) if m.lastindex else m.group(0)
                if not _is_placeholder(captured):
                    hits.append(f"{path}:{lineno} — {desc}")

    if hits:
        return CheckResult(
            check_id="AI-DEPLOY-002",
            title="No Hardcoded Credentials in Model Config",
            status=FAIL,
            severity="HIGH",
            category=CATEGORY,
            details=f"{len(hits)} hardcoded credential(s) found in config files. These give attackers access to your databases and services.",
            evidence=[_mask(h) for h in hits[:5]],
            remediation=(
                "1. Replace hardcoded values with environment variable references: ${DB_PASSWORD}.\n"
                "2. Rotate all exposed credentials.\n"
                "3. For docker-compose: use env_file: .env or secrets: instead of environment: with values.\n"
                "4. For Kubernetes: use Secret objects, not ConfigMaps."
            ),
            frameworks={"OWASP LLM": "LLM07", "FedRAMP": "IA-5, CM-6", "NIST AI RMF": "MANAGE 2.2"},
        )
    else:
        all_text = '\n'.join(
            v for k, v in ctx.files.items() if not _is_env_path(k)
        )
        has_ref = bool(re.search(r'\$\{[A-Z_]+\}|\$\([A-Z_]+\)', all_text))
        ev = []
        if has_ref:
            ev.append("Environment variable references found (${}  style) — credentials correctly externalized")
        ev.append(f"{len(ctx.env_files)} .env file(s) present for secret storage")
        return CheckResult(
            check_id="AI-DEPLOY-002",
            title="No Hardcoded Credentials in Model Config",
            status=PASS,
            severity="HIGH",
            category=CATEGORY,
            details="No hardcoded credentials detected in config files.",
            evidence=ev,
            frameworks={"OWASP LLM": "LLM07", "FedRAMP": "IA-5, CM-6", "NIST AI RMF": "MANAGE 2.2"},
        )


def check_deploy_003(ctx: ScanContext) -> CheckResult:
    all_text = '\n'.join(ctx.files.values())
    log_hits = [r.pattern for r in _LOG_RE if r.search(all_text)]
    has_retention = bool(_LOG_RETENTION_RE.search(all_text))

    if not log_hits:
        return CheckResult(
            check_id="AI-DEPLOY-003",
            title="Logging Enabled and Retained",
            status=WARN,
            severity="HIGH",
            category=CATEGORY,
            details=(
                "No logging configuration detected in scanned files. "
                "Without logs, you cannot detect abuse, investigate incidents, or produce compliance evidence."
            ),
            evidence=["No log_level, log_file, access_log, or logging framework configuration found"],
            remediation=(
                "1. Add structured logging to your AI service (log timestamp, session ID, request hash, response hash, latency).\n"
                "2. Do NOT log raw user inputs that may contain PII — log a hash or truncated summary.\n"
                "3. Configure log rotation: minimum 30 days for SMB, 90 days for regulated environments.\n"
                "4. Route logs to a write-protected sink (file with restricted permissions, CloudWatch, etc.)."
            ),
            frameworks={"OWASP LLM": "LLM10", "FedRAMP": "AU-2, AU-11", "NIST AI RMF": "MEASURE 2.5"},
        )
    elif not has_retention:
        return CheckResult(
            check_id="AI-DEPLOY-003",
            title="Logging Enabled and Retained",
            status=WARN,
            severity="HIGH",
            category=CATEGORY,
            details="Logging configuration found, but no log retention or rotation settings detected.",
            evidence=[f"Logging config detected ({len(log_hits)} pattern(s) matched)",
                      "No retention/rotation policy found in config"],
            remediation=(
                "Configure log retention: minimum 30 days for SMB, 90 days for regulated environments.\n"
                "Add log rotation settings to your web server or application config."
            ),
            frameworks={"OWASP LLM": "LLM10", "FedRAMP": "AU-2, AU-11", "NIST AI RMF": "MEASURE 2.5"},
        )
    else:
        return CheckResult(
            check_id="AI-DEPLOY-003",
            title="Logging Enabled and Retained",
            status=PASS,
            severity="HIGH",
            category=CATEGORY,
            details="Logging configuration and retention settings found.",
            evidence=[f"Logging patterns matched: {len(log_hits)}", "Log retention configuration present"],
            frameworks={"OWASP LLM": "LLM10", "FedRAMP": "AU-2, AU-11", "NIST AI RMF": "MEASURE 2.5"},
        )


def check_deploy_004(ctx: ScanContext) -> CheckResult:
    all_text = '\n'.join(ctx.files.values())
    has_auth = any(r.search(all_text) for r in _AUTH_POSITIVE_RE)

    # Check for openly exposed ports in docker-compose
    exposed_ports = []
    if ctx.docker_compose_raw:
        for m in _PORT_EXPOSED_RE.finditer(ctx.docker_compose_raw):
            port = m.group(1)
            exposed_ports.append(port)

    if not has_auth and exposed_ports:
        return CheckResult(
            check_id="AI-DEPLOY-004",
            title="Access Controls on AI Endpoint",
            status=FAIL,
            severity="CRITICAL",
            category=CATEGORY,
            details=(
                f"Port(s) {', '.join(exposed_ports)} exposed in docker-compose with no authentication configuration detected. "
                "An unauthenticated AI endpoint can be used by anyone who can reach it."
            ),
            evidence=[
                f"Exposed ports: {', '.join(exposed_ports)}",
                "No authentication configuration found (no JWT, API key, auth_basic, OAuth)",
            ],
            remediation=(
                "1. Add authentication middleware to all AI endpoint routes.\n"
                "2. Test: curl -X POST http://your-endpoint/v1/chat/completions — should return 401.\n"
                "3. Restrict port binding: use 127.0.0.1:8080:8080 for local-only access.\n"
                "4. Add an API gateway with auth enforcement in front of the AI service."
            ),
            frameworks={"OWASP LLM": "LLM07", "FedRAMP": "AC-3, AC-17", "NIST AI RMF": "GOVERN 1.1"},
        )
    elif not has_auth:
        return CheckResult(
            check_id="AI-DEPLOY-004",
            title="Access Controls on AI Endpoint",
            status=WARN,
            severity="CRITICAL",
            category=CATEGORY,
            details="No authentication configuration found in scanned files. Cannot verify endpoint protection.",
            evidence=["No JWT, API key, auth_basic, or OAuth configuration detected"],
            remediation=(
                "Ensure authentication is enforced at the gateway layer for all AI endpoint routes.\n"
                "Test by sending an unauthenticated request — it should return 401, not model output."
            ),
            frameworks={"OWASP LLM": "LLM07", "FedRAMP": "AC-3", "NIST AI RMF": "GOVERN 1.1"},
        )
    else:
        ev = ["Authentication configuration detected"]
        if exposed_ports:
            ev.append(f"Exposed ports: {', '.join(exposed_ports)} (verify auth is enforced)")
        return CheckResult(
            check_id="AI-DEPLOY-004",
            title="Access Controls on AI Endpoint",
            status=PASS,
            severity="CRITICAL",
            category=CATEGORY,
            details="Authentication configuration found in deployment files.",
            evidence=ev,
            frameworks={"OWASP LLM": "LLM07", "FedRAMP": "AC-3", "NIST AI RMF": "GOVERN 1.1"},
        )


def check_deploy_005(ctx: ScanContext) -> CheckResult:
    all_text = '\n'.join(ctx.files.values())
    has_tls = any(r.search(all_text) for r in _TLS_POSITIVE_RE)
    http_only_hits = _scan(ctx, _HTTP_ONLY_RE, skip_env=False)

    if http_only_hits and not has_tls:
        return CheckResult(
            check_id="AI-DEPLOY-005",
            title="TLS/HTTPS Enforced on All AI Connections",
            status=FAIL,
            severity="HIGH",
            category=CATEGORY,
            details=(
                "Plain HTTP endpoints detected with no TLS configuration. "
                "AI traffic is sensitive — unencrypted connections expose prompts, responses, and API keys."
            ),
            evidence=[f"{p}:{n} — {l}" for p, n, l in http_only_hits[:3]],
            remediation=(
                "1. Obtain a TLS certificate (Let's Encrypt is free: certbot).\n"
                "2. Configure your web server to reject plain HTTP or redirect to HTTPS.\n"
                "3. Set minimum TLS version: ssl_protocols TLSv1.2 TLSv1.3;\n"
                "4. Add HSTS: Strict-Transport-Security: max-age=31536000; includeSubDomains"
            ),
            frameworks={"OWASP LLM": "LLM08", "FedRAMP": "SC-8", "NIST AI RMF": "MANAGE 2.2"},
        )
    elif not has_tls:
        return CheckResult(
            check_id="AI-DEPLOY-005",
            title="TLS/HTTPS Enforced on All AI Connections",
            status=WARN,
            severity="HIGH",
            category=CATEGORY,
            details="No TLS configuration detected. Cannot verify that AI connections are encrypted.",
            evidence=["No ssl_certificate, ssl_protocols, or HTTPS configuration found"],
            remediation="Configure TLS on your AI endpoint. For local dev this is acceptable; for production or any external traffic it is required.",
            frameworks={"OWASP LLM": "LLM08", "FedRAMP": "SC-8", "NIST AI RMF": "MANAGE 2.2"},
        )
    else:
        return CheckResult(
            check_id="AI-DEPLOY-005",
            title="TLS/HTTPS Enforced on All AI Connections",
            status=PASS,
            severity="HIGH",
            category=CATEGORY,
            details="TLS configuration found in deployment files.",
            evidence=["TLS/SSL configuration detected"],
            frameworks={"OWASP LLM": "LLM08", "FedRAMP": "SC-8", "NIST AI RMF": "MANAGE 2.2"},
        )


def check_deploy_006(ctx: ScanContext) -> CheckResult:
    all_text = '\n'.join(ctx.files.values())
    has_rate_limit = any(r.search(all_text) for r in _RATE_LIMIT_RE)

    if not has_rate_limit:
        return CheckResult(
            check_id="AI-DEPLOY-006",
            title="Rate Limiting Configured",
            status=FAIL,
            severity="MEDIUM",
            category=CATEGORY,
            details=(
                "No rate limiting configuration detected. "
                "Without limits, a single user or script can exhaust your entire API budget in minutes."
            ),
            evidence=["No rate_limit, limit_req, requests_per_minute, or throttle configuration found"],
            remediation=(
                "1. Add rate limiting at the API gateway: nginx limit_req_zone, AWS API Gateway throttling.\n"
                "2. Set per-user or per-IP limits (start conservative: 100 req/min).\n"
                "3. Set a monthly spend limit in your AI provider dashboard.\n"
                "4. For agentic workflows: add max_iterations and max_tokens parameters to every agent run."
            ),
            frameworks={"OWASP LLM": "LLM10", "FedRAMP": "SC-5", "NIST AI RMF": "MANAGE 2.2"},
        )
    else:
        return CheckResult(
            check_id="AI-DEPLOY-006",
            title="Rate Limiting Configured",
            status=PASS,
            severity="MEDIUM",
            category=CATEGORY,
            details="Rate limiting configuration found in deployment files.",
            evidence=["Rate limiting patterns detected in config"],
            frameworks={"OWASP LLM": "LLM10", "FedRAMP": "SC-5", "NIST AI RMF": "MANAGE 2.2"},
        )


def check_inp_005_config(ctx: ScanContext) -> CheckResult:
    """AI-INP-005 config-mode portion: check for input limit settings."""
    all_text = '\n'.join(ctx.files.values())
    has_limits = any(r.search(all_text) for r in _INPUT_LIMIT_RE)

    if not has_limits:
        return CheckResult(
            check_id="AI-INP-005",
            title="Input Length and Token Limits Enforced",
            status=WARN,
            severity="MEDIUM",
            category="AI-INP",
            details=(
                "No input length or token limit configuration detected. "
                "Unbounded inputs enable context overflow attacks, accidental cost overruns, and DoS via resource exhaustion."
            ),
            evidence=["No max_tokens, client_max_body_size, or input length limit found in config files"],
            remediation=(
                "1. Add client_max_body_size in nginx (e.g., 1m for most AI use cases).\n"
                "2. Add max_tokens to your model call configuration.\n"
                "3. For multi-turn conversations: cap total conversation history length.\n"
                "Note: Run with --mode api or --mode local to verify limits are enforced at runtime."
            ),
            frameworks={"OWASP LLM": "LLM10", "FedRAMP": "SI-10, SC-5", "NIST AI RMF": "MANAGE 2.2"},
        )
    else:
        return CheckResult(
            check_id="AI-INP-005",
            title="Input Length and Token Limits Enforced",
            status=PASS,
            severity="MEDIUM",
            category="AI-INP",
            details="Input limit configuration found in deployment files.",
            evidence=["max_tokens or input length limit configuration detected"],
            frameworks={"OWASP LLM": "LLM10", "FedRAMP": "SI-10", "NIST AI RMF": "MANAGE 2.2"},
        )


def run_all(ctx: ScanContext) -> list:
    return [
        check_deploy_001(ctx),
        check_deploy_002(ctx),
        check_deploy_003(ctx),
        check_deploy_004(ctx),
        check_deploy_005(ctx),
        check_deploy_006(ctx),
    ]
