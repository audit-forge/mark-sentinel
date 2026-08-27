"""
AI-DEPLOY checks — Deployment Security
Checks: AI-DEPLOY-001 through AI-DEPLOY-006
"""
import re
import shlex
from fnmatch import fnmatch
from pathlib import PurePosixPath
from . import CheckResult, PASS, FAIL, WARN
from connectors.config_connector import ScanContext

CATEGORY = "AI-DEPLOY"
PLAINTEXT_API_KEY_TITLE = "Plaintext Secret Outside Protected Secret Storage"

# API key patterns — only match values that look like real keys (long, opaque)
_API_KEY_RE = [
    (re.compile(r'(?<![a-zA-Z])sk-[a-zA-Z0-9_-]{20,}'), 'OpenAI API key'),
    (re.compile(r'(?<![a-zA-Z])sk-ant-api\d+-[a-zA-Z0-9_-]{20,}'), 'Anthropic API key'),
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
    'fixture', 'fake', 'sample', 'dummy', 'test-key', 'testkey', 'demo-',
)

_CRED_RE = [
    (re.compile(r'(?im)^(?:export\s+)?(?:DB|DATABASE|MYSQL|POSTGRES|MONGODB)_PASSWORD\s*=\s*(?!\$\{)(?!\$\()(?!\s*$)(.+)$'), 'Database password'),
    (re.compile(r'(?im)^(?:export\s+)?REDIS_PASSWORD\s*=\s*(?!\$)(?!\s*$)(.+)$'), 'Redis password'),
    (re.compile(r'(?i)postgres(?:ql)?://[^:\s]+:(?!\$\{)(?!\$\()([^@\s]{4,})@'), 'PostgreSQL URL with password'),
    (re.compile(r'(?i)mysql://[^:\s]+:(?!\$\{)(?!\$\()([^@\s]{4,})@'), 'MySQL URL with password'),
    (re.compile(r'(?i)mongodb://[^:\s]+:(?!\$\{)(?!\$\()([^@\s]{4,})@'), 'MongoDB URL with password'),
    (re.compile(r'(?i)"password"\s*:\s*"(?!\$\{)([^"$]{4,})"'), 'Password in JSON'),
]

_RUNTIME_ENV_CRED_RE = re.compile(
    r'(?im)^\s*(?:export\s+)?([A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|API_KEY)[A-Z0-9_]*)\s*=\s*(.+)$'
)
# *_FILE variables point at secret files (Docker secrets, 12-factor) — not hardcoded values.
_RUNTIME_ENV_FILE_RE = re.compile(r'(?im)^\s*(?:export\s+)?([A-Z0-9_]+_FILE)\s*=')
_AGENT_JSON_TOKEN_RE = re.compile(r'(?i)"[a-z0-9_-]*token"\s*:\s*"([^"]+)"')

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


# ── AI-DEPLOY-002: CI test-fixture classifier ──────────────────────────────
# A PostgreSQL connection string inside a GitHub Actions workflow that points at
# that same workflow's `postgres` service container, with a test-named database,
# is a CI fixture — it grants no access outside the ephemeral runner. It stays
# visible, but as WARN/LOW under its own title instead of FAIL/HIGH.
CI_TEST_CREDENTIAL_TITLE = "CI Test Credential Hygiene"

_WORKFLOW_PATH_RE = re.compile(r'(?:^|/)\.github/workflows/[^/]+\.ya?ml$', re.IGNORECASE)
_PG_URL_HOST_RE = re.compile(r'(?i)postgres(?:ql)?://[^:\s/@]+:[^@\s]{4,}@([A-Za-z0-9._-]+)')
_CI_LOCAL_HOSTS = frozenset({'localhost', '127.0.0.1'})
_SERVICES_KEY_RE = re.compile(r'(?m)^\s*services:\s*(?:#.*)?$')
_PG_SERVICE_IMAGE_RE = re.compile(
    r'(?im)^\s*image:\s*["\']?(?:docker\.io/)?(?:library/)?postgres(?:[:@\s"\']|$)'
)
_POSTGRES_DB_RE = re.compile(r'(?im)^\s*POSTGRES_DB\s*[:=]\s*["\']?([A-Za-z0-9._-]+)')


def _pg_url_host(line: str) -> str:
    """Host portion of a PostgreSQL URL. Never returns the credential value."""
    m = _PG_URL_HOST_RE.search(line)
    return m.group(1).lower() if m else ''


def _declares_postgres_service(workflow: str) -> bool:
    return bool(_SERVICES_KEY_RE.search(workflow) and _PG_SERVICE_IMAGE_RE.search(workflow))


def _has_test_postgres_db(workflow: str) -> bool:
    return any('test' in m.group(1).lower() for m in _POSTGRES_DB_RE.finditer(workflow))


def _is_ci_test_credential(path: str, desc: str, line: str, workflow: str) -> bool:
    """True only when every CI-fixture condition holds — anything else is a real hit."""
    if desc != 'PostgreSQL URL with password':
        return False
    if not _WORKFLOW_PATH_RE.search(path.replace('\\', '/')):
        return False
    if _pg_url_host(line) not in _CI_LOCAL_HOSTS:
        return False
    return _declares_postgres_service(workflow) and _has_test_postgres_db(workflow)


def _is_env_path(path: str) -> bool:
    name = path.split('/')[-1]
    return name == '.env' or name.startswith('.env.') or name.endswith('.env')


def _is_placeholder(val: str) -> bool:
    v = val.lower()
    return any(f in v for f in _PLACEHOLDER_FRAGMENTS) or len(val.strip()) < 8


def _scan(ctx: ScanContext, patterns: list, skip_env: bool = True) -> list:
    """Return list of (path, lineno, line) for matching lines."""
    # Exclude system package directories — installed packages (botocore, AWS SDKs,
    # Google Ops Agent) contain schema/example JSON with credential-like patterns
    # that are not user-declared secrets. These are false positives.
    _SYSTEM_PATH_PREFIXES = (
        'usr/lib/', 'usr/share/', 'usr/local/lib/', 'usr/local/share/',
        'lib/python', 'site-packages/', 'dist-packages/', 'node_modules/',
        'google-cloud-ops-agent', 'opt/google',
    )
    hits = []
    for path, content in ctx.files.items():
        if any(p in path for p in _SYSTEM_PATH_PREFIXES):
            continue
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
            val = m.group(1) if m and m.lastindex else (m.group(0) if m else None)
            if m and not _is_placeholder(val):
                # Google Chat incoming-webhook URLs include an AIza token as part
                # of the webhook credential. They are not Gemini API keys.
                if desc == 'Google/Gemini API key' and 'chat.googleapis.com/' in line:
                    continue
                key_hits.append((path, lineno, desc, line))

    gi_issues = []
    if not ctx.has_gitignore:
        gi_issues.append("No .gitignore found — .env files could be accidentally committed")
    else:
        if not any(p in ctx.gitignore_content for p in ('.env', '*.env')):
            gi_issues.append(".gitignore does not include .env or *.env patterns")

    if key_hits:
        return CheckResult(
            check_id="AI-DEPLOY-001",
            title=PLAINTEXT_API_KEY_TITLE,
            status=FAIL,
            severity="CRITICAL",
            category=CATEGORY,
            details=(
                f"{len(key_hits)} secret(s) detected in plaintext configuration or deployment files. "
                "Restrict access and rotate any credential that remains active."
            ),
            evidence=[_mask(f"{p}:{n} — {d}") for p, n, d, _ in key_hits[:5]],
            remediation=(
                "1. Rotate any exposed key at the provider dashboard NOW.\n"
                "2. Remove the key from the plaintext file and store it in the service's protected "
                "secret mechanism or environment.\n"
                "3. Restrict secret files to the service identity (typically mode 0600).\n"
                "4. If the file is tracked by Git, remove the key from history and add '.env' and '*.env' "
                "to .gitignore."
            ),
            frameworks={"OWASP LLM": "LLM07", "FedRAMP": "IA-5", "NIST AI RMF": "MANAGE 2.2"},
        )
    elif gi_issues:
        return CheckResult(
            check_id="AI-DEPLOY-001",
            title="API Key Exposure Risk — .gitignore Gap",
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
    findings = []  # (path, lineno, desc, is_ci_fixture, host)
    for regex, desc in _CRED_RE:
        for path, lineno, line in _scan(ctx, [regex], skip_env=True):
            if path.endswith('.py') or path.endswith('.md'):
                continue  # skip source/doc files — credential patterns match regex strings
            m = regex.search(line)
            if not m:
                continue
            # Classify first: a qualifying CI fixture never has its password bound
            # to a local, not even transiently. Only non-CI hits reach _is_placeholder.
            if _is_ci_test_credential(path, desc, line, ctx.files.get(path, '')):
                findings.append((path, lineno, desc, True, _pg_url_host(line)))
                continue
            captured = m.group(1) if m.lastindex else m.group(0)
            if not _is_placeholder(captured):
                findings.append((path, lineno, desc, False, ''))

    findings.extend(_docker_context_credential_findings(ctx))

    hits = [f"{p}:{n} — {d}" for p, n, d, _, _ in findings]
    ci_findings = [f for f in findings if f[3]]

    if hits and len(ci_findings) == len(findings):
        # Every hit is a local CI service fixture — report it, but not as an exposure.
        return CheckResult(
            check_id="AI-DEPLOY-002",
            title=CI_TEST_CREDENTIAL_TITLE,
            status=WARN,
            severity="LOW",
            category=CATEGORY,
            details=(
                f"{len(ci_findings)} PostgreSQL connection string(s) in GitHub Actions workflow(s) "
                "point at the workflow's own postgres service container using a test-named database. "
                "These are CI fixtures scoped to the ephemeral runner, not production credentials — "
                "no external system is reachable with them. No hardcoded production credentials were found."
            ),
            evidence=[
                _mask(f"{p}:{n} — {d} (local CI postgres service fixture, host {host})")
                for p, n, d, _, host in ci_findings[:5]
            ],
            remediation=(
                "1. Keep CI fixture connection strings pointed at localhost/127.0.0.1 and a test-only database.\n"
                "2. Prefer job-level env vars or ${{ secrets.* }} even for CI fixtures, so workflows match production practice.\n"
                "3. Never reuse a CI fixture password for any non-CI service."
            ),
            frameworks={"OWASP LLM": "LLM07", "FedRAMP": "IA-5, CM-6", "NIST AI RMF": "MANAGE 2.2"},
        )

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


def _dockerignore_excludes(path: str, dockerignore: str) -> bool:
    """Evaluate Dockerignore patterns for a normalized relative file path."""
    excluded = False
    for raw in dockerignore.splitlines():
        pattern = raw.strip()
        if not pattern or pattern.startswith('#'):
            continue
        negated = pattern.startswith('!')
        pattern = pattern[1:] if negated else pattern
        if _dockerignore_matches(path, pattern):
            excluded = not negated
    return excluded


def _dockerignore_matches(path: str, pattern: str) -> bool:
    """Match the Dockerignore path subset needed for file and directory rules."""
    path_parts = tuple(part for part in path.strip('/').split('/') if part)
    pattern = pattern.strip()
    if not pattern:
        return False
    directory_rule = pattern.endswith('/')
    pattern_parts = tuple(part for part in pattern.strip('/').split('/') if part)
    if not pattern_parts:
        return False
    # Docker excludes a subtree when a parent directory matches, even when the
    # pattern does not end in '/'. Evaluate each path prefix for that behavior.
    max_end = len(path_parts) - 1 if directory_rule else len(path_parts)
    for end in range(1, max_end + 1):
        candidate = path_parts[:end]
        if len(pattern_parts) == 1:
            if fnmatch(candidate[-1], pattern_parts[0]):
                return True
        elif _dockerignore_parts_match(candidate, pattern_parts):
            return True
    return False


def _dockerignore_parts_match(path_parts: tuple[str, ...], pattern_parts: tuple[str, ...]) -> bool:
    """Match path components so * never crosses a directory boundary; ** can."""
    if not pattern_parts:
        return not path_parts
    head, *tail = pattern_parts
    if head == '**':
        return any(_dockerignore_parts_match(path_parts[index:], tuple(tail))
                   for index in range(len(path_parts) + 1))
    return bool(path_parts) and fnmatch(path_parts[0], head) and _dockerignore_parts_match(
        path_parts[1:], tuple(tail))


def _dockerfile_copies_build_context(content: str) -> bool:
    """Return True when COPY/ADD uses the local build context as a source."""
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith('#'):
            continue
        try:
            parts = shlex.split(line, comments=True)
        except ValueError:
            continue
        if not parts or parts[0].lower() not in ('copy', 'add'):
            continue
        if any(part == '--from' or part.startswith('--from=') for part in parts[1:]):
            continue
        operands = [part for part in parts[1:] if not part.startswith('--')]
        if len(operands) >= 2 and any(PurePosixPath(source) == PurePosixPath('.')
                                      for source in operands[:-1]):
            return True
    return False


def _dockerfile_build_context_roots(ctx: ScanContext) -> dict[str, str]:
    """Map each Dockerfile's build-context root (its own directory) to that
    root's .dockerignore content, for every Dockerfile that COPY . .s its
    build context. A credential file elsewhere on a broader scan (e.g. a
    sibling project, or an unrelated /etc config on the same host) is not
    reachable by that COPY and must not be treated as if it were."""
    roots: dict[str, str] = {}
    for path, content in ctx.files.items():
        name = PurePosixPath(path).name.lower()
        if name.startswith('dockerfile') and _dockerfile_copies_build_context(content):
            root = str(PurePosixPath(path).parent)
            ignore_path = '.dockerignore' if root == '.' else f'{root}/.dockerignore'
            roots[root] = ctx.files.get(ignore_path, '')
    return roots


def _build_context_root_for(path: str, roots: dict[str, str]) -> str | None:
    """Return the build-context root that contains `path`, or None if `path`
    is outside every known Dockerfile's build context."""
    for root in roots:
        if root == '.' or path == root or path.startswith(root + '/'):
            return root
    return None


def _docker_context_credential_findings(ctx: ScanContext) -> list[tuple[str, int, str, bool, str]]:
    """Find runtime credentials that COPY . . would bake into a Docker image."""
    roots = _dockerfile_build_context_roots(ctx)
    if not roots:
        return []

    findings = []
    for path, content in ctx.files.items():
        root = _build_context_root_for(path, roots)
        if root is None:
            continue  # not reachable by any Dockerfile's COPY . . on this scan
        is_env = path in ctx.env_files
        is_agent_config = PurePosixPath(path).name == 'agent_config.json'
        is_agent_token = PurePosixPath(path).name == 'agent_token.txt'
        if not (is_env or is_agent_config or is_agent_token) or _dockerignore_excludes(path, roots[root]):
            continue
        if is_agent_token and content.strip() and not _is_placeholder(content.strip()):
            findings.append((path, 1, 'Agent authentication token baked into Docker image', False, ''))
        for lineno, line in enumerate(content.splitlines(), 1):
            # *_FILE= references are secret-file pointers, not hardcoded credentials.
            if _RUNTIME_ENV_FILE_RE.match(line):
                continue
            match = _RUNTIME_ENV_CRED_RE.match(line)
            if match and not _is_placeholder(match.group(2).strip()):
                findings.append((path, lineno, f'{match.group(1)} baked into Docker image', False, ''))
            if is_agent_config:
                match = _AGENT_JSON_TOKEN_RE.search(line)
                if match and len(match.group(1)) >= 16 and not _is_placeholder(match.group(1)):
                    findings.append((path, lineno, 'Agent authentication token baked into Docker image', False, ''))
    return findings


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
            evidence=[f"{p}:{n} — {ln}" for p, n, ln in http_only_hits[:3]],
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
        check_inp_005_config(ctx),
    ]
