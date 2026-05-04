"""
AI-RUNTIME checks — Runtime Behavioral Monitoring
Checks: AI-RUNTIME-001 through AI-RUNTIME-005

Evaluates whether the AI deployment has runtime monitoring wired in.
Inspects config files and the live Hash runtime API when available.
"""
import re
from . import CheckResult, PASS, FAIL, WARN
from connectors.config_connector import ScanContext

CATEGORY = "AI-RUNTIME"

_MON_ENABLED_RE  = re.compile(r'(?i)"monitoring"\s*:\s*\{[^}]*"enabled"\s*:\s*true')
_MON_DB_RE       = re.compile(r'(?i)"(?:db_path|log_path|activity[_-]?db)"\s*:\s*"[^"]+\.db"')
_RETENTION_RE    = re.compile(r'(?i)"retention[_-]?days"\s*:\s*([0-9]+)')
_ANOMALY_RE      = re.compile(r'(?i)"anomaly[_-]?detection"\s*:\s*\{[^}]*"enabled"\s*:\s*true')
_BUDGET_RE       = re.compile(r'(?i)"(?:max[_-]?tokens?|token[_-]?budget|token[_-]?limit)"\s*:\s*[0-9]')
_HUMAN_LOOP_RE   = re.compile(
    r'(?i)"(?:human[_-]?(?:in[_-]?(?:the[_-]?)?loop|oversight|review|approval)|'
    r'require[_-]?confirm(?:ation)?|hitl|approval[_-]?required)"\s*:\s*true'
)
_AUDIT_TRAIL_RE  = re.compile(
    r'(?i)"(?:prompt[_-]?(?:audit|log|trail|hash)|audit[_-]?trail|log[_-]?prompts?'
    r'|prompt[_-]?logging)"\s*:\s*true'
)


def _all_text(ctx: ScanContext) -> str:
    return "\n".join(ctx.files.values())


def check_runtime_001(ctx: ScanContext) -> CheckResult:
    """AI-RUNTIME-001 — Inference activity logging enabled."""
    all_text = _all_text(ctx)

    monitoring_enabled = bool(_MON_ENABLED_RE.search(all_text))
    has_db_path        = bool(_MON_DB_RE.search(all_text))

    activity_db_exists = False
    for rel_path in ctx.files:
        if ".activity.db" in rel_path or "activity_log" in rel_path:
            activity_db_exists = True
            break

    if monitoring_enabled and (has_db_path or activity_db_exists):
        return CheckResult(
            check_id="AI-RUNTIME-001",
            title="Inference activity logging enabled",
            status=PASS,
            severity="CRITICAL",
            category=CATEGORY,
            details="monitoring.enabled = true and activity log database configured.",
            remediation="",
        )

    if monitoring_enabled and not has_db_path:
        return CheckResult(
            check_id="AI-RUNTIME-001",
            title="Inference activity logging enabled but no log path configured",
            status=WARN,
            severity="MEDIUM",
            category=CATEGORY,
            details="monitoring.enabled = true but no db_path found — logs may not persist.",
            remediation=(
                'Add "db_path" under "monitoring" in hash.json:\n'
                '  "monitoring": {"enabled": true, "db_path": "workspace/memory/.activity.db"}'
            ),
        )

    return CheckResult(
        check_id="AI-RUNTIME-001",
        title="Inference activity logging not enabled",
        status=FAIL,
        severity="CRITICAL",
        category=CATEGORY,
        details="No monitoring configuration found. Every inference call is untracked.",
        remediation=(
            'Add to hash.json (or equivalent config):\n'
            '  "monitoring": {\n'
            '    "enabled": true,\n'
            '    "db_path": "workspace/memory/.activity.db",\n'
            '    "retention_days": 30\n'
            '  }'
        ),
        evidence=[],
    )


def check_runtime_002(ctx: ScanContext) -> CheckResult:
    """AI-RUNTIME-002 — Anomaly detection configured."""
    all_text = _all_text(ctx)

    if _ANOMALY_RE.search(all_text):
        return CheckResult(
            check_id="AI-RUNTIME-002",
            title="Anomaly detection configured",
            status=PASS,
            severity="HIGH",
            category=CATEGORY,
            details="anomaly_detection.enabled = true found in config.",
            remediation="",
        )

    if _MON_ENABLED_RE.search(all_text):
        return CheckResult(
            check_id="AI-RUNTIME-002",
            title="Activity logging enabled but anomaly detection not configured",
            status=WARN,
            severity="MEDIUM",
            category=CATEGORY,
            details="monitoring.enabled = true but no anomaly_detection block found.",
            remediation=(
                'Add anomaly detection to hash.json:\n'
                '  "monitoring": {\n'
                '    "enabled": true,\n'
                '    "anomaly_detection": {"enabled": true}\n'
                '  }'
            ),
        )

    return CheckResult(
        check_id="AI-RUNTIME-002",
        title="Anomaly detection not configured",
        status=FAIL,
        severity="HIGH",
        category=CATEGORY,
        details="No anomaly detection found. Token spikes, off-hours agentic activity, "
               "and unexpected tool calls go undetected.",
        remediation=(
            'Add to hash.json:\n'
            '  "monitoring": {\n'
            '    "enabled": true,\n'
            '    "anomaly_detection": {"enabled": true}\n'
            '  }'
        ),
        evidence=[],
    )


def check_runtime_003(ctx: ScanContext) -> CheckResult:
    """AI-RUNTIME-003 — Human oversight checkpoint for autonomous agent tasks."""
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
                '  }'
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
            '  "monitoring": {"token_budget_daily": 500000}'
        ),
        evidence=[],
    )


def check_runtime_005(ctx: ScanContext) -> CheckResult:
    """AI-RUNTIME-005 — Prompt audit trail retained."""
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
            '  }'
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
