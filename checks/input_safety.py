"""
AI-INP checks — Prompt Injection & Input Safety
Checks: AI-INP-001 through AI-INP-005

AI-INP-001 through 004 require live adversarial probes — SKIP in config mode.
AI-INP-005 is partially evaluable from config files.
"""
import re
from . import CheckResult, PASS, FAIL, WARN, SKIP
from connectors.config_connector import ScanContext

CATEGORY = "AI-INP"

_INPUT_LIMIT_RE = [
    re.compile(r'(?i)max[_-]?(?:tokens|input[_-]?length|message[_-]?length|context)\s*[=:{]'),
    re.compile(r'(?i)"max[_-]?tokens"\s*:'),
    re.compile(r'client_max_body_size'),
    re.compile(r'(?i)MAX_TOKENS\s*='),
    re.compile(r'(?i)MAX_INPUT(?:_LENGTH)?\s*='),
    re.compile(r'(?i)token[_-]?(?:budget|limit)\s*[=:{]'),
    re.compile(r'(?i)"max[_-]?(?:input|context)[_-]?(?:length|tokens?)"\s*:'),
]

_SKIP_MSG = (
    "This check requires a live AI connection to send adversarial probes. "
    "Run with --mode api or --mode local to evaluate."
)


def _skip(check_id: str, title: str) -> CheckResult:
    return CheckResult(
        check_id=check_id,
        title=title,
        status=SKIP,
        severity="CRITICAL" if check_id in ("AI-INP-001", "AI-INP-003") else "HIGH",
        category=CATEGORY,
        details=_SKIP_MSG,
        remediation="Rerun with --mode api --endpoint <url> or --mode local --ollama-host http://localhost:11434",
        frameworks={"OWASP LLM": "LLM01", "FedRAMP": "SI-10", "NIST AI RMF": "MEASURE 2.6"},
    )


def check_inp_001(ctx: ScanContext) -> CheckResult:
    return _skip("AI-INP-001", "System Prompt Cannot Be Overridden by User Input")


def check_inp_002(ctx: ScanContext) -> CheckResult:
    return _skip("AI-INP-002", "Direct Prompt Injection Resistance")


def check_inp_003(ctx: ScanContext) -> CheckResult:
    return _skip("AI-INP-003", "Indirect Prompt Injection Resistance (RAG)")


def check_inp_004(ctx: ScanContext) -> CheckResult:
    return _skip("AI-INP-004", "Jailbreak Resistance")


def check_inp_005(ctx: ScanContext) -> CheckResult:
    all_text = '\n'.join(ctx.files.values())
    has_limits = any(r.search(all_text) for r in _INPUT_LIMIT_RE)

    if not has_limits:
        return CheckResult(
            check_id="AI-INP-005",
            title="Input Length and Token Limits Enforced",
            status=WARN,
            severity="MEDIUM",
            category=CATEGORY,
            details=(
                "No input length or token limit configuration detected. "
                "Unbounded inputs enable context overflow attacks, cost overruns, and resource exhaustion."
            ),
            evidence=["No max_tokens, client_max_body_size, or input limit found in scanned config files"],
            remediation=(
                "1. Add client_max_body_size in nginx (e.g., client_max_body_size 1m).\n"
                "2. Set max_tokens in your model call configuration.\n"
                "3. For multi-turn: cap conversation history length.\n"
                "4. Run with --mode api or --mode local to verify limits are enforced at runtime."
            ),
            frameworks={"OWASP LLM": "LLM10", "FedRAMP": "SI-10, SC-5", "NIST AI RMF": "MANAGE 2.2"},
        )
    else:
        return CheckResult(
            check_id="AI-INP-005",
            title="Input Length and Token Limits Enforced",
            status=PASS,
            severity="MEDIUM",
            category=CATEGORY,
            details="Input limit configuration found in deployment files.",
            evidence=["max_tokens or input length limit configuration detected"],
            frameworks={"OWASP LLM": "LLM10", "FedRAMP": "SI-10", "NIST AI RMF": "MANAGE 2.2"},
        )


def run_all(ctx: ScanContext) -> list:
    return [
        check_inp_001(ctx),
        check_inp_002(ctx),
        check_inp_003(ctx),
        check_inp_004(ctx),
        check_inp_005(ctx),
    ]
