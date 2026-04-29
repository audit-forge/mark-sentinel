"""
AI-OUT checks — Output & Data Safety
Checks: AI-OUT-001 through AI-OUT-005

AI-OUT-001 through 004 require live probes — SKIP in config mode.
AI-OUT-005 is evaluable via static code analysis.
"""
import re
from . import CheckResult, PASS, FAIL, WARN, SKIP
from connectors.config_connector import ScanContext

CATEGORY = "AI-OUT"

_SKIP_MSG = (
    "This check requires a live AI connection to send adversarial probes. "
    "Run with --mode api or --mode local to evaluate."
)

# Dangerous patterns for output sanitization check (AI-OUT-005)
_DANGEROUS_RE = [
    (re.compile(r'subprocess\.run\s*\(.*shell\s*=\s*True'), 'subprocess.run with shell=True (shell injection risk)'),
    (re.compile(r'subprocess\.call\s*\(.*shell\s*=\s*True'), 'subprocess.call with shell=True'),
    (re.compile(r'os\.system\s*\('), 'os.system() call (shell injection risk)'),
    (re.compile(r'\beval\s*\('), 'eval() call (code injection risk)'),
    (re.compile(r'\bexec\s*\('), 'exec() call (code injection risk)'),
    (re.compile(r'cursor\.execute\s*\(\s*f["\']|cursor\.execute\s*\(\s*".*%s.*"'), 'SQL string formatting (injection risk)'),
    (re.compile(r'render_template_string\s*\('), 'Flask render_template_string (SSTI risk)'),
    (re.compile(r'innerHTML\s*='), 'innerHTML assignment (XSS risk)'),
    (re.compile(r'document\.write\s*\('), 'document.write (XSS risk)'),
    (re.compile(r'(?i)dangerouslySetInnerHTML'), 'React dangerouslySetInnerHTML (XSS risk)'),
]

# Markers that suggest AI output is being used unsafely near dangerous patterns
_AI_OUTPUT_MARKERS = re.compile(
    r'(?i)(?:response|completion|output|result|generated|ai_|llm_|model_)'
    r'(?:\.content|\.text|\.choices|\.message|_text|_output|_response)',
)

_SANITIZATION_RE = [
    re.compile(r'(?i)(?:bleach|DOMPurify|html\.escape|escape\(|sanitize|htmlspecialchars)'),
    re.compile(r'(?i)parameterized|prepared[_\s]statement|ORM|sqlalchemy'),
    re.compile(r'(?i)subprocess.*args.*=.*\['),
]


def _skip(check_id: str, title: str, severity: str = "HIGH") -> CheckResult:
    return CheckResult(
        check_id=check_id,
        title=title,
        status=SKIP,
        severity=severity,
        category=CATEGORY,
        details=_SKIP_MSG,
        remediation="Rerun with --mode api --endpoint <url> or --mode local --ollama-host http://localhost:11434",
        frameworks={"OWASP LLM": "LLM02", "FedRAMP": "AC-4", "NIST AI RMF": "MEASURE 2.5"},
    )


def check_out_001(ctx: ScanContext) -> CheckResult:
    return _skip("AI-OUT-001", "Model Does Not Return Training Data on Request")


def check_out_002(ctx: ScanContext) -> CheckResult:
    return _skip("AI-OUT-002", "PII Not Leaked in Responses", severity="CRITICAL")


def check_out_003(ctx: ScanContext) -> CheckResult:
    return _skip("AI-OUT-003", "System Prompt Not Disclosed on Request")


def check_out_004(ctx: ScanContext) -> CheckResult:
    return _skip("AI-OUT-004", "Model Refusals Work for Harmful Content")


def check_out_005(ctx: ScanContext) -> CheckResult:
    """AI-OUT-005: Static analysis for unsafe AI output handling patterns."""
    danger_hits = []
    sanitized = False

    all_text = '\n'.join(ctx.python_files.values())

    # Check for sanitization patterns (positive signal)
    if any(r.search(all_text) for r in _SANITIZATION_RE):
        sanitized = True

    # Look for dangerous patterns in Python source files
    for path, content in ctx.python_files.items():
        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            for regex, desc in _DANGEROUS_RE:
                if regex.search(line):
                    # Check if AI output markers appear nearby (within 10 lines)
                    context_lines = '\n'.join(lines[max(0, i - 10):i + 5])
                    if _AI_OUTPUT_MARKERS.search(context_lines):
                        danger_hits.append(f"{path}:{i} — {desc} (near AI output usage)")
                    else:
                        danger_hits.append(f"{path}:{i} — {desc} (verify AI output is not passed here)")

    if not ctx.python_files:
        return CheckResult(
            check_id="AI-OUT-005",
            title="Output Sanitization Before Passing to Downstream Systems",
            status=SKIP,
            severity="CRITICAL",
            category=CATEGORY,
            details="No Python source files found to analyze. Static analysis requires source code in the target directory.",
            remediation="Point --target at a directory containing your application source code, or run with --mode api for live testing.",
            frameworks={"OWASP LLM": "LLM05", "FedRAMP": "SI-10", "NIST AI RMF": "MEASURE 2.5"},
        )

    if danger_hits and not sanitized:
        return CheckResult(
            check_id="AI-OUT-005",
            title="Output Sanitization Before Passing to Downstream Systems",
            status=FAIL,
            severity="CRITICAL",
            category=CATEGORY,
            details=(
                f"{len(danger_hits)} potentially unsafe output handling pattern(s) found near AI output usage. "
                "AI output passed to shell commands, eval(), or SQL queries without sanitization is exploitable."
            ),
            evidence=danger_hits[:5],
            remediation=(
                "1. Never trust AI output as safe input — treat it like user-supplied data.\n"
                "2. HTML output: run through bleach.clean() or html.escape() before rendering.\n"
                "3. Database queries: use ORM or parameterized queries, never f-strings.\n"
                "4. Shell commands: never shell=True with AI-generated arguments; use argument lists.\n"
                "5. Code execution: sandbox in a container (Docker, Pyodide) with no network/filesystem access."
            ),
            frameworks={"OWASP LLM": "LLM05", "FedRAMP": "SI-10, AC-4", "NIST AI RMF": "MEASURE 2.5"},
        )
    elif danger_hits:
        return CheckResult(
            check_id="AI-OUT-005",
            title="Output Sanitization Before Passing to Downstream Systems",
            status=WARN,
            severity="CRITICAL",
            category=CATEGORY,
            details=(
                f"{len(danger_hits)} potentially unsafe pattern(s) found. "
                "Sanitization library usage detected — verify it covers all AI output paths."
            ),
            evidence=danger_hits[:3] + ["Sanitization library usage detected (bleach/html.escape/parameterized queries)"],
            remediation=(
                "Review each flagged location to confirm AI output is sanitized before use. "
                "Ensure sanitization covers every code path, not just the common cases."
            ),
            frameworks={"OWASP LLM": "LLM05", "FedRAMP": "SI-10", "NIST AI RMF": "MEASURE 2.5"},
        )
    else:
        ev = [f"{len(ctx.python_files)} Python file(s) analyzed"]
        if sanitized:
            ev.append("Sanitization library usage detected (html.escape, bleach, parameterized queries)")
        return CheckResult(
            check_id="AI-OUT-005",
            title="Output Sanitization Before Passing to Downstream Systems",
            status=PASS,
            severity="CRITICAL",
            category=CATEGORY,
            details="No unsafe AI output handling patterns detected in Python source files.",
            evidence=ev,
            frameworks={"OWASP LLM": "LLM05", "FedRAMP": "SI-10", "NIST AI RMF": "MEASURE 2.5"},
        )


def run_all(ctx: ScanContext) -> list:
    return [
        check_out_001(ctx),
        check_out_002(ctx),
        check_out_003(ctx),
        check_out_004(ctx),
        check_out_005(ctx),
    ]
