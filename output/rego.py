"""
M.A.R.K. Sentinel — OPA Rego policy generator
Produces a Rego bundle that gates CI/CD using M.A.R.K. JSON report as input.

Usage:
  # Run audit, produce JSON
  python audit.py --mode config --profile fedramp --output json,rego --out-file report

  # Evaluate gate in CI
  opa eval -d report.rego -I < report.json "data.mark_sentinel.fedramp.allow"
  opa eval -d report.rego -I < report.json "data.mark_sentinel.fedramp.deny"
"""
from datetime import date


_HEADER = """\
# M.A.R.K. Sentinel — OPA Rego Policy Bundle
# Profile : {profile}
# Target  : {target}
# Mode    : {mode}
# Generated: {today}
#
# Evaluate against a M.A.R.K. JSON report:
#   opa eval -d {pkg}.rego -I < report.json "data.mark_sentinel.{pkg}.allow"
#   opa eval -d {pkg}.rego -I < report.json "data.mark_sentinel.{pkg}.deny"
#
# Input schema: {{ "findings": [ {{ "check_id", "title", "status", "severity",
#                                   "category", "details", "frameworks" }} ] }}

package mark_sentinel.{pkg}

import future.keywords.if
import future.keywords.in
"""

_CORE_RULES = """\
# ---------------------------------------------------------------------------
# Top-level gate — use in CI/CD pipeline
# ---------------------------------------------------------------------------

default allow := false

allow if {{
    count(deny) == 0
}}

# Block on any CRITICAL or HIGH failure
deny[msg] if {{
    finding := input.findings[_]
    finding.status == "FAIL"
    finding.severity in {{"CRITICAL", "HIGH"}}
    msg := sprintf("[%v] %v (severity=%v): %v", [
        finding.check_id, finding.title, finding.severity, finding.details,
    ])
}}

# Advisories — WARN and MEDIUM/LOW failures surfaced but not blocking by default
warn[msg] if {{
    finding := input.findings[_]
    finding.status == "WARN"
    msg := sprintf("[WARN][%v] %v: %v", [finding.check_id, finding.title, finding.details])
}}

warn[msg] if {{
    finding := input.findings[_]
    finding.status == "FAIL"
    finding.severity in {{"MEDIUM", "LOW"}}
    msg := sprintf("[%v] %v (severity=%v, non-blocking): %v", [
        finding.check_id, finding.title, finding.severity, finding.details,
    ])
}}
"""

_FEDRAMP_RULE = """\
# ---------------------------------------------------------------------------
# FedRAMP gate — all FedRAMP-mapped findings must pass
# ---------------------------------------------------------------------------

deny_fedramp[msg] if {{
    finding := input.findings[_]
    finding.status == "FAIL"
    control := finding.frameworks.FedRAMP
    msg := sprintf("[FedRAMP][%v] %v — control %v: %v", [
        finding.check_id, finding.title, control, finding.details,
    ])
}}
"""

_CMMC_RULE = """\
# ---------------------------------------------------------------------------
# CMMC 2.0 gate — all CMMC-mapped findings must pass
# ---------------------------------------------------------------------------

deny_cmmc[msg] if {{
    finding := input.findings[_]
    finding.status == "FAIL"
    practice := finding.frameworks["CMMC 2.0"]
    msg := sprintf("[CMMC][%v] %v — practice %v: %v", [
        finding.check_id, finding.title, practice, finding.details,
    ])
}}
"""

_NIST_RULE = """\
# ---------------------------------------------------------------------------
# NIST AI RMF gate — all NIST-mapped findings must pass
# ---------------------------------------------------------------------------

deny_nist_ai_rmf[msg] if {{
    finding := input.findings[_]
    finding.status == "FAIL"
    func := finding.frameworks["NIST AI RMF"]
    msg := sprintf("[NIST AI RMF][%v] %v — function %v: %v", [
        finding.check_id, finding.title, func, finding.details,
    ])
}}
"""

_SUMMARY_RULE = """\
# ---------------------------------------------------------------------------
# Summary helpers
# ---------------------------------------------------------------------------

critical_failures[id] if {{
    finding := input.findings[_]
    finding.status == "FAIL"
    finding.severity == "CRITICAL"
    id := finding.check_id
}}

all_failures[id] if {{
    finding := input.findings[_]
    finding.status == "FAIL"
    id := finding.check_id
}}

passed[id] if {{
    finding := input.findings[_]
    finding.status == "PASS"
    id := finding.check_id
}}
"""


def _per_check_rules(results: list) -> str:
    active = [r for r in results if r.status in ("FAIL", "WARN")]
    if not active:
        return "# No failures or warnings — all checks passed.\n"

    lines = [
        "# ---------------------------------------------------------------------------",
        "# Per-check rules (generated from this scan's findings)",
        "# ---------------------------------------------------------------------------",
        "",
    ]
    for r in active:
        verb = "failed" if r.status == "FAIL" else "flagged"
        block_or_warn = "deny" if r.status == "FAIL" else "warn"
        lines += [
            f"# {r.check_id}: {r.title}",
            f"{block_or_warn}[msg] if {{",
            '    finding := input.findings[_]',
            f'    finding.check_id == "{r.check_id}"',
            f'    finding.status == "{r.status}"',
            f'    msg := sprintf("{r.check_id} {verb} — %v", [finding.details])',
            "}",
            "",
        ]
    return "\n".join(lines)


def format_rego(results: list, profile: dict, target: str, mode: str) -> str:
    profile_name = profile.get("name", "default")
    pkg = profile_name.lower().replace(" ", "_").replace("-", "_")
    today = str(date.today())

    sections = [
        _HEADER.format(
            profile=profile_name, target=target, mode=mode, today=today, pkg=pkg
        ),
        _CORE_RULES,
    ]

    if "fedramp" in profile_name.lower() or profile.get("checks") == "all":
        sections.append(_FEDRAMP_RULE)
    if "cmmc" in profile_name.lower() or profile.get("checks") == "all":
        sections.append(_CMMC_RULE)
    if profile.get("checks") == "all":
        sections.append(_NIST_RULE)

    sections.append(_SUMMARY_RULE)
    sections.append(_per_check_rules(results))

    return "\n".join(sections)
