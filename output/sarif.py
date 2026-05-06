"""
M.A.R.K. Sentinel — SARIF 2.1.0 output formatter
Compatible with GitHub Advanced Security, Wiz, Azure Defender, and any SARIF-consuming tool.
"""
import json
from datetime import date
from checks import CheckResult

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)

_LEVEL = {"PASS": "note", "FAIL": "error", "WARN": "warning", "SKIP": "none"}
_SEV_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}

_CATEGORY_DOC = {
    "AI-DEPLOY": "AI-DEPLOY.md",
    "AI-INP": "AI-INP.md",
    "AI-OUT": "AI-OUT.md",
    "AI-AGENT": "AI-AGENT.md",
    "AI-SUPPLY": "AI-SUPPLY.md",
    "AI-GOV": "AI-GOV.md",
}

_REPO_BASE = "https://github.com/audit-forge/mark-sentinel/blob/main/checks"


def format_sarif(results: list, profile: dict, target: str, mode: str) -> str:
    # Deduplicate rules (one per check_id)
    seen = set()
    rules = []
    for r in results:
        if r.check_id not in seen:
            rules.append(_make_rule(r))
            seen.add(r.check_id)

    run = {
        "tool": {
            "driver": {
                "name": "M.A.R.K. Sentinel",
                "version": "1.0.0-phase1",
                "informationUri": "https://github.com/audit-forge/mark-sentinel",
                "rules": rules,
            }
        },
        "invocations": [
            {
                "executionSuccessful": True,
                "commandLine": (
                    f"audit.py --mode {mode} --target {target} "
                    f"--profile {profile.get('name', 'default')} --output sarif"
                ),
            }
        ],
        "artifacts": [
            {
                "location": {"uri": target},
                "description": {"text": "Scanned directory"},
            }
        ],
        "results": [_make_result(r, target) for r in results],
        "properties": {
            "scanDate": str(date.today()),
            "target": target,
            "mode": mode,
            "profile": profile.get("name", "default"),
            "summary": {
                "pass": sum(1 for r in results if r.status == "PASS"),
                "fail": sum(1 for r in results if r.status == "FAIL"),
                "warn": sum(1 for r in results if r.status == "WARN"),
                "skip": sum(1 for r in results if r.status == "SKIP"),
            },
        },
    }

    report = {"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}
    return json.dumps(report, indent=2)


def _make_rule(r: CheckResult) -> dict:
    doc_file = _CATEGORY_DOC.get(r.category, "README.md")
    return {
        "id": r.check_id,
        "name": _pascal(r.title),
        "shortDescription": {"text": r.title},
        "fullDescription": {"text": r.details},
        "helpUri": f"{_REPO_BASE}/{doc_file}#{r.check_id.lower()}",
        "defaultConfiguration": {"level": _SEV_LEVEL.get(r.severity.upper(), "note")},
        "properties": {
            "severity": r.severity,
            "category": r.category,
            "frameworks": r.frameworks,
            "tags": ["security", "ai-security", r.category.lower()],
        },
    }


def _make_result(r: CheckResult, target: str) -> dict:
    msg_parts = [r.details or ""]
    if r.evidence:
        msg_parts.append("\nEvidence:")
        msg_parts.extend(f"  • {e}" for e in r.evidence)
    if r.remediation and r.status in ("FAIL", "WARN"):
        msg_parts.append(f"\nRemediation:\n{r.remediation}")

    result = {
        "ruleId": r.check_id,
        "level": _LEVEL.get(r.status, "none"),
        "message": {"text": "\n".join(msg_parts)},
        "locations": [
            {
                "logicalLocations": [
                    {
                        "name": target,
                        "kind": "module",
                        "fullyQualifiedName": target,
                    }
                ]
            }
        ],
        "properties": {
            "status": r.status,
            "severity": r.severity,
            "category": r.category,
            "evidence": r.evidence,
            "frameworks": r.frameworks,
        },
    }

    # If evidence contains a file:line reference, add a physical location
    for ev in r.evidence:
        loc = _parse_file_loc(ev, target)
        if loc:
            result["locations"][0]["physicalLocation"] = loc
            break

    return result


def _parse_file_loc(evidence: str, target: str) -> dict | None:
    """Try to extract file:line from an evidence string like 'config.json:14 — ...'"""
    import re
    m = re.match(r'^([^\s:]+\.[a-z]+):(\d+)', evidence)
    if m:
        return {
            "artifactLocation": {
                "uri": m.group(1),
                "uriBaseId": "%SRCROOT%",
            },
            "region": {"startLine": int(m.group(2))},
        }
    return None


def _pascal(title: str) -> str:
    return "".join(w.capitalize() for w in title.replace("/", " ").split())
