"""
M.A.R.K. Sentinel — JSON output formatter
Produces structured JSON audit report.
"""
import json
from datetime import date
from checks import CheckResult


def format_json(results: list, profile: dict, target: str, mode: str) -> str:
    active = [r for r in results if r.status != "SKIP"]
    skipped = [r for r in results if r.status == "SKIP"]

    summary = {
        "total_evaluated": len(active),
        "pass": sum(1 for r in active if r.status == "PASS"),
        "warn": sum(1 for r in active if r.status == "WARN"),
        "fail": sum(1 for r in active if r.status == "FAIL"),
        "skip": len(skipped),
        "has_critical_fail": any(r.status == "FAIL" and r.severity == "CRITICAL" for r in results),
    }

    findings = [_result_to_dict(r) for r in results]

    report = {
        "mark_sentinel_version": "1.0.0-phase1",
        "scan_date": str(date.today()),
        "target": target,
        "mode": mode,
        "profile": profile.get("name", "default"),
        "summary": summary,
        "findings": findings,
    }

    return json.dumps(report, indent=2)


def _result_to_dict(r: CheckResult) -> dict:
    return {
        "check_id": r.check_id,
        "title": r.title,
        "status": r.status,
        "severity": r.severity,
        "category": r.category,
        "details": r.details,
        "evidence": r.evidence,
        "remediation": r.remediation,
        "frameworks": r.frameworks,
    }
