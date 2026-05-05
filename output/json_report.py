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

    critical_fails = [r for r in active if r.status == "FAIL" and r.severity == "CRITICAL"]
    summary = {
        "total_evaluated": len(active),
        "pass": sum(1 for r in active if r.status == "PASS"),
        "warn": sum(1 for r in active if r.status == "WARN"),
        "fail": sum(1 for r in active if r.status == "FAIL"),
        "skip": len(skipped),
        "has_critical_fail": len(critical_fails) > 0,
        "critical_count": len(critical_fails),
    }

    report = {
        "mark_sentinel_version": "1.0.0-phase1",
        "scan_date": str(date.today()),
        "target": target,
        "mode": mode,
        "profile": profile.get("name", "default"),
        "profile_framework": profile.get("framework_emphasis"),
        "profile_description": profile.get("description"),
        "summary": summary,
        "findings": [_result_to_dict(r, profile) for r in results],
    }

    return json.dumps(report, indent=2)


def _result_to_dict(r: CheckResult, profile: dict) -> dict:
    d = {
        "check_id": r.check_id,
        "title": r.title,
        "status": r.status,
        "severity": r.severity,
        "category": r.category,
        "details": r.details,
        "evidence": r.evidence,
        "remediation": r.remediation if profile.get("include_remediation", True) else "",
        "frameworks": r.frameworks if profile.get("include_frameworks", True) else {},
    }
    controls = profile.get("_controls", {}).get(r.check_id)
    if controls:
        d["emphasis_controls"] = controls
    return d
