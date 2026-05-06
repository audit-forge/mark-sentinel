"""
M.A.R.K. Sentinel — DefectDojo Connector
Pushes audit findings to a DefectDojo instance via the v2 REST API.
"""
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import date
_SEVERITY_MAP = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
}

# FAIL and WARN become Active findings; PASS becomes Closed (only pushed when push_passing=True)
_ACTIVE_STATUSES = {"FAIL", "WARN"}


def push_findings(
    results: list,
    profile: dict,
    target: str,
    mode: str,
    url: str,
    api_key: str,
    product_name: str | None = None,
    engagement_name: str | None = None,
    push_passing: bool = False,
) -> dict:
    """Push M.A.R.K. Sentinel findings to a DefectDojo instance.

    Returns a summary dict with keys: product_id, engagement_id, test_id,
    pushed, skipped, errors, engagement_url.
    """
    base_url = url.rstrip("/")
    headers = {
        "Authorization": f"Token {api_key}",
        "Content-Type": "application/json",
    }

    if not product_name:
        product_name = f"M.A.R.K. Sentinel — {os.path.basename(target) or target}"
    if not engagement_name:
        engagement_name = f"{profile.get('name', 'default')} — {date.today()}"

    product_type_id = _get_or_create_product_type(base_url, headers)
    product_id = _get_or_create_product(base_url, headers, product_name, product_type_id)
    engagement_id = _create_engagement(base_url, headers, product_id, engagement_name, mode)
    test_type_id = _get_or_create_test_type(base_url, headers)
    test_id = _create_test(base_url, headers, engagement_id, test_type_id, profile, mode)

    pushed = 0
    skipped = 0
    errors = []

    for result in results:
        if result.status == "SKIP":
            skipped += 1
            continue
        if result.status == "PASS" and not push_passing:
            skipped += 1
            continue

        try:
            _create_finding(base_url, headers, test_id, result)
            pushed += 1
        except Exception as exc:
            errors.append(f"{result.check_id}: {exc}")

    return {
        "product_id": product_id,
        "engagement_id": engagement_id,
        "test_id": test_id,
        "pushed": pushed,
        "skipped": skipped,
        "errors": errors,
        "engagement_url": f"{base_url}/engagement/{engagement_id}",
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _api_get(base_url: str, headers: dict, path: str, params: dict = None) -> dict:
    url = f"{base_url}{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode())


def _api_post(base_url: str, headers: dict, path: str, body: dict) -> dict:
    url = f"{base_url}{path}"
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")
        raise RuntimeError(f"POST {path} returned {exc.code}: {detail}") from exc


def _get_or_create_product_type(base_url: str, headers: dict) -> int:
    name = "AI Security"
    data = _api_get(base_url, headers, "/api/v2/product_types/", {"name": name})
    if data.get("count", 0) > 0:
        return data["results"][0]["id"]
    result = _api_post(base_url, headers, "/api/v2/product_types/", {
        "name": name,
        "critical_product": False,
        "key_product": False,
    })
    return result["id"]


def _get_or_create_product(base_url: str, headers: dict, name: str, prod_type_id: int) -> int:
    data = _api_get(base_url, headers, "/api/v2/products/", {"name": name})
    if data.get("count", 0) > 0:
        return data["results"][0]["id"]
    result = _api_post(base_url, headers, "/api/v2/products/", {
        "name": name,
        "prod_type": prod_type_id,
        "description": "AI security findings from M.A.R.K. Sentinel (powered by Hash).",
    })
    return result["id"]


def _create_engagement(
    base_url: str, headers: dict, product_id: int, name: str, mode: str
) -> int:
    today = str(date.today())
    result = _api_post(base_url, headers, "/api/v2/engagements/", {
        "name": name,
        "product": product_id,
        "engagement_type": "CI/CD",
        "status": "Completed",
        "target_start": today,
        "target_end": today,
        "deduplication_on_engagement": False,
        "description": f"Scan mode: {mode}",
    })
    return result["id"]


def _get_or_create_test_type(base_url: str, headers: dict) -> int:
    name = "M.A.R.K. Sentinel"
    data = _api_get(base_url, headers, "/api/v2/test_types/", {"name": name})
    if data.get("count", 0) > 0:
        return data["results"][0]["id"]
    result = _api_post(base_url, headers, "/api/v2/test_types/", {
        "name": name,
        "static_tool": True,
        "active": True,
    })
    return result["id"]


def _create_test(
    base_url: str, headers: dict, engagement_id: int, test_type_id: int,
    profile: dict, mode: str
) -> int:
    today = str(date.today())
    result = _api_post(base_url, headers, "/api/v2/tests/", {
        "engagement": engagement_id,
        "test_type": test_type_id,
        "title": f"M.A.R.K. Sentinel — {profile.get('name', 'default')} ({mode})",
        "target_start": today,
        "target_end": today,
        "scan_type": "Other",
    })
    return result["id"]


def _create_finding(base_url: str, headers: dict, test_id: int, result) -> dict:
    active = result.status in _ACTIVE_STATUSES
    severity = _SEVERITY_MAP.get(result.status == "WARN" and "MEDIUM" or result.severity, "Medium")
    if result.status == "WARN" and result.severity not in _SEVERITY_MAP:
        severity = "Medium"
    else:
        severity = _SEVERITY_MAP.get(result.severity, "Medium")

    description = _build_description(result)
    mitigation = result.remediation or "See M.A.R.K. Sentinel remediation guidance."
    references = _build_references(result)
    steps = "\n".join(result.evidence) if result.evidence else "No specific evidence captured."

    tags = [result.category]
    for fw in result.frameworks:
        tags.append(fw)

    body = {
        "test": test_id,
        "title": f"[{result.check_id}] {result.title}",
        "severity": severity,
        "description": description,
        "mitigation": mitigation,
        "references": references,
        "impact": result.details,
        "steps_to_reproduce": steps,
        "active": active,
        "verified": False,
        "false_p": False,
        "duplicate": False,
        "out_of_scope": False,
        "vuln_id_from_tool": result.check_id,
        "component_name": result.category,
        "tags": tags,
    }
    return _api_post(base_url, headers, "/api/v2/findings/", body)


def _build_description(result) -> str:
    lines = [result.details]
    if result.category == "AI-GOV":
        lines.append(
            "\n**Note:** This is a governance/compliance finding, not a traditional vulnerability. "
            "It reflects a policy or documentation gap rather than a technical weakness."
        )
    lines.append(f"\n**Check ID:** {result.check_id}")
    lines.append(f"**Status:** {result.status}  |  **Severity:** {result.severity}")
    return "\n".join(lines)


def _build_references(result) -> str:
    if not result.frameworks:
        return ""
    lines = []
    for framework, control in result.frameworks.items():
        if isinstance(control, list):
            lines.append(f"- **{framework}:** {', '.join(control)}")
        else:
            lines.append(f"- **{framework}:** {control}")
    return "\n".join(lines)
