"""
docker_connector.py

Simple, test-friendly docker connector. Two main functions:
- parse_docker_compose(path) -> dict of services
- scan_container_by_compose(path, service_name) -> a lightweight result dict

This module tries to use PyYAML if available, otherwise falls back to a
minimal parser that will not support advanced YAML features. The intention is
for unit tests / fixture-driven validation using the provided docker-compose
fixtures in test/fixtures.
"""
from typing import Any


def _load_yaml(path: str) -> dict[str, Any] | None:
    try:
        import yaml
    except Exception:
        yaml = None
    if yaml:
        with open(path, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh)
    # fallback: very small parser that looks for 'services:' and then top-level keys
    data = {}
    with open(path, "r", encoding="utf-8") as fh:
        lines = fh.readlines()
    in_services = False
    current = None
    for raw in lines:
        line = raw.rstrip('\n')
        stripped = line.lstrip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("services:"):
            in_services = True
            continue
        if in_services:
            # detect top-level service (no leading spaces)
            if not line.startswith(" ") and not line.startswith("\t") and stripped.endswith(":"):
                current = stripped[:-1]
                data.setdefault("services", {})[current] = {}
            elif current and ":" in stripped:
                k, v = stripped.split(":", 1)
                data["services"][current][k.strip()] = v.strip()
    return data


def parse_docker_compose(compose_path: str) -> dict[str, Any]:
    """Return the parsed docker-compose content (services dict)

    This intentionally returns a simplified representation suitable for the
    audit engine and unit tests (service names, image, ports, environment).
    """
    doc = _load_yaml(compose_path) or {}
    services = doc.get("services") or {}
    parsed = {}
    for name, spec in services.items():
        if not isinstance(spec, dict):
            # spec may be a simple string in the fallback parser
            parsed[name] = {"raw": spec}
            continue
        parsed[name] = {
            "image": spec.get("image") or spec.get("build"),
            "ports": spec.get("ports") or [],
            "environment": spec.get("environment") or {},
            "labels": spec.get("labels") or {},
        }
    return parsed


def scan_container_by_compose(compose_path: str, service_name: str) -> dict[str, Any]:
    """Lightweight scan that inspects the compose service and returns findings.
    Returns a dict with service, findings (list), and metadata.
    """
    services = parse_docker_compose(compose_path)
    service = services.get(service_name)
    if not service:
        return {"service": service_name, "status": "NOT_FOUND", "findings": []}

    findings = []
    image = service.get("image")
    if not image:
        findings.append({
            "id": "AI-DEPLOY-002",
            "title": "No image specified / build-only service",
            "result": "WARN",
            "severity": "low",
            "description": "Service does not pin an image; builds from local source may vary.",
            "remediation": "Pin explicit image versions or include provenance metadata.",
        })
    raw_env = service.get("environment") or {}
    if isinstance(raw_env, list):
        env = {}
        for item in raw_env:
            if isinstance(item, str) and '=' in item:
                k, _, v = item.partition('=')
                env[k] = v
    else:
        env = raw_env
    for k, v in env.items():
        if isinstance(v, str) and ("KEY" in k.upper() or "SECRET" in k.upper()):
            findings.append({
                "id": "AI-DEPLOY-001",
                "title": "Potential API key in environment",
                "result": "FAIL",
                "severity": "high",
                "description": f"Environment variable {k} looks like a key/secret.",
                "remediation": "Move secrets into a secrets manager and do not store them in plain env files.",
            })
    return {"service": service_name, "status": "FOUND", "findings": findings, "meta": service}


if __name__ == "__main__":
    import argparse
    import json
    parser = argparse.ArgumentParser()
    parser.add_argument("compose", help="path to docker-compose.yml")
    parser.add_argument("service", help="service name")
    parser.add_argument("--out", help="write JSON output to path")
    args = parser.parse_args()
    res = scan_container_by_compose(args.compose, args.service)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(res, fh, indent=2)
    else:
        print(res)
