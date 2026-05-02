"""
kubectl_connector.py

A minimal, fixture-friendly kubectl connector. It provides helpers to parse
Kubernetes manifest files and to produce a simple scan result suitable for
unit tests and for the compliance formatter.

Functions:
- parse_k8s_manifest(path) -> list of resource dicts
- scan_manifest_for_ai_components(path) -> dict with findings

No external kubernetes client is required; this works from YAML manifests.
"""
from typing import Any


def _load_yaml_multi(path: str) -> list[dict[str, Any]]:
    try:
        import yaml
    except Exception:
        yaml = None
    text = open(path, "r", encoding="utf-8").read()
    if yaml:
        docs = list(yaml.safe_load_all(text))
        return [d for d in docs if d]
    # very small fallback: split on "---" and look for "kind:" and "metadata:"
    docs = []
    parts = text.split('\n---\n')
    for part in parts:
        doc = {}
        lines = part.splitlines()
        for raw in lines:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("kind:"):
                doc["kind"] = line.split(":", 1)[1].strip()
            elif line.startswith("metadata:"):
                # attempt to capture name next line
                pass
            elif line.startswith("name:"):
                doc.setdefault("metadata", {})["name"] = line.split(":", 1)[1].strip()
        if doc:
            docs.append(doc)
    return docs


def parse_k8s_manifest(manifest_path: str) -> list[dict[str, Any]]:
    """Return a list of parsed k8s resources from a manifest file."""
    return _load_yaml_multi(manifest_path)


def scan_manifest_for_ai_components(manifest_path: str) -> dict[str, Any]:
    """Look for common AI service patterns (Deployments, Pods with images that look like 'ai' or 'model')

    Returns a dict: {resources: [...], findings: [...]}
    """
    resources = parse_k8s_manifest(manifest_path)
    findings = []
    for r in resources:
        kind = r.get("kind", "")
        name = (r.get("metadata") or {}).get("name") or r.get("metadata_name") or "unknown"
        if kind.lower() in ("deployment", "pod", "statefulset"):
            # naive heuristic: name or image contains 'ai' or 'model' or 'inference'
            name_l = name.lower()
            if any(tok in name_l for tok in ("ai", "model", "inference")):
                findings.append({
                    "id": "AI-DEPLOY-004",
                    "title": "Potential public AI endpoint / deployment",
                    "result": "WARN",
                    "severity": "medium",
                    "description": f"Kubernetes resource {kind}/{name} may expose an AI endpoint.",
                    "remediation": "Review service exposure (ClusterIP vs LoadBalancer) and restrict to private networks; add authentication."
                })
    return {"resources": resources, "findings": findings}


if __name__ == "__main__":
    import argparse, json
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest")
    parser.add_argument("--out")
    args = parser.parse_args()
    res = scan_manifest_for_ai_components(args.manifest)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(res, fh, indent=2)
    else:
        print(res)
