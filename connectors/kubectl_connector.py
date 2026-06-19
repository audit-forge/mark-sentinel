"""
kubectl_connector.py

Kubernetes connector for Sentinel. Provides both:
- Static manifest parsing (original capability, unchanged)
- Live cluster querying via kubectl CLI (new)

No Python kubernetes client required — uses kubectl subprocess calls.
"""
from __future__ import annotations
import json
import subprocess
from typing import Any


# ── Static manifest helpers (original, unchanged) ─────────────────────────────

def _load_yaml_multi(path: str) -> list[dict[str, Any]]:
    try:
        import yaml
    except Exception:
        yaml = None
    text = open(path, "r", encoding="utf-8").read()
    if yaml:
        docs = list(yaml.safe_load_all(text))
        return [d for d in docs if d]
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
            elif line.startswith("name:"):
                doc.setdefault("metadata", {})["name"] = line.split(":", 1)[1].strip()
        if doc:
            docs.append(doc)
    return docs


def parse_k8s_manifest(manifest_path: str) -> list[dict[str, Any]]:
    """Return a list of parsed k8s resources from a manifest file."""
    return _load_yaml_multi(manifest_path)


def scan_manifest_for_ai_components(manifest_path: str) -> dict[str, Any]:
    """Look for AI service patterns in a manifest file."""
    resources = parse_k8s_manifest(manifest_path)
    findings = []
    for r in resources:
        kind = r.get("kind", "")
        name = (r.get("metadata") or {}).get("name") or r.get("metadata_name") or "unknown"
        if kind.lower() in ("deployment", "pod", "statefulset"):
            name_l = name.lower()
            if any(tok in name_l for tok in ("ai", "model", "inference")):
                findings.append({
                    "id": "AI-DEPLOY-004",
                    "title": "Potential public AI endpoint / deployment",
                    "result": "WARN",
                    "severity": "medium",
                    "description": f"Kubernetes resource {kind}/{name} may expose an AI endpoint.",
                    "remediation": "Review service exposure and restrict to private networks; add authentication."
                })
    return {"resources": resources, "findings": findings}


# ── Live cluster helpers ───────────────────────────────────────────────────────

def _kubectl_json(args: list[str], timeout: int = 15) -> dict | None:
    """Run kubectl with -o json, return parsed dict or None on any error."""
    try:
        r = subprocess.run(
            ['kubectl'] + args + ['-o', 'json'],
            capture_output=True, text=True, timeout=timeout,
        )
        if r.returncode != 0:
            return None
        return json.loads(r.stdout)
    except Exception:
        return None


def cluster_reachable(timeout: int = 5) -> bool:
    """Return True if kubectl can reach the currently configured cluster."""
    try:
        r = subprocess.run(
            ['kubectl', 'cluster-info'],
            capture_output=True, timeout=timeout,
        )
        return r.returncode == 0
    except Exception:
        return False


def current_context() -> str:
    """Return the active kubectl context name, or empty string."""
    try:
        r = subprocess.run(
            ['kubectl', 'config', 'current-context'],
            capture_output=True, text=True, timeout=5,
        )
        return r.stdout.strip() if r.returncode == 0 else ''
    except Exception:
        return ''


def cluster_server_url() -> str:
    """Return the API server URL for the current cluster."""
    try:
        r = subprocess.run(
            ['kubectl', 'config', 'view', '--minify',
             '-o', 'jsonpath={.clusters[0].cluster.server}'],
            capture_output=True, text=True, timeout=5,
        )
        return r.stdout.strip() if r.returncode == 0 else ''
    except Exception:
        return ''


def build_k8s_context():
    """
    Query the live cluster and return a K8sContext populated with resource data.
    Returns None if the cluster is unreachable.
    """
    from checks.kubernetes import K8sContext

    if not cluster_reachable():
        return None

    ctx = K8sContext()
    ctx.context_name = current_context()
    ctx.server_url   = cluster_server_url()

    pods = _kubectl_json(['get', 'pods', '--all-namespaces'])
    if pods:
        ctx.pods = pods.get('items', [])

    svcs = _kubectl_json(['get', 'services', '--all-namespaces'])
    if svcs:
        ctx.services = svcs.get('items', [])

    ns = _kubectl_json(['get', 'namespaces'])
    if ns:
        ctx.namespaces = [n['metadata']['name'] for n in ns.get('items', [])]

    crbs = _kubectl_json(['get', 'clusterrolebindings'])
    if crbs:
        ctx.cluster_role_bindings = crbs.get('items', [])

    nps = _kubectl_json(['get', 'networkpolicies', '--all-namespaces'])
    if nps:
        ctx.network_policies = nps.get('items', [])

    return ctx


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", nargs='?')
    parser.add_argument("--live", action="store_true")
    args = parser.parse_args()
    if args.live:
        ctx = build_k8s_context()
        print(json.dumps({'pods': len(ctx.pods if ctx else []),
                          'services': len(ctx.services if ctx else []),
                          'context': ctx.context_name if ctx else 'unreachable'}, indent=2))
    elif args.manifest:
        print(json.dumps(scan_manifest_for_ai_components(args.manifest), indent=2))
