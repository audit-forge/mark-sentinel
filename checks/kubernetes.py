"""
AI-K8S checks — Kubernetes Cluster Security
Checks: AI-K8S-001 through AI-K8S-010

Live cluster checks via kubectl. Requires kubectl configured and cluster reachable.
Uses connectors.kubectl_connector.build_k8s_context() for resource data.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from . import CheckResult, PASS, FAIL, WARN, SKIP

CATEGORY = "AI-K8S"

_SECRET_ENV_PATTERNS = (
    'password', 'passwd', 'secret', 'token', 'api_key', 'apikey',
    'auth', 'credential', 'cred', 'private_key', 'access_key',
    'db_pass', 'database_pass', 'smtp_pass',
)

_SYSTEM_NAMESPACES = {'kube-system', 'kube-public', 'kube-node-lease'}
_SYSTEM_SA_PREFIXES = ('system:', 'kubeadm:', 'helm', 'rancher', 'local-path', 'traefik', 'svclb')


@dataclass
class K8sContext:
    pods:                  list[dict] = field(default_factory=list)
    services:              list[dict] = field(default_factory=list)
    namespaces:            list[str]  = field(default_factory=list)
    cluster_role_bindings: list[dict] = field(default_factory=list)
    network_policies:      list[dict] = field(default_factory=list)
    context_name:          str = ''
    server_url:            str = ''
    error:                 str = ''


def _workload_ns(pod: dict) -> str:
    return pod.get('metadata', {}).get('namespace', 'default')


def _workload_name(pod: dict) -> str:
    return pod.get('metadata', {}).get('name', 'unknown')


def _containers(pod: dict) -> list[dict]:
    spec = pod.get('spec', {})
    return spec.get('containers', []) + spec.get('initContainers', [])


def _user_namespaces(ctx: K8sContext) -> list[str]:
    return [ns for ns in ctx.namespaces if ns not in _SYSTEM_NAMESPACES]


# ── AI-K8S-001: Privileged containers ─────────────────────────────────────────

def check_k8s_001(ctx: K8sContext) -> CheckResult:
    hits: list[str] = []
    for pod in ctx.pods:
        ns = _workload_ns(pod)
        if ns in _SYSTEM_NAMESPACES:
            continue
        name = _workload_name(pod)
        for c in _containers(pod):
            sc = c.get('securityContext', {})
            if sc.get('privileged') is True:
                hits.append(f'{ns}/{name} → {c.get("name", "?")}')

    if hits:
        return CheckResult(
            check_id='AI-K8S-001',
            title='Privileged Containers Running',
            status=FAIL,
            severity='CRITICAL',
            category=CATEGORY,
            details=f'{len(hits)} container(s) running with privileged: true — full host kernel access.',
            evidence=hits[:10],
            remediation='Remove privileged: true from securityContext. Use specific capabilities instead (e.g. NET_ADMIN). '
                        'No AI workload requires full host privilege.',
            frameworks={
                'CIS K8s': '5.2.1',
                'NIST SP 800-190': 'AC-6',
                'NSA K8s Hardening': 'Container Security',
            },
        )
    return CheckResult(
        check_id='AI-K8S-001', title='No Privileged Containers',
        status=PASS, severity='CRITICAL', category=CATEGORY,
        details='No user-namespace containers are running with privileged: true.',
    )


# ── AI-K8S-002: Missing resource limits ───────────────────────────────────────

def check_k8s_002(ctx: K8sContext) -> CheckResult:
    hits: list[str] = []
    for pod in ctx.pods:
        ns = _workload_ns(pod)
        if ns in _SYSTEM_NAMESPACES:
            continue
        name = _workload_name(pod)
        for c in pod.get('spec', {}).get('containers', []):
            limits = (c.get('resources') or {}).get('limits', {})
            if not limits.get('memory') or not limits.get('cpu'):
                hits.append(f'{ns}/{name} → {c.get("name", "?")} (missing: '
                            f'{"memory " if not limits.get("memory") else ""}'
                            f'{"cpu" if not limits.get("cpu") else ""})')

    if hits:
        return CheckResult(
            check_id='AI-K8S-002',
            title='Containers Without Resource Limits',
            status=WARN,
            severity='MEDIUM',
            category=CATEGORY,
            details=f'{len(hits)} container(s) have no CPU or memory limits. '
                    'AI workloads without limits can exhaust node resources and cause cascading failures.',
            evidence=hits[:10],
            remediation='Add resources.limits.cpu and resources.limits.memory to every container spec. '
                        'For AI inference containers, set limits based on model memory footprint.',
            frameworks={
                'CIS K8s': '5.2.4',
                'NIST SP 800-190': 'SI-16',
            },
        )
    return CheckResult(
        check_id='AI-K8S-002', title='All Containers Have Resource Limits',
        status=PASS, severity='MEDIUM', category=CATEGORY,
        details='All user-namespace containers define CPU and memory limits.',
    )


# ── AI-K8S-003: Unpinned image tags ───────────────────────────────────────────

def check_k8s_003(ctx: K8sContext) -> CheckResult:
    hits: list[str] = []
    for pod in ctx.pods:
        ns = _workload_ns(pod)
        if ns in _SYSTEM_NAMESPACES:
            continue
        name = _workload_name(pod)
        for c in _containers(pod):
            image = c.get('image', '')
            tag = image.split(':')[-1] if ':' in image else 'latest'
            if tag in ('latest', 'main', 'master', 'edge', 'dev', 'nightly') or ':' not in image:
                hits.append(f'{ns}/{name} → {image}')

    if hits:
        return CheckResult(
            check_id='AI-K8S-003',
            title='Containers Using Unpinned Image Tags',
            status=WARN,
            severity='MEDIUM',
            category=CATEGORY,
            details=f'{len(hits)} container(s) use mutable image tags (latest, main, etc.). '
                    'A compromised registry or accidental update can silently replace the running AI model or service.',
            evidence=hits[:10],
            remediation='Pin all images to a specific digest or immutable tag (e.g. postgres:16.3-alpine3.19). '
                        'Use image signing (Cosign) for AI model containers.',
            frameworks={
                'CIS K8s': '5.3.1',
                'NIST AI RMF': 'GOVERN-6.2',
                'OWASP AI': 'Supply Chain Integrity',
            },
        )
    return CheckResult(
        check_id='AI-K8S-003', title='All Containers Use Pinned Image Tags',
        status=PASS, severity='MEDIUM', category=CATEGORY,
        details='No containers are using mutable image tags.',
    )


# ── AI-K8S-004: Containers running as root ────────────────────────────────────

def check_k8s_004(ctx: K8sContext) -> CheckResult:
    hits: list[str] = []
    for pod in ctx.pods:
        ns = _workload_ns(pod)
        if ns in _SYSTEM_NAMESPACES:
            continue
        name = _workload_name(pod)
        pod_sc = (pod.get('spec') or {}).get('securityContext', {})
        run_as_nonroot = pod_sc.get('runAsNonRoot', False)
        run_as_user    = pod_sc.get('runAsUser')

        for c in pod.get('spec', {}).get('containers', []):
            c_sc = c.get('securityContext', {})
            c_nonroot = c_sc.get('runAsNonRoot', run_as_nonroot)
            c_uid     = c_sc.get('runAsUser', run_as_user)
            if not c_nonroot and c_uid in (None, 0):
                hits.append(f'{ns}/{name} → {c.get("name", "?")}')

    if hits:
        return CheckResult(
            check_id='AI-K8S-004',
            title='Containers May Run as Root',
            status=FAIL,
            severity='HIGH',
            category=CATEGORY,
            details=f'{len(hits)} container(s) do not enforce non-root execution. '
                    'A container escape from an AI workload running as root gives full host access.',
            evidence=hits[:10],
            remediation='Set securityContext.runAsNonRoot: true and runAsUser: <non-zero UID> '
                        'in each container spec. Most AI serving containers support non-root operation.',
            frameworks={
                'CIS K8s': '5.2.6',
                'NIST SP 800-190': 'CM-6',
                'NSA K8s Hardening': 'Pod Security',
            },
        )
    return CheckResult(
        check_id='AI-K8S-004', title='Containers Enforce Non-Root Execution',
        status=PASS, severity='HIGH', category=CATEGORY,
        details='All user-namespace containers enforce non-root user context.',
    )


# ── AI-K8S-005: Host namespace access ────────────────────────────────────────

def check_k8s_005(ctx: K8sContext) -> CheckResult:
    hits: list[str] = []
    for pod in ctx.pods:
        ns = _workload_ns(pod)
        if ns in _SYSTEM_NAMESPACES:
            continue
        name = _workload_name(pod)
        spec = pod.get('spec', {})
        flags = []
        if spec.get('hostNetwork'):
            flags.append('hostNetwork')
        if spec.get('hostPID'):
            flags.append('hostPID')
        if spec.get('hostIPC'):
            flags.append('hostIPC')
        if flags:
            hits.append(f'{ns}/{name}: {", ".join(flags)}')

    if hits:
        return CheckResult(
            check_id='AI-K8S-005',
            title='Pods Sharing Host Namespaces',
            status=FAIL,
            severity='HIGH',
            category=CATEGORY,
            details=f'{len(hits)} pod(s) share host network, PID, or IPC namespaces. '
                    'This breaks container isolation and exposes host-level resources to AI workloads.',
            evidence=hits[:10],
            remediation='Remove hostNetwork, hostPID, and hostIPC from pod specs unless '
                        'strictly required for infrastructure components.',
            frameworks={
                'CIS K8s': '5.2.2 / 5.2.3 / 5.2.4',
                'NIST SP 800-190': 'SC-39',
            },
        )
    return CheckResult(
        check_id='AI-K8S-005', title='No Host Namespace Sharing',
        status=PASS, severity='HIGH', category=CATEGORY,
        details='No user-namespace pods share host network, PID, or IPC namespaces.',
    )


# ── AI-K8S-006: Externally exposed services ──────────────────────────────────

def check_k8s_006(ctx: K8sContext) -> CheckResult:
    hits: list[str] = []
    for svc in ctx.services:
        ns   = svc.get('metadata', {}).get('namespace', 'default')
        name = svc.get('metadata', {}).get('name', 'unknown')
        stype = svc.get('spec', {}).get('type', 'ClusterIP')
        if stype in ('NodePort', 'LoadBalancer') and ns not in _SYSTEM_NAMESPACES:
            ports = svc.get('spec', {}).get('ports', [])
            port_strs = [str(p.get('nodePort', p.get('port', '?'))) for p in ports]
            hits.append(f'{ns}/{name} ({stype}) — ports: {", ".join(port_strs)}')

    if hits:
        return CheckResult(
            check_id='AI-K8S-006',
            title='AI Services Exposed Outside Cluster',
            status=WARN,
            severity='MEDIUM',
            category=CATEGORY,
            details=f'{len(hits)} service(s) are externally reachable via NodePort or LoadBalancer. '
                    'Unauthenticated AI endpoints (Ollama, model APIs) can be discovered and abused.',
            evidence=hits[:10],
            remediation='Use ClusterIP for internal AI services. Expose externally only via an authenticated '
                        'ingress with TLS and rate limiting. Audit each NodePort to confirm it requires auth.',
            frameworks={
                'NIST AI RMF': 'GOVERN-1.4',
                'OWASP AI': 'API01 — Broken Object Level Auth',
                'CIS K8s': '5.4.1',
            },
        )
    return CheckResult(
        check_id='AI-K8S-006', title='No Unauthenticated AI Services Exposed',
        status=PASS, severity='MEDIUM', category=CATEGORY,
        details='No user-namespace services use NodePort or LoadBalancer exposure.',
    )


# ── AI-K8S-007: Secrets in plain environment variables ───────────────────────

def check_k8s_007(ctx: K8sContext) -> CheckResult:
    hits: list[str] = []
    for pod in ctx.pods:
        ns = _workload_ns(pod)
        if ns in _SYSTEM_NAMESPACES:
            continue
        name = _workload_name(pod)
        for c in _containers(pod):
            for env in c.get('env', []):
                env_name = env.get('name', '').lower()
                if any(pat in env_name for pat in _SECRET_ENV_PATTERNS):
                    if 'value' in env and 'valueFrom' not in env:
                        hits.append(f'{ns}/{name} → {c.get("name", "?")} env: {env.get("name")}')

    if hits:
        return CheckResult(
            check_id='AI-K8S-007',
            title='Credentials Passed as Plain Environment Variables',
            status=FAIL,
            severity='HIGH',
            category=CATEGORY,
            details=f'{len(hits)} container(s) pass secret-like values as plain env vars instead of '
                    'Kubernetes Secrets or a secrets manager. These appear in pod specs and logs.',
            evidence=hits[:10],
            remediation='Move credentials to Kubernetes Secrets and reference via env.valueFrom.secretKeyRef. '
                        'For AI API keys, use an external secrets manager (AWS Secrets Manager, Vault, GCP Secret Manager).',
            frameworks={
                'CIS K8s': '5.4.1',
                'NIST AI RMF': 'MANAGE-2.2',
                'OWASP Top 10': 'A02 Cryptographic Failures',
            },
        )
    return CheckResult(
        check_id='AI-K8S-007', title='No Credentials in Plain Env Vars',
        status=PASS, severity='HIGH', category=CATEGORY,
        details='No containers pass secret-like values as plain environment variables.',
    )


# ── AI-K8S-008: Missing network policies ─────────────────────────────────────

def check_k8s_008(ctx: K8sContext) -> CheckResult:
    ns_with_policy: set[str] = {
        np.get('metadata', {}).get('namespace', '') for np in ctx.network_policies
    }
    user_ns = _user_namespaces(ctx)
    unprotected = [ns for ns in user_ns if ns not in ns_with_policy]

    if unprotected:
        return CheckResult(
            check_id='AI-K8S-008',
            title='Namespaces Lack Network Policies',
            status=WARN,
            severity='MEDIUM',
            category=CATEGORY,
            details=f'{len(unprotected)} namespace(s) have no NetworkPolicy. '
                    'Any pod can reach any other pod in the cluster — including AI model APIs and databases.',
            evidence=unprotected[:10],
            remediation='Apply a default-deny NetworkPolicy to each namespace, then explicitly allow '
                        'only required traffic. AI inference services should only accept traffic from '
                        'known application pods, not the entire cluster.',
            frameworks={
                'CIS K8s': '5.3.2',
                'NIST SP 800-190': 'SC-7',
                'NSA K8s Hardening': 'Network Separation',
            },
        )
    return CheckResult(
        check_id='AI-K8S-008', title='Network Policies Configured',
        status=PASS, severity='MEDIUM', category=CATEGORY,
        details='All user namespaces have at least one NetworkPolicy.',
    )


# ── AI-K8S-009: Overprivileged RBAC (cluster-admin bindings) ─────────────────

def check_k8s_009(ctx: K8sContext) -> CheckResult:
    hits: list[str] = []
    for crb in ctx.cluster_role_bindings:
        role_ref = crb.get('roleRef', {})
        if role_ref.get('name') != 'cluster-admin':
            continue
        subjects = crb.get('subjects') or []
        for subj in subjects:
            name = subj.get('name', '')
            if not any(name.startswith(p) for p in _SYSTEM_SA_PREFIXES):
                kind = subj.get('kind', 'Unknown')
                ns   = subj.get('namespace', '')
                label = f'{kind}: {ns}/{name}' if ns else f'{kind}: {name}'
                hits.append(label)

    if hits:
        return CheckResult(
            check_id='AI-K8S-009',
            title='Non-System Accounts Bound to cluster-admin',
            status=FAIL,
            severity='CRITICAL',
            category=CATEGORY,
            details=f'{len(hits)} non-system account(s) have cluster-admin privileges. '
                    'A compromised AI workload with cluster-admin can exfiltrate all secrets and modify any resource.',
            evidence=hits[:10],
            remediation='Audit each cluster-admin binding. Remove non-essential bindings. '
                        'Use namespace-scoped Roles instead of ClusterRoles. Apply least-privilege RBAC for all AI service accounts.',
            frameworks={
                'CIS K8s': '5.1.1',
                'NIST SP 800-190': 'AC-6',
                'NSA K8s Hardening': 'RBAC',
            },
        )
    return CheckResult(
        check_id='AI-K8S-009', title='No Excess cluster-admin Bindings',
        status=PASS, severity='CRITICAL', category=CATEGORY,
        details='No non-system accounts are bound to the cluster-admin ClusterRole.',
    )


# ── AI-K8S-010: Default service account usage ────────────────────────────────

def check_k8s_010(ctx: K8sContext) -> CheckResult:
    hits: list[str] = []
    for pod in ctx.pods:
        ns = _workload_ns(pod)
        if ns in _SYSTEM_NAMESPACES:
            continue
        name  = _workload_name(pod)
        sa    = (pod.get('spec') or {}).get('serviceAccountName', 'default')
        if sa == 'default':
            hits.append(f'{ns}/{name}')

    if hits:
        return CheckResult(
            check_id='AI-K8S-010',
            title='Pods Using Default Service Account',
            status=WARN,
            severity='LOW',
            category=CATEGORY,
            details=f'{len(hits)} pod(s) use the default service account. '
                    'Default service accounts often accumulate permissions over time and have automounted tokens by default.',
            evidence=hits[:10],
            remediation='Create a dedicated service account for each workload with only required permissions. '
                        'Set automountServiceAccountToken: false if the pod does not call the Kubernetes API.',
            frameworks={
                'CIS K8s': '5.1.5',
                'NIST SP 800-190': 'AC-2',
            },
        )
    return CheckResult(
        check_id='AI-K8S-010', title='Pods Use Dedicated Service Accounts',
        status=PASS, severity='LOW', category=CATEGORY,
        details='No user-namespace pods use the default service account.',
    )


# ── Entry point ────────────────────────────────────────────────────────────────

_CHECKS = [
    check_k8s_001,
    check_k8s_002,
    check_k8s_003,
    check_k8s_004,
    check_k8s_005,
    check_k8s_006,
    check_k8s_007,
    check_k8s_008,
    check_k8s_009,
    check_k8s_010,
]


def run_all(ctx: K8sContext) -> list[CheckResult]:
    results = []
    for fn in _CHECKS:
        try:
            results.append(fn(ctx))
        except Exception as exc:
            results.append(CheckResult(
                check_id=fn.__name__.replace('check_', 'AI-').upper(),
                title=f'Check error: {fn.__name__}',
                status=SKIP,
                severity='LOW',
                category=CATEGORY,
                details=f'Check raised an exception: {exc}',
            ))
    return results
