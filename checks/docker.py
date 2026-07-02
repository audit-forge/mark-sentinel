"""
AI-DOCKER checks — Docker Host & Container Security
Checks: AI-DOCKER-001 through AI-DOCKER-010

Operates on live Docker daemon data via docker inspect.
No Python Docker SDK required — uses docker CLI via subprocess.
"""
from __future__ import annotations
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from . import CheckResult, PASS, FAIL, WARN, SKIP

CATEGORY = "AI-DOCKER"

_SECRET_KEY_RE = re.compile(
    r'(?i)^(.*?(?:key|secret|password|token|api[_-]?key|access[_-]?key|'
    r'private[_-]?key|auth|credential|passwd)[s]?)=(.+)$'
)
_PLACEHOLDER_RE = re.compile(
    r'(?i)(^$|xxx|placeholder|changeme|replace|your[_-]|example|'
    r'^test$|demo|fake|dummy|^none$|^empty$|^\*+$|^<.+>$)'
)
_DANGEROUS_CAPS = frozenset({
    'SYS_ADMIN', 'NET_ADMIN', 'ALL', 'SYS_PTRACE', 'SYS_MODULE',
    'DAC_OVERRIDE', 'SETUID', 'SETGID', 'SYS_RAWIO', 'SYS_CHROOT',
})


@dataclass
class DockerContext:
    daemon_version: str
    containers: list[dict] = field(default_factory=list)
    docker_bin: str = 'docker'


def build_docker_context(docker_bin: str = 'docker') -> DockerContext | None:
    """Query live Docker daemon and return a DockerContext. Returns None if daemon unreachable."""
    env = _docker_env()
    try:
        r = subprocess.run(
            [docker_bin, 'version', '--format', '{{.Server.Version}}'],
            capture_output=True, text=True, timeout=8, env=env,
        )
        if r.returncode != 0 or not r.stdout.strip():
            return None
        daemon_version = r.stdout.strip()
    except Exception:
        return None

    try:
        r = subprocess.run(
            [docker_bin, 'ps', '-q'],
            capture_output=True, text=True, timeout=8, env=env,
        )
        ids = [i for i in r.stdout.strip().splitlines() if i]
    except Exception:
        ids = []

    containers: list[dict] = []
    if ids:
        try:
            r = subprocess.run(
                [docker_bin, 'inspect'] + ids,
                capture_output=True, text=True, timeout=30, env=env,
            )
            if r.returncode == 0 and r.stdout.strip():
                containers = json.loads(r.stdout)
        except Exception:
            pass

    return DockerContext(daemon_version=daemon_version, containers=containers, docker_bin=docker_bin)


def _docker_env() -> dict:
    """Return env with Docker socket path set for macOS Docker Desktop running as root."""
    import os
    from pathlib import Path
    env = os.environ.copy()
    if sys.platform == 'darwin' and os.geteuid() == 0:
        for home in Path('/Users').iterdir():
            sock = home / '.docker' / 'run' / 'docker.sock'
            if sock.exists():
                env['DOCKER_HOST'] = f'unix://{sock}'
                break
    return env


def _cname(c: dict) -> str:
    return c.get('Name', '').lstrip('/') or c.get('Id', '')[:12]


def _is_real_secret(val: str) -> bool:
    if not val or len(val.strip()) < 8:
        return False
    if _PLACEHOLDER_RE.search(val.strip()):
        return False
    if val.startswith('$') or val.startswith('#{'):
        return False
    return True


# ── Checks ─────────────────────────────────────────────────────────────────────

def check_docker_001(ctx: DockerContext) -> CheckResult:
    """AI-DOCKER-001 — Privileged containers."""
    privileged = [_cname(c) for c in ctx.containers
                  if c.get('HostConfig', {}).get('Privileged')]
    if privileged:
        return CheckResult(
            check_id='AI-DOCKER-001',
            title='Privileged Container Detected',
            status=FAIL,
            severity='CRITICAL',
            category=CATEGORY,
            details=(
                f"{len(privileged)} container(s) running with --privileged. "
                "Privileged containers have full host kernel access and bypass all container isolation — "
                "a compromised AI process inside can take over the host."
            ),
            evidence=[f"Privileged: {n}" for n in privileged],
            remediation=(
                "1. Remove --privileged from docker run command or compose file.\n"
                "2. Use specific --cap-add capabilities instead: e.g. --cap-add NET_BIND_SERVICE.\n"
                "3. For AI GPU workloads: use --gpus flag or --device /dev/nvidia0 — not --privileged.\n"
                "4. Apply a seccomp profile: --security-opt seccomp=/etc/docker/seccomp.json"
            ),
            frameworks={
                'CIS Docker Benchmark': '5.4',
                'NIST SP 800-190': '4.3.3',
                'MITRE ATT&CK': 'T1611 — Escape to Host',
                'ISO 42001': '8.4 AI system lifecycle',
            },
        )
    return CheckResult(
        check_id='AI-DOCKER-001',
        title='No Privileged Containers',
        status=PASS,
        severity='CRITICAL',
        category=CATEGORY,
        details=f"No containers running with --privileged. ({len(ctx.containers)} checked)",
        evidence=[],
        frameworks={'CIS Docker Benchmark': '5.4', 'NIST SP 800-190': '4.3.3'},
    )


def check_docker_002(ctx: DockerContext) -> CheckResult:
    """AI-DOCKER-002 — Containers running as root (UID 0)."""
    if not ctx.containers:
        return CheckResult(
            check_id='AI-DOCKER-002', title='Container Root User Check',
            status=PASS, severity='HIGH', category=CATEGORY,
            details='No running containers to evaluate.', evidence=[],
            frameworks={'CIS Docker Benchmark': '5.1'},
        )
    root_containers = []
    for c in ctx.containers:
        user = c.get('Config', {}).get('User', '') or ''
        if not user or user.split(':')[0] in ('0', 'root'):
            root_containers.append(_cname(c))
    if root_containers:
        return CheckResult(
            check_id='AI-DOCKER-002',
            title='Containers Running as Root',
            status=WARN,
            severity='HIGH',
            category=CATEGORY,
            details=(
                f"{len(root_containers)} container(s) running as root (UID 0). "
                "If an attacker achieves code execution inside the container, they have root on the host namespace."
            ),
            evidence=[f"Root user: {n}" for n in root_containers],
            remediation=(
                "1. Add USER directive to Dockerfile: USER 1000:1000\n"
                "2. For compose: services.<name>.user: '1000:1000'\n"
                "3. For Ollama: runs as non-root when started with a user directive; set model dir permissions accordingly.\n"
                "4. Ensure non-root user has read access to model files and write access to cache/output dirs only."
            ),
            frameworks={
                'CIS Docker Benchmark': '5.1',
                'NIST SP 800-190': '4.3.2',
                'OWASP LLM': 'LLM07',
            },
        )
    return CheckResult(
        check_id='AI-DOCKER-002',
        title='Containers Running as Non-Root Users',
        status=PASS,
        severity='HIGH',
        category=CATEGORY,
        details=f"All containers specify a non-root user. ({len(ctx.containers)} checked)",
        evidence=[],
        frameworks={'CIS Docker Benchmark': '5.1', 'NIST SP 800-190': '4.3.2'},
    )


def check_docker_003(ctx: DockerContext) -> CheckResult:
    """AI-DOCKER-003 — Docker socket bind-mounted into containers."""
    socket_mounts = []
    for c in ctx.containers:
        for mount in c.get('Mounts', []):
            if 'docker.sock' in mount.get('Source', ''):
                socket_mounts.append(f"{_cname(c)}: {mount['Source']}")
    if socket_mounts:
        return CheckResult(
            check_id='AI-DOCKER-003',
            title='Docker Socket Mounted Inside Container',
            status=FAIL,
            severity='CRITICAL',
            category=CATEGORY,
            details=(
                f"{len(socket_mounts)} container(s) have the Docker socket mounted. "
                "This grants the container full control over the Docker daemon — "
                "equivalent to unrestricted root access to the host."
            ),
            evidence=socket_mounts,
            remediation=(
                "1. Remove the /var/run/docker.sock volume mount unless absolutely required.\n"
                "2. If CI/CD tooling needs Docker access: use Docker socket proxy (tecnativa/docker-socket-proxy) "
                "   to allow read-only access only.\n"
                "3. For AI build pipelines: use Kaniko or BuildKit in sandboxed mode instead.\n"
                "4. Audit regularly: docker ps --format '{{.Names}}' | xargs -I{} docker inspect {} | grep docker.sock"
            ),
            frameworks={
                'CIS Docker Benchmark': '5.31',
                'NIST SP 800-190': '4.3.3',
                'MITRE ATT&CK': 'T1611 — Escape to Host',
                'MITRE ATLAS': 'AML.T0025 — Exfiltration via Cyber Means',
            },
        )
    return CheckResult(
        check_id='AI-DOCKER-003',
        title='Docker Socket Not Exposed to Containers',
        status=PASS,
        severity='CRITICAL',
        category=CATEGORY,
        details=f"No containers have the Docker socket bind-mounted. ({len(ctx.containers)} checked)",
        evidence=[],
        frameworks={'CIS Docker Benchmark': '5.31', 'NIST SP 800-190': '4.3.3'},
    )


def check_docker_004(ctx: DockerContext) -> CheckResult:
    """AI-DOCKER-004 — Host network mode."""
    host_net = [_cname(c) for c in ctx.containers
                if c.get('HostConfig', {}).get('NetworkMode') == 'host']
    if host_net:
        return CheckResult(
            check_id='AI-DOCKER-004',
            title='Containers Using Host Network Mode',
            status=WARN,
            severity='HIGH',
            category=CATEGORY,
            details=(
                f"{len(host_net)} container(s) using --network=host. "
                "Host network mode removes Docker network isolation — the container shares the host network stack "
                "and can sniff or inject traffic on all interfaces."
            ),
            evidence=[f"Host network: {n}" for n in host_net],
            remediation=(
                "1. Remove --network=host; let Docker assign a bridge network.\n"
                "2. Publish only required ports explicitly: -p 127.0.0.1:11434:11434\n"
                "3. Create isolated networks for AI services: docker network create --internal ai-net\n"
                "4. Host networking is rarely required — typically only for network monitoring tools."
            ),
            frameworks={
                'CIS Docker Benchmark': '5.14',
                'NIST SP 800-190': '4.3.1',
            },
        )
    return CheckResult(
        check_id='AI-DOCKER-004',
        title='No Containers Using Host Network Mode',
        status=PASS,
        severity='HIGH',
        category=CATEGORY,
        details=f"All containers use isolated Docker networking. ({len(ctx.containers)} checked)",
        evidence=[],
        frameworks={'CIS Docker Benchmark': '5.14', 'NIST SP 800-190': '4.3.1'},
    )


def check_docker_005(ctx: DockerContext) -> CheckResult:
    """AI-DOCKER-005 — Unpinned image tags (:latest or no digest)."""
    unpinned = []
    for c in ctx.containers:
        img = c.get('Config', {}).get('Image', '')
        if not img:
            unpinned.append(f"{_cname(c)}: (no image tag)")
        elif img.endswith(':latest') or ':' not in img:
            unpinned.append(f"{_cname(c)}: {img}")
    if unpinned:
        return CheckResult(
            check_id='AI-DOCKER-005',
            title='Containers Using Unpinned Image Tags',
            status=WARN,
            severity='MEDIUM',
            category=CATEGORY,
            details=(
                f"{len(unpinned)} container(s) using :latest or untagged images. "
                ":latest is mutable — a supply chain compromise or accidental registry push "
                "can silently replace the image on the next pull."
            ),
            evidence=unpinned,
            remediation=(
                "1. Pin to specific versions: ollama/ollama:0.3.14 not ollama/ollama:latest.\n"
                "2. Use image digest pinning for production: image@sha256:<digest>.\n"
                "3. Enable Docker Content Trust to verify image signatures: export DOCKER_CONTENT_TRUST=1\n"
                "4. Add image scanning to your deploy pipeline: trivy image <image>:<tag>"
            ),
            frameworks={
                'CIS Docker Benchmark': '6.2',
                'NIST SP 800-190': '4.2.2',
                'MITRE ATLAS': 'AML.T0017 — ML Supply Chain Compromise',
                'ISO 42001': '8.4 AI system lifecycle',
            },
        )
    return CheckResult(
        check_id='AI-DOCKER-005',
        title='Container Images Pinned to Specific Versions',
        status=PASS,
        severity='MEDIUM',
        category=CATEGORY,
        details=f"All containers use versioned image tags (not :latest). ({len(ctx.containers)} checked)",
        evidence=[],
        frameworks={'CIS Docker Benchmark': '6.2', 'NIST SP 800-190': '4.2.2'},
    )


def check_docker_006(ctx: DockerContext) -> CheckResult:
    """AI-DOCKER-006 — Secrets in container environment variables."""
    secret_hits: list[str] = []
    for c in ctx.containers:
        name = _cname(c)
        for env_str in (c.get('Config', {}).get('Env') or []):
            if '=' not in env_str:
                continue
            key, _, val = env_str.partition('=')
            if _SECRET_KEY_RE.match(env_str) and _is_real_secret(val):
                masked = f"{key}={val[:4]}***" if len(val) > 4 else f"{key}=***"
                secret_hits.append(f"{name}: {masked}")
    if secret_hits:
        return CheckResult(
            check_id='AI-DOCKER-006',
            title='Secrets Found in Container Environment Variables',
            status=FAIL,
            severity='HIGH',
            category=CATEGORY,
            details=(
                f"{len(secret_hits)} potential secret(s) in container environment variables. "
                "Env vars are visible via 'docker inspect', process listings (/proc), and application logs — "
                "they provide no actual confidentiality."
            ),
            evidence=secret_hits[:8],
            remediation=(
                "1. Use Docker Secrets (Swarm) or a secrets manager — mount at /run/secrets/<name>.\n"
                "2. For compose: use the secrets: block, not plain environment: values.\n"
                "3. For AI API keys: load from AWS Secrets Manager, HashiCorp Vault, or GCP Secret Manager at runtime.\n"
                "4. Rotate any exposed keys immediately at the provider dashboard."
            ),
            frameworks={
                'CIS Docker Benchmark': '5.25',
                'NIST SP 800-190': '4.3.2',
                'OWASP LLM': 'LLM07 — Insecure Plugin Design',
                'MITRE ATLAS': 'AML.T0024 — Exfiltration via ML Inference API',
            },
        )
    return CheckResult(
        check_id='AI-DOCKER-006',
        title='No Secrets Detected in Container Environment',
        status=PASS,
        severity='HIGH',
        category=CATEGORY,
        details=f"No AI API keys or plaintext secrets found in container environment variables. ({len(ctx.containers)} checked)",
        evidence=[],
        frameworks={'CIS Docker Benchmark': '5.25', 'NIST SP 800-190': '4.3.2'},
    )


def check_docker_007(ctx: DockerContext) -> CheckResult:
    """AI-DOCKER-007 — Writable root filesystem."""
    if not ctx.containers:
        return CheckResult(
            check_id='AI-DOCKER-007', title='Read-Only Root Filesystem',
            status=PASS, severity='MEDIUM', category=CATEGORY,
            details='No running containers to evaluate.', evidence=[],
            frameworks={'CIS Docker Benchmark': '5.12'},
        )
    writable = [_cname(c) for c in ctx.containers
                if not c.get('HostConfig', {}).get('ReadonlyRootfs', False)]
    if writable:
        return CheckResult(
            check_id='AI-DOCKER-007',
            title='Containers Have Writable Root Filesystems',
            status=WARN,
            severity='MEDIUM',
            category=CATEGORY,
            details=(
                f"{len(writable)} container(s) have writable root filesystems. "
                "An attacker with code execution inside the container can install tools, modify binaries, "
                "and establish persistence within the container layer."
            ),
            evidence=[f"Writable root: {n}" for n in writable],
            remediation=(
                "1. Add --read-only flag: docker run --read-only --tmpfs /tmp <image>\n"
                "2. For compose: read_only: true — then add tmpfs: ['/tmp'] for temp writes.\n"
                "3. For AI model servers (Ollama, vLLM): mount model dir read-only; use a named volume for cache only.\n"
                "4. Test first: docker run --read-only --tmpfs /tmp <image> — most apps need only /tmp writable."
            ),
            frameworks={
                'CIS Docker Benchmark': '5.12',
                'NIST SP 800-190': '4.3.2',
            },
        )
    return CheckResult(
        check_id='AI-DOCKER-007',
        title='Containers Use Read-Only Root Filesystems',
        status=PASS,
        severity='MEDIUM',
        category=CATEGORY,
        details=f"All containers use read-only root filesystems. ({len(ctx.containers)} checked)",
        evidence=[],
        frameworks={'CIS Docker Benchmark': '5.12', 'NIST SP 800-190': '4.3.2'},
    )


def check_docker_008(ctx: DockerContext) -> CheckResult:
    """AI-DOCKER-008 — Ports exposed on all interfaces (0.0.0.0)."""
    exposed: list[str] = []
    for c in ctx.containers:
        name = _cname(c)
        for cport, bindings in (c.get('NetworkSettings', {}).get('Ports') or {}).items():
            if not bindings:
                continue
            for b in bindings:
                host_ip = b.get('HostIp', '') or ''
                if host_ip in ('0.0.0.0', ''):
                    exposed.append(f"{name}: {cport} → 0.0.0.0:{b.get('HostPort', '?')}")
    if exposed:
        return CheckResult(
            check_id='AI-DOCKER-008',
            title='Container Ports Exposed on All Network Interfaces',
            status=WARN,
            severity='HIGH',
            category=CATEGORY,
            details=(
                f"{len(exposed)} port binding(s) listening on 0.0.0.0 — reachable from any network interface. "
                "AI model APIs (Ollama port 11434, vLLM port 8000, etc.) exposed on 0.0.0.0 without an "
                "authenticating gateway are accessible to anyone who can reach the host."
            ),
            evidence=exposed[:8],
            remediation=(
                "1. Bind to localhost for internal services: -p 127.0.0.1:11434:11434\n"
                "2. For compose: '127.0.0.1:11434:11434' not '11434:11434'\n"
                "3. Put a reverse proxy (nginx with auth) in front for any externally accessible AI endpoint.\n"
                "4. Use Docker internal networks for container-to-container comms — no host binding needed."
            ),
            frameworks={
                'CIS Docker Benchmark': '5.7',
                'NIST SP 800-190': '4.3.1',
                'OWASP LLM': 'LLM07 — Insecure Plugin Design',
                'MITRE ATLAS': 'AML.T0040 — ML Model Inference API Access',
            },
        )
    return CheckResult(
        check_id='AI-DOCKER-008',
        title='Container Ports Not Exposed on All Interfaces',
        status=PASS,
        severity='HIGH',
        category=CATEGORY,
        details=f"All port bindings are restricted to specific interfaces. ({len(ctx.containers)} checked)",
        evidence=[],
        frameworks={'CIS Docker Benchmark': '5.7', 'NIST SP 800-190': '4.3.1'},
    )


def check_docker_009(ctx: DockerContext) -> CheckResult:
    """AI-DOCKER-009 — Dangerous Linux capability additions."""
    cap_hits: list[str] = []
    for c in ctx.containers:
        cap_add = c.get('HostConfig', {}).get('CapAdd') or []
        dangerous = [cap for cap in cap_add if cap.upper() in _DANGEROUS_CAPS]
        if dangerous:
            cap_hits.append(f"{_cname(c)}: {', '.join(dangerous)}")
    if cap_hits:
        return CheckResult(
            check_id='AI-DOCKER-009',
            title='Dangerous Linux Capabilities Added to Containers',
            status=FAIL,
            severity='HIGH',
            category=CATEGORY,
            details=(
                f"{len(cap_hits)} container(s) with dangerous capability additions. "
                "SYS_ADMIN, NET_ADMIN, and ALL are common container escape vectors — "
                "they provide near-root access to host kernel interfaces."
            ),
            evidence=cap_hits,
            remediation=(
                "1. Remove SYS_ADMIN, NET_ADMIN, and ALL from --cap-add.\n"
                "2. Use only the minimum required capability: --cap-add NET_BIND_SERVICE for ports <1024.\n"
                "3. Apply a restrictive seccomp profile: --security-opt seccomp=default.json\n"
                "4. Audit: docker inspect <container> | jq '.[].HostConfig.CapAdd'"
            ),
            frameworks={
                'CIS Docker Benchmark': '5.3',
                'NIST SP 800-190': '4.3.3',
                'MITRE ATT&CK': 'T1611 — Escape to Host',
            },
        )
    return CheckResult(
        check_id='AI-DOCKER-009',
        title='No Dangerous Capabilities Added to Containers',
        status=PASS,
        severity='HIGH',
        category=CATEGORY,
        details=f"No containers have dangerous Linux capabilities (SYS_ADMIN, NET_ADMIN, ALL) added. ({len(ctx.containers)} checked)",
        evidence=[],
        frameworks={'CIS Docker Benchmark': '5.3', 'NIST SP 800-190': '4.3.3'},
    )


def check_docker_010(ctx: DockerContext) -> CheckResult:
    """AI-DOCKER-010 — Memory and CPU resource limits."""
    no_limits = []
    for c in ctx.containers:
        hc = c.get('HostConfig', {})
        if hc.get('Memory', 0) == 0 and hc.get('NanoCpus', 0) == 0:
            no_limits.append(_cname(c))
    if no_limits:
        return CheckResult(
            check_id='AI-DOCKER-010',
            title='Containers Running Without Resource Limits',
            status=WARN,
            severity='MEDIUM',
            category=CATEGORY,
            details=(
                f"{len(no_limits)} container(s) have no memory or CPU limits. "
                "AI model containers (Ollama, vLLM, LM Studio) can consume all available RAM under load, "
                "triggering host OOM and taking down all other services on the machine."
            ),
            evidence=[f"No limits: {n}" for n in no_limits],
            remediation=(
                "1. Set memory limits: docker run --memory=8g --memory-swap=8g <image>\n"
                "2. For compose: deploy: resources: limits: memory: 8G  cpus: '4.0'\n"
                "3. Memory guidance by model size: 7B → 8GB, 13B → 16GB, 70B → 48GB.\n"
                "4. Set CPU limits to prevent inference from starving other processes: --cpus=4\n"
                "5. Monitor live usage: docker stats --no-stream"
            ),
            frameworks={
                'CIS Docker Benchmark': '5.10',
                'NIST SP 800-190': '4.3.4',
                'OWASP LLM': 'LLM10 — Overreliance',
                'MITRE ATLAS': 'AML.T0034 — Cost Harvesting',
            },
        )
    return CheckResult(
        check_id='AI-DOCKER-010',
        title='Containers Have Resource Limits Configured',
        status=PASS,
        severity='MEDIUM',
        category=CATEGORY,
        details=f"All containers have memory or CPU limits configured. ({len(ctx.containers)} checked)",
        evidence=[],
        frameworks={'CIS Docker Benchmark': '5.10', 'NIST SP 800-190': '4.3.4'},
    )


def run_all(ctx: DockerContext) -> list:
    return [
        check_docker_001(ctx),
        check_docker_002(ctx),
        check_docker_003(ctx),
        check_docker_004(ctx),
        check_docker_005(ctx),
        check_docker_006(ctx),
        check_docker_007(ctx),
        check_docker_008(ctx),
        check_docker_009(ctx),
        check_docker_010(ctx),
    ]
