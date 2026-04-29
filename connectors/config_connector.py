"""
M.A.R.K. Sentinel — Config Connector
Scans a directory for AI deployment files and returns a structured ScanContext.
"""
import os
import re
import json
from pathlib import Path
from dataclasses import dataclass, field

try:
    import yaml
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False

SKIP_DIRS = frozenset({
    '.git', '__pycache__', '.venv', 'venv', 'node_modules',
    '.pytest_cache', 'dist', 'build', '.eggs', '.tox',
})
TEXT_EXTS = frozenset({
    '.py', '.json', '.yml', '.yaml', '.txt', '.md', '.env',
    '.cfg', '.ini', '.conf', '.toml', '.sh', '.bash', '.nginx',
    '.htaccess', '.properties',
})
MAX_FILE_BYTES = 200_000
MAX_FILES = 500

_POLICY_KEYS = ('ai_usage_policy', 'ai-usage-policy', 'ai_policy', 'ai-policy', 'usage_policy', 'aipolicy')
_RETENTION_KEYS = ('data_retention', 'retention_policy', 'data-retention', 'ai_retention')
_IR_KEYS = ('incident_response', 'ir_plan', 'incident-response', 'ai_incident', 'ai-incident', 'ai_ir')
_INVENTORY_KEYS = ('ai_inventory', 'ai_asset', 'aibom', 'ai-inventory', 'ai-asset', 'asset_inventory')
_OVERSIGHT_KEYS = ('oversight', 'human_review', 'human-oversight', 'ai_governance', 'ai-governance')
_CHECKSUM_KEYS = ('checksum', '.sha256', '.md5', 'sha256sum', 'model_checksums')


@dataclass
class ScanContext:
    target_dir: str
    mode: str = "config"

    # All readable text files: relative_path -> content
    files: dict = field(default_factory=dict)

    # Environment files
    env_files: list = field(default_factory=list)
    env_vars: dict = field(default_factory=dict)

    # .gitignore
    has_gitignore: bool = False
    gitignore_content: str = ""

    # Specific config files (raw text + parsed dicts where possible)
    docker_compose_raw: str = ""
    docker_compose: dict = field(default_factory=dict)
    nginx_conf: str = ""
    config_json: dict = field(default_factory=dict)
    config_json_raw: str = ""
    model_config: dict = field(default_factory=dict)
    model_config_raw: str = ""
    requirements_txt: str = ""
    agent_config: dict = field(default_factory=dict)
    agent_config_raw: str = ""

    # Documentation
    policy_files: list = field(default_factory=list)
    retention_policy_files: list = field(default_factory=list)
    ir_plan_files: list = field(default_factory=list)
    inventory_files: list = field(default_factory=list)
    oversight_docs: list = field(default_factory=list)
    checksum_files: list = field(default_factory=list)

    # Python source files: relative_path -> content
    python_files: dict = field(default_factory=dict)

    errors: list = field(default_factory=list)
    total_files_scanned: int = 0

    # Live probe results — populated by api_connector / ollama_connector
    probe_results: dict = field(default_factory=dict)   # probe_id -> ProbeResult
    live_endpoint: str = ""
    live_model: str = ""
    live_error: str = ""


def scan_directory(target_dir: str, mode: str = "config") -> ScanContext:
    ctx = ScanContext(target_dir=str(Path(target_dir).resolve()), mode=mode)
    root = Path(target_dir).resolve()
    count = 0

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        rel_dir = Path(dirpath).relative_to(root)

        for filename in filenames:
            if count >= MAX_FILES:
                break

            filepath = Path(dirpath) / filename
            rel_path = str(rel_dir / filename) if str(rel_dir) != '.' else filename
            rel_path = rel_path.replace('\\', '/')

            try:
                size = filepath.stat().st_size
            except OSError:
                continue

            if size > MAX_FILE_BYTES:
                continue

            ext = filepath.suffix.lower()
            name_lower = filename.lower()
            _special = {'.gitignore', '.dockerignore', '.gitattributes', '.editorconfig'}
            if ext not in TEXT_EXTS and not name_lower.startswith('.env') and 'dockerfile' not in name_lower:
                if filename not in _special:
                    continue

            try:
                content = filepath.read_text(encoding='utf-8', errors='replace')
            except (OSError, PermissionError) as e:
                ctx.errors.append(f"Cannot read {rel_path}: {e}")
                continue

            ctx.files[rel_path] = content
            count += 1
            _categorize(ctx, rel_path, filename, name_lower, content)

    ctx.total_files_scanned = count
    return ctx


def _categorize(ctx: ScanContext, rel_path: str, filename: str, name_lower: str, content: str):
    path_lower = rel_path.lower()

    if filename == '.gitignore':
        ctx.has_gitignore = True
        ctx.gitignore_content = content

    if _is_env_file(filename):
        ctx.env_files.append(rel_path)
        ctx.env_vars.update(_parse_env(content))

    if _is_docker_compose(filename):
        ctx.docker_compose_raw = content
        ctx.docker_compose = _try_yaml(content)

    if _is_nginx_conf(filename):
        ctx.nginx_conf = (ctx.nginx_conf + '\n' + content).strip()

    if _is_config_json(filename):
        ctx.config_json_raw = content
        ctx.config_json = _try_json(content)

    if _is_model_config(filename):
        ctx.model_config_raw = content
        ctx.model_config = _try_json(content)

    if _is_agent_config(filename):
        ctx.agent_config_raw = content
        ctx.agent_config = _try_json(content)

    if _is_requirements(filename):
        ctx.requirements_txt = (ctx.requirements_txt + '\n' + content).strip()

    if filename.endswith('.py'):
        ctx.python_files[rel_path] = content

    if any(k in name_lower for k in _CHECKSUM_KEYS):
        ctx.checksum_files.append(rel_path)

    # Documentation classification
    if any(k in path_lower for k in _POLICY_KEYS) and rel_path not in ctx.policy_files:
        ctx.policy_files.append(rel_path)

    if any(k in path_lower for k in _RETENTION_KEYS) and rel_path not in ctx.retention_policy_files:
        ctx.retention_policy_files.append(rel_path)

    if any(k in path_lower for k in _IR_KEYS) and rel_path not in ctx.ir_plan_files:
        ctx.ir_plan_files.append(rel_path)

    if any(k in path_lower for k in _INVENTORY_KEYS) and rel_path not in ctx.inventory_files:
        ctx.inventory_files.append(rel_path)

    if any(k in path_lower for k in _OVERSIGHT_KEYS) and rel_path not in ctx.oversight_docs:
        ctx.oversight_docs.append(rel_path)


# --- File type helpers ---

def _is_env_file(name: str) -> bool:
    return name == '.env' or name.startswith('.env.') or name.endswith('.env')


def _is_docker_compose(name: str) -> bool:
    return name in (
        'docker-compose.yml', 'docker-compose.yaml',
        'docker-compose.prod.yml', 'docker-compose.prod.yaml',
        'compose.yml', 'compose.yaml',
    )


def _is_nginx_conf(name: str) -> bool:
    lower = name.lower()
    return 'nginx' in lower and (lower.endswith('.conf') or lower.endswith('.nginx'))


def _is_config_json(name: str) -> bool:
    return name in ('config.json', 'config.prod.json', 'app.json', 'settings.json', 'app_config.json')


def _is_model_config(name: str) -> bool:
    return name in (
        'model_config.json', 'model.json', 'llm_config.json',
        'ai_config.json', 'model_settings.json',
    )


def _is_agent_config(name: str) -> bool:
    return name in (
        'agent_config.json', 'agent.json', 'tools.json',
        'agent.yml', 'agent.yaml', 'tools_config.json',
    )


def _is_requirements(name: str) -> bool:
    return name.startswith('requirements') and (name.endswith('.txt') or name.endswith('.in'))


# --- Parsing helpers ---

def _parse_env(content: str) -> dict:
    result = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if '=' in line:
            key, _, value = line.partition('=')
            result[key.strip()] = value.strip().strip('"\'')
    return result


def _try_json(content: str) -> dict:
    try:
        return json.loads(content)
    except (json.JSONDecodeError, ValueError):
        return {}


def _try_yaml(content: str) -> dict:
    if not _HAS_YAML:
        return {}
    try:
        return yaml.safe_load(content) or {}
    except Exception:
        return {}
