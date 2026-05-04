"""
AI-TOOL checks — AI CLI Tool Detection & Credential Security
Checks: AI-TOOL-001 through AI-TOOL-007

Detects AI developer tools that do not expose network ports:
Gemini CLI, Claude Code, OpenAI CLI, Aider, GitHub Copilot CLI, Cursor.
Evaluates credential file permissions and exposed API keys in shell profiles.
"""
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path
from . import CheckResult, PASS, FAIL, WARN, SKIP
from connectors.config_connector import ScanContext

CATEGORY = "AI-TOOL"

_API_KEY_RE = re.compile(
    r'(?i)(OPENAI_API_KEY|ANTHROPIC_API_KEY|GOOGLE_API_KEY|GEMINI_API_KEY|'
    r'COHERE_API_KEY|MISTRAL_API_KEY|GROQ_API_KEY|TOGETHER_API_KEY|'
    r'HUGGINGFACE_TOKEN|HF_TOKEN)'
    r'\s*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})["\']?'
)


def _home_dirs() -> list:
    homes = {Path.home()}
    home_root = Path('/home')
    if home_root.exists():
        for p in home_root.iterdir():
            if p.is_dir():
                homes.add(p)
    return list(homes)


def _is_world_readable(path: Path) -> bool:
    try:
        return bool(path.stat().st_mode & stat.S_IROTH)
    except OSError:
        return False


def _file_contains_key(path: Path) -> list:
    try:
        text = path.read_text(errors='ignore')
        return [m.group(1) for m in _API_KEY_RE.finditer(text)]
    except OSError:
        return []


def _pip_installed(package: str) -> bool:
    for cmd in ['pip', 'pip3']:
        try:
            r = subprocess.run([cmd, 'show', package], capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                return True
        except Exception:
            pass
    return False


def _npm_global(package: str) -> bool:
    try:
        r = subprocess.run(
            ['npm', 'list', '-g', '--depth=0', package],
            capture_output=True, text=True, timeout=10
        )
        return package in r.stdout
    except Exception:
        return False


def _world_readable_in(directory: Path) -> list:
    found = []
    try:
        for p in directory.rglob('*'):
            if p.is_file() and _is_world_readable(p):
                found.append(str(p))
    except OSError:
        pass
    return found


def check_tool_001(ctx: ScanContext) -> CheckResult:
    """AI-TOOL-001 — Gemini CLI: presence and credential security."""
    binary = bool(shutil.which('gemini'))
    pip_found = _pip_installed('google-generativeai') or _pip_installed('google-genai')

    cred_files = []
    world_readable = []
    for home in _home_dirs():
        d = home / '.gemini'
        if d.exists():
            for fname in ['credentials.json', 'config.json', '.env']:
                p = d / fname
                if p.exists():
                    cred_files.append(str(p))
                    if _is_world_readable(p):
                        world_readable.append(str(p))

    if not binary and not pip_found and not cred_files:
        return CheckResult(
            check_id='AI-TOOL-001',
            title='Gemini CLI not detected',
            status=SKIP,
            severity='LOW',
            category=CATEGORY,
            details='Gemini CLI not found on this system.',
        )

    if world_readable:
        return CheckResult(
            check_id='AI-TOOL-001',
            title='Gemini CLI credential files are world-readable',
            status=FAIL,
            severity='HIGH',
            category=CATEGORY,
            details=f'Credential files readable by all users: {", ".join(world_readable)}',
            evidence=world_readable,
            remediation='chmod 600 ~/.gemini/credentials.json',
            frameworks={'NIST AI RMF': 'GOVERN 1.7', 'OWASP LLM': 'LLM06'},
        )

    parts = []
    if binary:
        parts.append('gemini binary in PATH')
    if pip_found:
        parts.append('google-generativeai pip package installed')
    if cred_files:
        parts.append(f'credential files present: {", ".join(cred_files)}')

    return CheckResult(
        check_id='AI-TOOL-001',
        title='Gemini CLI detected — credentials secured',
        status=PASS,
        severity='LOW',
        category=CATEGORY,
        details='; '.join(parts) + '. Credential files have correct permissions.',
        frameworks={'NIST AI RMF': 'GOVERN 1.7'},
    )


def check_tool_002(ctx: ScanContext) -> CheckResult:
    """AI-TOOL-002 — Claude Code CLI: presence and credential security."""
    binary = bool(shutil.which('claude'))
    npm_found = _npm_global('@anthropic-ai/claude-code')
    pip_found = _pip_installed('anthropic')

    world_readable = []
    config_found = False
    for home in _home_dirs():
        d = home / '.claude'
        if d.exists():
            config_found = True
            world_readable.extend(_world_readable_in(d))

    if not binary and not npm_found and not pip_found and not config_found:
        return CheckResult(
            check_id='AI-TOOL-002',
            title='Claude Code CLI not detected',
            status=SKIP,
            severity='LOW',
            category=CATEGORY,
            details='Claude Code CLI not found on this system.',
        )

    if world_readable:
        return CheckResult(
            check_id='AI-TOOL-002',
            title='Claude Code CLI config files are world-readable',
            status=FAIL,
            severity='HIGH',
            category=CATEGORY,
            details=f'Config files readable by all users: {", ".join(world_readable)}',
            evidence=world_readable,
            remediation='chmod -R 600 ~/.claude/*.json',
            frameworks={'NIST AI RMF': 'GOVERN 1.7', 'OWASP LLM': 'LLM06'},
        )

    parts = []
    if binary:
        parts.append('claude binary in PATH')
    if npm_found:
        parts.append('@anthropic-ai/claude-code npm package installed')
    if pip_found:
        parts.append('anthropic pip package installed')

    return CheckResult(
        check_id='AI-TOOL-002',
        title='Claude Code CLI detected — credentials secured',
        status=PASS,
        severity='LOW',
        category=CATEGORY,
        details='; '.join(parts) + '. Config files have correct permissions.',
        frameworks={'NIST AI RMF': 'GOVERN 1.7'},
    )


def check_tool_003(ctx: ScanContext) -> CheckResult:
    """AI-TOOL-003 — OpenAI CLI: presence and credential security."""
    binary = bool(shutil.which('openai'))
    pip_found = _pip_installed('openai')

    cred_files = []
    world_readable = []
    for home in _home_dirs():
        for rel in ['.openai', '.config/openai']:
            d = home / rel
            if d.exists():
                for p in d.rglob('*'):
                    if p.is_file():
                        cred_files.append(str(p))
                        if _is_world_readable(p):
                            world_readable.append(str(p))

    if not binary and not pip_found and not cred_files:
        return CheckResult(
            check_id='AI-TOOL-003',
            title='OpenAI CLI not detected',
            status=SKIP,
            severity='LOW',
            category=CATEGORY,
            details='OpenAI CLI not found on this system.',
        )

    if world_readable:
        return CheckResult(
            check_id='AI-TOOL-003',
            title='OpenAI CLI credential files are world-readable',
            status=FAIL,
            severity='HIGH',
            category=CATEGORY,
            details=f'Credential files readable by all users: {", ".join(world_readable)}',
            evidence=world_readable,
            remediation='chmod 600 ~/.openai/* && chmod 700 ~/.openai',
            frameworks={'NIST AI RMF': 'GOVERN 1.7', 'OWASP LLM': 'LLM06'},
        )

    parts = []
    if binary:
        parts.append('openai binary in PATH')
    if pip_found:
        parts.append('openai pip package installed')

    return CheckResult(
        check_id='AI-TOOL-003',
        title='OpenAI CLI detected — credentials secured',
        status=PASS,
        severity='LOW',
        category=CATEGORY,
        details='; '.join(parts) + '. Credential files have correct permissions.',
        frameworks={'NIST AI RMF': 'GOVERN 1.7'},
    )


def check_tool_004(ctx: ScanContext) -> CheckResult:
    """AI-TOOL-004 — Aider AI coding assistant: presence and hardcoded key detection."""
    binary = bool(shutil.which('aider'))
    pip_found = _pip_installed('aider-chat')

    config_files = []
    leaked_keys = []
    for home in _home_dirs():
        for fname in ['.aider.conf.yml', '.aider.model.settings.yml', '.aider.model.metadata.json']:
            p = home / fname
            if p.exists():
                config_files.append(str(p))
                keys = _file_contains_key(p)
                if keys:
                    leaked_keys.extend([f'{p}: {k}' for k in keys])

    if not binary and not pip_found and not config_files:
        return CheckResult(
            check_id='AI-TOOL-004',
            title='Aider not detected',
            status=SKIP,
            severity='LOW',
            category=CATEGORY,
            details='Aider AI coding assistant not found on this system.',
        )

    if leaked_keys:
        return CheckResult(
            check_id='AI-TOOL-004',
            title='Aider config contains hardcoded API keys',
            status=FAIL,
            severity='CRITICAL',
            category=CATEGORY,
            details=f'API keys found in Aider config: {"; ".join(leaked_keys)}',
            evidence=leaked_keys,
            remediation=(
                'Remove API keys from aider config files.\n'
                'Use environment variables or a secrets manager instead.\n'
                'Add .aider.conf.yml to .gitignore to prevent accidental commits.'
            ),
            frameworks={'NIST AI RMF': 'GOVERN 1.7', 'OWASP LLM': 'LLM06', 'FedRAMP': 'IA-5'},
        )

    parts = []
    if binary:
        parts.append('aider binary in PATH')
    if pip_found:
        parts.append('aider-chat pip package installed')
    if config_files:
        parts.append(f'config files: {", ".join(config_files)}')

    return CheckResult(
        check_id='AI-TOOL-004',
        title='Aider detected — no hardcoded API keys found',
        status=PASS,
        severity='LOW',
        category=CATEGORY,
        details='; '.join(parts),
        frameworks={'NIST AI RMF': 'GOVERN 1.7'},
    )


def check_tool_005(ctx: ScanContext) -> CheckResult:
    """AI-TOOL-005 — GitHub Copilot CLI: presence and credential security."""
    copilot_ext = False
    if shutil.which('gh'):
        try:
            r = subprocess.run(
                ['gh', 'extension', 'list'],
                capture_output=True, text=True, timeout=10
            )
            copilot_ext = 'copilot' in r.stdout.lower()
        except Exception:
            pass

    world_readable = []
    config_found = False
    for home in _home_dirs():
        d = home / '.config' / 'github-copilot'
        if d.exists():
            config_found = True
            world_readable.extend(_world_readable_in(d))

    if not copilot_ext and not config_found:
        return CheckResult(
            check_id='AI-TOOL-005',
            title='GitHub Copilot CLI not detected',
            status=SKIP,
            severity='LOW',
            category=CATEGORY,
            details='GitHub Copilot CLI extension not found on this system.',
        )

    if world_readable:
        return CheckResult(
            check_id='AI-TOOL-005',
            title='GitHub Copilot CLI credential files are world-readable',
            status=FAIL,
            severity='HIGH',
            category=CATEGORY,
            details=f'Copilot credential files readable by all users: {", ".join(world_readable)}',
            evidence=world_readable,
            remediation='chmod -R 600 ~/.config/github-copilot/',
            frameworks={'NIST AI RMF': 'GOVERN 1.7', 'OWASP LLM': 'LLM06'},
        )

    return CheckResult(
        check_id='AI-TOOL-005',
        title='GitHub Copilot CLI detected — credentials secured',
        status=PASS,
        severity='LOW',
        category=CATEGORY,
        details='GitHub Copilot CLI installed; credential files have correct permissions.',
        frameworks={'NIST AI RMF': 'GOVERN 1.7'},
    )


def check_tool_006(ctx: ScanContext) -> CheckResult:
    """AI-TOOL-006 — Cursor IDE: presence check and data policy reminder."""
    cursor_found = bool(shutil.which('cursor'))
    if not cursor_found:
        cursor_found = Path('/Applications/Cursor.app').exists()
    if not cursor_found:
        win_path = Path(os.path.expandvars('%LOCALAPPDATA%')) / 'Programs' / 'Cursor' / 'Cursor.exe'
        cursor_found = win_path.exists()

    config_found = False
    for home in _home_dirs():
        for rel in ['.cursor', '.config/Cursor']:
            if (home / rel).exists():
                config_found = True

    if not cursor_found and not config_found:
        return CheckResult(
            check_id='AI-TOOL-006',
            title='Cursor IDE not detected',
            status=SKIP,
            severity='LOW',
            category=CATEGORY,
            details='Cursor IDE not found on this system.',
        )

    return CheckResult(
        check_id='AI-TOOL-006',
        title='Cursor IDE detected — review data policy',
        status=WARN,
        severity='LOW',
        category=CATEGORY,
        details=(
            'Cursor IDE is installed. Cursor sends code context to AI providers by default. '
            'Verify that Privacy Mode is enabled if operating in a sensitive or regulated environment.'
        ),
        remediation=(
            'In Cursor: Settings → Privacy → enable Privacy Mode to prevent code from being '
            'used for model training. Review which AI providers are enabled under Settings → Models.'
        ),
        frameworks={'NIST AI RMF': 'GOVERN 2.2', 'OWASP LLM': 'LLM06'},
    )


def check_tool_007(ctx: ScanContext) -> CheckResult:
    """AI-TOOL-007 — AI API keys hardcoded in shell profile or system environment files."""
    candidates = [Path('/etc/environment'), Path('/etc/profile')]
    for home in _home_dirs():
        for fname in ['.bashrc', '.zshrc', '.profile', '.bash_profile', '.env', '.envrc']:
            candidates.append(home / fname)

    leaked = []
    system_level = []
    for p in candidates:
        if not p.exists():
            continue
        keys = _file_contains_key(p)
        if keys:
            entry = f'{p}: {", ".join(keys)}'
            leaked.append(entry)
            if str(p).startswith('/etc/'):
                system_level.append(entry)

    if leaked:
        severity = 'CRITICAL' if system_level else 'HIGH'
        return CheckResult(
            check_id='AI-TOOL-007',
            title='AI API keys hardcoded in shell profile or system environment files',
            status=FAIL,
            severity=severity,
            category=CATEGORY,
            details=f'API keys found in: {"; ".join(leaked)}',
            evidence=leaked,
            remediation=(
                'Remove API keys from shell profile files.\n'
                'Use a secrets manager (AWS Secrets Manager, HashiCorp Vault, macOS Keychain)\n'
                'or per-project .env files that are excluded from source control via .gitignore.\n'
                'For CI/CD: inject secrets via the pipeline secrets store, not environment files.'
            ),
            frameworks={
                'NIST AI RMF': 'GOVERN 1.7',
                'OWASP LLM': 'LLM06',
                'FedRAMP': 'IA-5, SC-28',
                'CMMC 2.0': 'IA.L2-3.5.10',
            },
        )

    return CheckResult(
        check_id='AI-TOOL-007',
        title='No AI API keys found in shell profile or system environment files',
        status=PASS,
        severity='LOW',
        category=CATEGORY,
        details='Checked shell profiles and system environment files — no hardcoded AI API keys detected.',
        frameworks={'NIST AI RMF': 'GOVERN 1.7', 'FedRAMP': 'IA-5'},
    )


def run_all(ctx: ScanContext) -> list:
    return [
        check_tool_001(ctx),
        check_tool_002(ctx),
        check_tool_003(ctx),
        check_tool_004(ctx),
        check_tool_005(ctx),
        check_tool_006(ctx),
        check_tool_007(ctx),
    ]
