"""Shadow AI endpoint inventory, governance categorization, and GxP risk scoring.

Tier 1 capabilities inspired by Cyberhaven analysis:
  1. Endpoint-based shadow AI inventory (installed tools + running processes)
  2. AI tool categorization (Sanctioned / Shadow / Tolerated / Restricted)
  3. GxP-specific AI risk scoring (data sensitivity, validation status,
     regulatory impact, human oversight, change control)
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import sys
from typing import Iterable

# ── Known AI tool signatures ────────────────────────────────────────────────

# macOS .app bundle names (directory under /Applications or ~/Applications)
_MAC_AI_APPS: dict[str, tuple[str, str]] = {
    # bundle_dir_name: (tool_name, tool_category)
    'Claude.app':              ('Claude Desktop', 'saas_ai'),
    'ChatGPT.app':             ('ChatGPT', 'saas_ai'),
    'Cursor.app':              ('Cursor', 'coding_assistant'),
    'Ollama.app':              ('Ollama', 'local_llm'),
    'LM Studio.app':           ('LM Studio', 'local_llm'),
    'Jan.app':                 ('Jan', 'local_llm'),
    'Otter.ai.app':            ('Otter.ai', 'transcription'),
    'GitHub Copilot.app':      ('GitHub Copilot', 'coding_assistant'),
    'Aider.app':               ('Aider', 'coding_assistant'),
    'ComfyUI.app':             ('ComfyUI', 'image_gen'),
    'Stable Diffusion.app':    ('Stable Diffusion WebUI', 'image_gen'),
    'Whisper.app':             ('Whisper', 'transcription'),
    'Superwhisper.app':        ('Superwhisper', 'transcription'),
    'Gemini.app':              ('Gemini', 'saas_ai'),
    'Perplexity.app':          ('Perplexity', 'saas_ai'),
    'Granola.app':             ('Granola', 'transcription'),
    'Tana.app':                ('Tana', 'saas_ai'),
    'Raycast.app':             ('Raycast AI', 'saas_ai'),  # only if AI features used
}

# Windows installed-program display-name substrings (registry / Program Files)
_WIN_AI_APP_NAMES: dict[str, tuple[str, str]] = {
    'Claude':                  ('Claude Desktop', 'saas_ai'),
    'ChatGPT':                 ('ChatGPT', 'saas_ai'),
    'Cursor':                  ('Cursor', 'coding_assistant'),
    'Ollama':                  ('Ollama', 'local_llm'),
    'LM Studio':               ('LM Studio', 'local_llm'),
    'Jan':                     ('Jan', 'local_llm'),
    'Otter':                   ('Otter.ai', 'transcription'),
    'GitHub Copilot':          ('GitHub Copilot', 'coding_assistant'),
    'ComfyUI':                 ('ComfyUI', 'image_gen'),
    'Stable Diffusion WebUI':  ('Stable Diffusion WebUI', 'image_gen'),
    'Whisper':                 ('Whisper', 'transcription'),
    'Perplexity':              ('Perplexity', 'saas_ai'),
    'Gemini':                  ('Gemini', 'saas_ai'),
}

# CLI tools / binaries to look for on PATH
_CLI_AI_TOOLS: dict[str, tuple[str, str]] = {
    'claude':    ('Claude Code', 'coding_assistant'),
    'cursor':    ('Cursor', 'coding_assistant'),
    'aider':     ('Aider', 'coding_assistant'),
    'copilot':   ('GitHub Copilot CLI', 'coding_assistant'),
    'codeium':   ('Codeium', 'coding_assistant'),
    'opencode':  ('OpenCode', 'coding_assistant'),
    'gemini':    ('Gemini CLI', 'coding_assistant'),
    'ollama':    ('Ollama', 'local_llm'),
    'llamafile': ('llamafile', 'local_llm'),
    'vllm':      ('vLLM', 'local_llm'),
    'localai':   ('LocalAI', 'local_llm'),
    'comfyui':   ('ComfyUI', 'image_gen'),
    'tabby':     ('TabbyML', 'coding_assistant'),
}

# Local model artifact directories that indicate an AI tool is installed
_LOCAL_MODEL_DIRS: list[str] = [
    os.path.expanduser('~/.ollama'),
    os.path.expanduser('~/.cache/huggingface'),
    os.path.expanduser('~/.cache/lm-studio'),
    os.path.expanduser('~/.lmstudio'),
    os.path.expanduser('~/.jan'),
    os.path.expanduser('~/.comfyui'),
    os.path.expanduser('~/Library/Application Support/comfyui'),
]

# Process-name substrings for running-process detection (mirrors agent.py)
_PROC_SIGS: dict[str, tuple[str, str]] = {
    'claude':         ('Claude Code', 'coding_assistant'),
    'cursor':         ('Cursor', 'coding_assistant'),
    'aider':          ('Aider', 'coding_assistant'),
    'copilot':        ('GitHub Copilot', 'coding_assistant'),
    'codeium':        ('Codeium', 'coding_assistant'),
    'continue':       ('Continue', 'coding_assistant'),
    'opencode':       ('OpenCode', 'coding_assistant'),
    'gemini':         ('Gemini CLI', 'coding_assistant'),
    'ollama':         ('Ollama', 'local_llm'),
    'lm-studio':      ('LM Studio', 'local_llm'),
    'lmstudio':       ('LM Studio', 'local_llm'),
    'llama-server':   ('llama.cpp', 'local_llm'),
    'llamafile':      ('llamafile', 'local_llm'),
    'koboldcpp':      ('KoboldCPP', 'local_llm'),
    'jan':            ('Jan', 'local_llm'),
    'vllm':           ('vLLM', 'local_llm'),
    'localai':        ('LocalAI', 'local_llm'),
    'comfyui':        ('ComfyUI', 'image_gen'),
    'stable-diffusion-webui': ('Stable Diffusion WebUI', 'image_gen'),
    'tabby':          ('TabbyML', 'coding_assistant'),
    'mcp-server':     ('MCP Server', 'mcp'),
    'fastmcp':        ('FastMCP', 'mcp'),
    'chatgpt':        ('ChatGPT', 'saas_ai'),
    'otter':          ('Otter.ai', 'transcription'),
}


# ── Governance categories ───────────────────────────────────────────────────

SANCTIONED = 'sanctioned'   # explicitly approved by the organization
TOLERATED  = 'tolerated'    # not approved but low-risk
SHADOW     = 'shadow'       # discovered without authorization
RESTRICTED = 'restricted'   # explicitly prohibited by policy

ALL_CATEGORIES = (SANCTIONED, TOLERATED, SHADOW, RESTRICTED)


def categorize_tool(tool_name: str, config: dict | None = None) -> str:
    """Assign a governance category based on config-defined lists.

    Config keys (in agent_config.json):
      sanctioned_ai_tools:  list[str]   — explicitly approved
      tolerated_ai_tools:   list[str]   — allowed but not formally sanctioned
      restricted_ai_tools:  list[str]   — explicitly prohibited

    Default: any discovered tool not on a list is SHADOW.
    """
    config = config or {}
    sanctioned = {t.lower() for t in config.get('sanctioned_ai_tools', [])}
    tolerated  = {t.lower() for t in config.get('tolerated_ai_tools', [])}
    restricted = {t.lower() for t in config.get('restricted_ai_tools', [])}
    name_lower = tool_name.lower()

    for s in restricted:
        if s in name_lower:
            return RESTRICTED
    for s in sanctioned:
        if s in name_lower:
            return SANCTIONED
    for s in tolerated:
        if s in name_lower:
            return TOLERATED
    return SHADOW


# ── GxP-specific risk scoring ────────────────────────────────────────────────

# Each dimension scored 0-20; total 0-100 (higher = riskier).
# Dimensions: data_sensitivity, validation_status, regulatory_impact,
#             human_oversight, change_control

# Category-based default risk dimension scores
_CATEGORY_DEFAULTS: dict[str, dict[str, int]] = {
    'coding_assistant': {
        'data_sensitivity': 15,
        'validation_status': 20,
        'regulatory_impact': 15,
        'human_oversight': 10,
        'change_control': 20,
    },
    'local_llm': {
        'data_sensitivity': 15,
        'validation_status': 20,
        'regulatory_impact': 10,
        'human_oversight': 15,
        'change_control': 20,
    },
    'saas_ai': {
        'data_sensitivity': 20,
        'validation_status': 20,
        'regulatory_impact': 15,
        'human_oversight': 10,
        'change_control': 15,
    },
    'image_gen': {
        'data_sensitivity': 10,
        'validation_status': 20,
        'regulatory_impact': 10,
        'human_oversight': 15,
        'change_control': 20,
    },
    'transcription': {
        'data_sensitivity': 20,
        'validation_status': 20,
        'regulatory_impact': 15,
        'human_oversight': 10,
        'change_control': 15,
    },
    'mcp': {
        'data_sensitivity': 15,
        'validation_status': 20,
        'regulatory_impact': 15,
        'human_oversight': 15,
        'change_control': 20,
    },
}

# Governance category risk adjustments (applied to the total)
_GOV_RISK_ADJUST: dict[str, int] = {
    SANCTIONED: -15,
    TOLERATED:  -5,
    SHADOW:     0,
    RESTRICTED: +10,
}

_RISK_DIMENSIONS = (
    'data_sensitivity',
    'validation_status',
    'regulatory_impact',
    'human_oversight',
    'change_control',
)


def score_gxp_risk(tool_category: str, governance_status: str,
                   config: dict | None = None) -> tuple[int, dict[str, int]]:
    """Compute a GxP-specific risk score (0-100, higher = riskier).

    Returns (total_score, dimension_dict).
    """
    config = config or {}
    base = dict(_CATEGORY_DEFAULTS.get(tool_category, {
        'data_sensitivity': 15,
        'validation_status': 20,
        'regulatory_impact': 15,
        'human_oversight': 10,
        'change_control': 15,
    }))

    # Apply config overrides if present
    overrides = config.get('gxp_risk_overrides', {})
    if isinstance(overrides, dict):
        for dim in _RISK_DIMENSIONS:
            if dim in overrides and isinstance(overrides[dim], dict):
                cat_key = tool_category
                if cat_key in overrides[dim]:
                    base[dim] = int(overrides[dim][cat_key])

    total = sum(base.values())
    total += _GOV_RISK_ADJUST.get(governance_status, 0)

    # Clamp to 0-100
    total = max(0, min(100, total))
    return total, base


def risk_band(score: int) -> str:
    """Map a 0-100 risk score to a severity band."""
    if score >= 75:
        return 'CRITICAL'
    if score >= 50:
        return 'HIGH'
    if score >= 25:
        return 'MEDIUM'
    return 'LOW'


# ── Platform-specific installed-tool discovery ───────────────────────────────

def _discover_macos_apps() -> list[dict]:
    """Scan /Applications and ~/Applications for known AI app bundles."""
    found = []
    search_dirs = ['/Applications', os.path.expanduser('~/Applications')]
    for base in search_dirs:
        if not os.path.isdir(base):
            continue
        try:
            for entry in os.listdir(base):
                if not entry.endswith('.app'):
                    continue
                sig = _MAC_AI_APPS.get(entry)
                if sig is None:
                    # Case-insensitive fallback
                    for key, val in _MAC_AI_APPS.items():
                        if key.lower() == entry.lower():
                            sig = val
                            break
                if sig is None:
                    continue
                tool_name, tool_category = sig
                found.append({
                    'tool_name': tool_name,
                    'tool_category': tool_category,
                    'install_path': os.path.join(base, entry),
                    'source': 'installed_app',
                })
        except PermissionError:
            pass
    return found


def _discover_windows_apps() -> list[dict]:
    """Scan registry uninstall keys for known AI tools on Windows."""
    found = []
    try:
        import winreg
    except ImportError:
        return found

    registry_keys = [
        (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'),
        (winreg.HKEY_LOCAL_MACHINE, r'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'),
        (winreg.HKEY_CURRENT_USER, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'),
    ]

    for hive, key_path in registry_keys:
        try:
            with winreg.OpenKey(hive, key_path) as parent:
                index = 0
                while True:
                    try:
                        sub_name = winreg.EnumKey(parent, index)
                        index += 1
                    except OSError:
                        break
                    try:
                        with winreg.OpenKey(parent, sub_name) as sub:
                            display_name, _ = winreg.QueryValueEx(sub, 'DisplayName')
                    except (FileNotFoundError, OSError):
                        continue
                    if not display_name:
                        continue
                    name_lower = (display_name or '').lower()
                    for sig_name, (tool_name, tool_category) in _WIN_AI_APP_NAMES.items():
                        if sig_name.lower() in name_lower:
                            found.append({
                                'tool_name': tool_name,
                                'tool_category': tool_category,
                                'install_path': display_name,
                                'source': 'installed_app',
                            })
                            break
        except (FileNotFoundError, PermissionError):
            pass
    return found


def _discover_cli_tools() -> list[dict]:
    """Check PATH for known AI CLI binaries."""
    found = []
    seen = set()
    for bin_name, (tool_name, tool_category) in _CLI_AI_TOOLS.items():
        if tool_name in seen:
            continue
        path = shutil.which(bin_name)
        if path:
            seen.add(tool_name)
            found.append({
                'tool_name': tool_name,
                'tool_category': tool_category,
                'install_path': path,
                'source': 'cli_tool',
            })
    return found


def _discover_local_model_dirs() -> list[dict]:
    """Check for local model artifact directories."""
    found = []
    for dir_path in _LOCAL_MODEL_DIRS:
        if os.path.isdir(dir_path):
            # Infer the tool from the directory name
            if 'ollama' in dir_path.lower():
                tool_name, tool_category = 'Ollama', 'local_llm'
            elif 'huggingface' in dir_path.lower():
                tool_name, tool_category = 'Hugging Face Cache', 'local_llm'
            elif 'lm-studio' in dir_path.lower() or 'lmstudio' in dir_path.lower():
                tool_name, tool_category = 'LM Studio', 'local_llm'
            elif 'jan' in dir_path.lower():
                tool_name, tool_category = 'Jan', 'local_llm'
            elif 'comfyui' in dir_path.lower():
                tool_name, tool_category = 'ComfyUI', 'image_gen'
            else:
                continue
            found.append({
                'tool_name': tool_name,
                'tool_category': tool_category,
                'install_path': dir_path,
                'source': 'local_model_dir',
            })
    return found


def discover_installed_ai_tools() -> list[dict]:
    """Platform-aware discovery of installed AI tools on the endpoint."""
    system = platform.system()
    results: list[dict] = []
    if system == 'Darwin':
        results += _discover_macos_apps()
    elif system == 'Windows':
        results += _discover_windows_apps()
    # CLI tools and local model dirs are cross-platform
    results += _discover_cli_tools()
    results += _discover_local_model_dirs()
    return _dedup_tools(results)


def discover_running_ai_processes() -> list[dict]:
    """Detect currently running AI tool processes via psutil."""
    try:
        import psutil
    except ImportError:
        return []
    found = []
    for proc in psutil.process_iter(['pid', 'name', 'create_time', 'exe']):
        try:
            pname = (proc.info['name'] or '').lower()
            if pname.endswith('.exe'):
                pname = pname[:-4]
            exe = proc.info.get('exe') or ''
            for proc_key, (tool_name, tool_category) in _PROC_SIGS.items():
                if proc_key in pname:
                    # Filter out macOS system frameworks that share names with AI tools.
                    # e.g. "CursorUIViewService" is a macOS text-input service, not
                    # the Cursor AI editor. System processes live under /System/.
                    if exe.startswith('/System/') or exe.startswith('/usr/libexec/'):
                        break
                    # Cursor: require the actual Cursor.app, not system services
                    if proc_key == 'cursor' and 'Cursor.app' not in exe and not exe.endswith('Cursor'):
                        break
                    # Jan: filter out unrelated system processes with "jan" in the name
                    if proc_key == 'jan' and 'Jan.app' not in exe and not pname.startswith('jan'):
                        break
                    found.append({
                        'tool_name': tool_name,
                        'tool_category': tool_category,
                        'pid': proc.info['pid'],
                        'install_path': exe,
                        'source': 'running_process',
                    })
                    break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return _dedup_tools(found, key='tool_name')


def _dedup_tools(tools: list[dict], key: str = 'tool_name') -> list[dict]:
    """Deduplicate tools by name, preserving first occurrence."""
    seen = set()
    deduped = []
    for t in tools:
        name = t.get(key, '')
        if name in seen:
            continue
        seen.add(name)
        deduped.append(t)
    return deduped


# ── Snapshot builder ─────────────────────────────────────────────────────────

def build_inventory_snapshot(config: dict | None = None) -> list[dict]:
    """Build a complete shadow AI inventory snapshot for this endpoint.

    Combines installed tools and running processes, assigns governance
    categories, and computes GxP risk scores for each tool.

    Returns a list of inventory entries, each containing:
      tool_name, tool_category, governance_status, install_path, source,
      running, risk_score, risk_dimensions, risk_band
    """
    config = config or {}
    installed = discover_installed_ai_tools()
    running   = discover_running_ai_processes()
    running_names = {t['tool_name'] for t in running}

    # Merge: installed tools + running-only tools (processes without install entry)
    merged: dict[str, dict] = {}
    for tool in installed:
        name = tool['tool_name']
        merged[name] = {
            'tool_name': name,
            'tool_category': tool['tool_category'],
            'install_path': tool.get('install_path', ''),
            'source': tool.get('source', 'installed'),
            'running': name in running_names,
        }
    for tool in running:
        name = tool['tool_name']
        if name not in merged:
            merged[name] = {
                'tool_name': name,
                'tool_category': tool['tool_category'],
                'install_path': tool.get('install_path', ''),
                'source': 'running_process',
                'running': True,
            }
        else:
            merged[name]['running'] = True

    entries = []
    for tool in merged.values():
        gov = categorize_tool(tool['tool_name'], config)
        score, dims = score_gxp_risk(tool['tool_category'], gov, config)
        entries.append({
            'tool_name': tool['tool_name'],
            'tool_category': tool['tool_category'],
            'governance_status': gov,
            'install_path': tool['install_path'],
            'source': tool['source'],
            'running': tool['running'],
            'risk_score': score,
            'risk_dimensions': dims,
            'risk_band': risk_band(score),
        })

    entries.sort(key=lambda e: e['risk_score'], reverse=True)
    return entries
