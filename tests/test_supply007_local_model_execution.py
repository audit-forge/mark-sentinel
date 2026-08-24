from connectors.config_connector import ScanContext
from checks import FAIL, SKIP, WARN
from checks.supply_chain import check_supply_007

_AGENT_MD_GATED = """---
description: Implements one approved task.
model: ollama/qwen3:30b-instruct
permission:
  edit: allow
  bash:
    "*": ask
    "git status*": allow
    "git diff*": allow
---

Body text.
"""

_AGENT_MD_WILDCARD_ALLOW = """---
description: Implements one approved task.
model: ollama/qwen3:30b-instruct
permission:
  edit: allow
  bash:
    "*": allow
---

Body text.
"""

_OPENCODE_JSON_LOCAL_MODEL = """{
  "$schema": "https://opencode.ai/config.json",
  "model": "ollama/qwen3:30b-instruct"
}
"""


def test_no_local_model_is_skip():
    ctx = ScanContext(target_dir="/project")
    ctx.files = {
        "opencode.json": '{"$schema": "https://opencode.ai/config.json", "model": "anthropic/claude-sonnet-5"}',
    }

    result = check_supply_007(ctx)

    assert result.status == SKIP
    assert result.check_id == "AI-SUPPLY-007"


def test_local_model_with_gated_bash_warns_that_static_scan_cannot_verify_weights():
    ctx = ScanContext(target_dir="/project")
    ctx.files = {
        ".config/opencode/agents/pharaoh-qwen-builder.md": _AGENT_MD_GATED,
        ".ollama/models/manifests/registry.ollama.ai/library/qwen3/30b-instruct": '{"config":{}}',
    }

    result = check_supply_007(ctx)

    assert result.status == WARN
    assert result.severity == "MEDIUM"
    assert result.check_id == "AI-SUPPLY-007"
    assert any("agent backed by a local" in e for e in result.evidence)
    assert "time-triggered" in result.remediation


def test_local_model_with_wildcard_bash_allow_is_fail():
    ctx = ScanContext(target_dir="/project")
    ctx.files = {
        ".config/opencode/agents/risky-builder.md": _AGENT_MD_WILDCARD_ALLOW,
    }

    result = check_supply_007(ctx)

    assert result.status == FAIL
    assert result.severity == "CRITICAL"
    assert any("without per-call approval" in e for e in result.evidence)


def test_opencode_json_local_model_plus_claude_settings_bypass_is_fail():
    ctx = ScanContext(target_dir="/project")
    ctx.files = {
        "opencode.json": _OPENCODE_JSON_LOCAL_MODEL,
        ".claude/settings.json": '{"defaultMode": "bypassPermissions"}',
    }

    result = check_supply_007(ctx)

    assert result.status == FAIL
    assert any("permission bypass configured" in e for e in result.evidence)


def test_unofficial_ollama_namespace_alone_is_warn():
    ctx = ScanContext(target_dir="/project")
    ctx.files = {
        ".ollama/models/manifests/registry.ollama.ai/someuser/qwen3-finetune/latest": '{"config":{}}',
    }

    result = check_supply_007(ctx)

    assert result.status == WARN
    assert result.severity == "HIGH"
    assert any("publisher: someuser" in e for e in result.evidence)


def test_official_ollama_namespace_is_not_flagged_as_unofficial():
    ctx = ScanContext(target_dir="/project")
    ctx.files = {
        ".ollama/models/manifests/registry.ollama.ai/library/qwen3/30b-instruct": '{"config":{}}',
    }

    result = check_supply_007(ctx)

    # A bare official-namespace manifest with no agent wiring is not itself
    # "local model evidence" (nothing shows it's actually driving an agent),
    # so this must not be reported as unofficial/unverified.
    assert result.status == SKIP


def test_unofficial_ollama_plus_unattended_bash_but_no_local_model_is_warn_not_fail():
    """An unofficial Ollama manifest alone (no agent wired to a local model)
    plus an unrelated Claude bypass setting must NOT produce a CRITICAL FAIL.
    Only a local model actually wired into an agent + unattended execution = FAIL."""
    ctx = ScanContext(target_dir="/project")
    ctx.files = {
        ".ollama/models/manifests/registry.ollama.ai/someuser/qwen3-finetune/latest": '{"config":{}}',
        ".claude/settings.json": '{"defaultMode": "bypassPermissions"}',
    }

    result = check_supply_007(ctx)

    assert result.status == WARN
    assert result.severity == "HIGH"
    assert "Unattended execution was also found" in result.details


def test_compact_json_local_model_is_detected():
    """The regex must match compact JSON without a space after the colon."""
    ctx = ScanContext(target_dir="/project")
    ctx.files = {
        "opencode.json": '{"model":"ollama/qwen3:30b-instruct"}',
    }

    result = check_supply_007(ctx)

    assert result.status == WARN
    assert any("primary model routed through a local" in e for e in result.evidence)


def test_single_quoted_local_model_in_yaml_is_detected():
    """The regex must match single-quoted YAML values."""
    ctx = ScanContext(target_dir="/project")
    ctx.files = {
        "config.yml": "model: 'ollama/qwen3:30b-instruct'\n",
    }

    result = check_supply_007(ctx)

    assert result.status == WARN


def test_claude_unscoped_bash_allow_is_detected():
    """An unscoped Bash(*) entry in Claude Code permissions.allow is a bypass."""
    ctx = ScanContext(target_dir="/project")
    ctx.files = {
        "opencode.json": _OPENCODE_JSON_LOCAL_MODEL,
        ".claude/settings.json": '{"permissions": {"allow": ["Bash(*)"]}}',
    }

    result = check_supply_007(ctx)

    assert result.status == FAIL
    assert any("permission bypass configured" in e for e in result.evidence)


def test_claude_plain_bash_allow_is_detected():
    """A bare 'Bash' entry in Claude Code permissions.allow is also a bypass."""
    ctx = ScanContext(target_dir="/project")
    ctx.files = {
        "opencode.json": _OPENCODE_JSON_LOCAL_MODEL,
        ".claude/settings.local.json": '{"permissions": {"allow": ["Bash"]}}',
    }

    result = check_supply_007(ctx)

    assert result.status == FAIL


def test_localhost_baseurl_is_detected_as_local_model():
    """A baseURL pointing at localhost indicates a local model runtime."""
    ctx = ScanContext(target_dir="/project")
    ctx.files = {
        "opencode.json": '{"baseURL": "http://127.0.0.1:11434/v1", "model": "local/qwen3"}',
    }

    result = check_supply_007(ctx)

    assert result.status == WARN
    assert any("local runtime" in e for e in result.evidence)


def test_scan_directory_collects_claude_settings_but_not_caches(tmp_path):
    """Integration test: scan_directory must collect .claude/settings.json
    but NOT .claude/projects/, .claude/shell-snapshots/, or .claude/todos/."""
    from connectors.config_connector import scan_directory

    # Build a temp tree
    claude_dir = tmp_path / ".claude"
    claude_dir.mkdir()
    (claude_dir / "settings.json").write_text('{"defaultMode": "bypassPermissions"}')
    (claude_dir / "settings.local.json").write_text('{"permissions": {"allow": []}}')
    projects = claude_dir / "projects" / "session-1"
    projects.mkdir(parents=True)
    (projects / "conversation.json").write_text('{"messages": ["secret data"]}')
    snapshots = claude_dir / "shell-snapshots"
    snapshots.mkdir()
    (snapshots / "cmd.sh").write_text('echo secret')
    todos = claude_dir / "todos"
    todos.mkdir()
    (todos / "todo.json").write_text('{"task": "review"}')

    ctx = scan_directory(str(tmp_path))
    claude_files = {k: v for k, v in ctx.files.items() if '.claude/' in k}

    assert '.claude/settings.json' in claude_files
    assert '.claude/settings.local.json' in claude_files
    assert not any('projects' in k for k in claude_files), \
        f".claude/projects/ files leaked into scan: {[k for k in claude_files if 'projects' in k]}"
    assert not any('shell-snapshots' in k for k in claude_files), \
        f".claude/shell-snapshots/ files leaked: {[k for k in claude_files if 'shell-snapshots' in k]}"
    assert not any('todos' in k for k in claude_files), \
        f".claude/todos/ files leaked: {[k for k in claude_files if 'todos' in k]}"


def test_scan_directory_collects_opencode_agent_md_but_not_sessions(tmp_path):
    """Integration test: scan_directory must collect .config/opencode/agents/*.md
    but NOT .config/opencode/sessions/ or .config/opencode/log/."""
    from connectors.config_connector import scan_directory

    agents_dir = tmp_path / ".config" / "opencode" / "agents"
    agents_dir.mkdir(parents=True)
    (agents_dir / "my-agent.md").write_text(
        '---\nmodel: ollama/qwen3:30b\npermission:\n  bash:\n    "*": ask\n---\nbody\n'
    )
    sessions = tmp_path / ".config" / "opencode" / "sessions"
    sessions.mkdir(parents=True)
    (sessions / "session-1.jsonl").write_text('{"messages": ["secret"]}')
    logs = tmp_path / ".config" / "opencode" / "log"
    logs.mkdir(parents=True)
    (logs / "opencode.log").write_text("secret log data")

    ctx = scan_directory(str(tmp_path))
    opencode_files = {k: v for k, v in ctx.files.items() if '.config/opencode/' in k}

    assert any(k.endswith('agents/my-agent.md') for k in opencode_files), \
        f"agent .md not collected: {list(opencode_files.keys())}"
    assert not any('sessions/' in k for k in opencode_files), \
        f"sessions leaked: {[k for k in opencode_files if 'sessions/' in k]}"
    assert not any('log/' in k for k in opencode_files), \
        f"log leaked: {[k for k in opencode_files if 'log/' in k]}"
