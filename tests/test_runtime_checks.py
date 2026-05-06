from connectors.config_connector import ScanContext
from checks.runtime import (
    check_runtime_001,
    check_runtime_002,
    check_runtime_003,
    check_runtime_004,
    check_runtime_005,
)
from checks import PASS, FAIL, WARN


# Helper to build a minimal ScanContext
def make_ctx(files: dict, total_files: int = None, live_error: str = "") -> ScanContext:
    ctx = ScanContext(target_dir="/fake/target")
    ctx.files = files
    ctx.total_files_scanned = total_files if total_files is not None else len(files)
    ctx.live_error = live_error
    return ctx


# --- Tests for AI-RUNTIME-001 ---

def test_runtime_001_pass_with_db_path():
    content = '{"monitoring": {"enabled": true, "db_path": "workspace/memory/.activity.db"}}'
    ctx = make_ctx({"hash.json": content})
    res = check_runtime_001(ctx)
    assert res.status == PASS


def test_runtime_001_pass_with_activity_db_file():
    # monitoring enabled, no explicit db_path, but activity DB file present in scanned files
    content = '{"monitoring": {"enabled": true}}'
    ctx = make_ctx({"hash.json": content, "workspace/memory/.activity.db": ""})
    res = check_runtime_001(ctx)
    assert res.status == PASS


def test_runtime_001_warn_no_db_path():
    # monitoring enabled but no db path and no activity db file
    content = '{"monitoring": {"enabled": true, "retention_days": 30}}'
    ctx = make_ctx({"hash.json": content})
    res = check_runtime_001(ctx)
    assert res.status == WARN


def test_runtime_001_fail_no_monitoring():
    ctx = make_ctx({"hash.json": "{}"})
    res = check_runtime_001(ctx)
    assert res.status == FAIL


# --- Tests for AI-RUNTIME-002 ---

def test_runtime_002_pass_anomaly_enabled():
    content = '{"monitoring": {"enabled": true, "anomaly_detection": {"enabled": true}}}'
    ctx = make_ctx({"hash.json": content})
    res = check_runtime_002(ctx)
    assert res.status == PASS


def test_runtime_002_warn_monitoring_but_no_anomaly():
    content = '{"monitoring": {"enabled": true}}'
    ctx = make_ctx({"hash.json": content})
    res = check_runtime_002(ctx)
    assert res.status == WARN


def test_runtime_002_fail_no_monitoring_or_anomaly():
    ctx = make_ctx({"hash.json": "{}"})
    res = check_runtime_002(ctx)
    assert res.status == FAIL


# --- Tests for AI-RUNTIME-003 ---

def test_runtime_003_pass_human_loop():
    content = '{"agents": {"some_agent": {}}, "human_oversight": true}'
    ctx = make_ctx({"agent_config.json": content})
    res = check_runtime_003(ctx)
    assert res.status == PASS


def test_runtime_003_fail_agents_without_human():
    content = '{"agents": {"background_worker": {"task": "cleanup"}}}'
    ctx = make_ctx({"agent_config.json": content})
    res = check_runtime_003(ctx)
    assert res.status == FAIL


def test_runtime_003_warn_no_agents_no_human():
    ctx = make_ctx({"README.md": "This repo has no agents configured."})
    res = check_runtime_003(ctx)
    assert res.status == WARN


# --- Tests for AI-RUNTIME-004 ---

def test_runtime_004_pass_token_limit_found():
    content = '{"providers": {"openai": {"max_tokens": 4096}, "anthropic": {"token_limit": 8192}}}'
    ctx = make_ctx({"config.json": content})
    res = check_runtime_004(ctx)
    assert res.status == PASS


def test_runtime_004_fail_no_token_limits():
    ctx = make_ctx({"config.json": "{}"})
    res = check_runtime_004(ctx)
    assert res.status == FAIL


# --- Tests for AI-RUNTIME-005 ---

def test_runtime_005_pass_audit_trail_explicit():
    content = '{"prompt_logging": true, "prompt_audit": true, "prompt_audit_logging": true}'
    # Use an explicit audit-trail style key that the regex recognizes
    content = '{"prompt_audit": true, "prompt_audit_logging": true, "monitoring": {"enabled": true}}'
    # Also include an explicit "prompt_logging" style flag using one of the recognized keys
    ctx = make_ctx({"hash.json": content})
    # Because audit trail patterns are flexible, ensure PASS
    res = check_runtime_005(ctx)
    assert res.status == PASS


def test_runtime_005_pass_retention_with_monitoring():
    content = '{"monitoring": {"enabled": true, "retention_days": 30}}'
    ctx = make_ctx({"hash.json": content})
    res = check_runtime_005(ctx)
    assert res.status == PASS


def test_runtime_005_warn_retention_too_short():
    content = '{"monitoring": {"enabled": true, "retention_days": 3}}'
    ctx = make_ctx({"hash.json": content})
    res = check_runtime_005(ctx)
    assert res.status == WARN


def test_runtime_005_warn_monitoring_no_retention():
    content = '{"monitoring": {"enabled": true}}'
    ctx = make_ctx({"hash.json": content})
    res = check_runtime_005(ctx)
    assert res.status == WARN


def test_runtime_005_fail_no_audit_or_monitoring():
    ctx = make_ctx({"hash.json": "{}"})
    res = check_runtime_005(ctx)
    assert res.status == FAIL
