from pathlib import Path


REPO = Path(__file__).resolve().parents[1]


def test_admin_monitor_queries_the_authenticated_host_broker():
    source = (REPO / "admin" / "monitor.py").read_text()
    assert 'f"/usage/{customer_id}"' in source
    assert 'X-Arckon-Deploy-Token' in source


def test_shadow_ai_lookup_uses_the_customer_container_database_path():
    source = (REPO / "admin" / "app.py").read_text()
    assert "db = sqlite3.connect('/app/data/agents.db')" in source


def test_stale_agents_get_a_grace_period_and_auditable_notifications():
    source = (REPO / "admin" / "monitor.py").read_text()
    db_source = (REPO / "admin" / "db.py").read_text()
    assert "_STALE_REMOVAL_GRACE_DAYS = 30" in source
    assert '"/stale/remove", "POST"' in source
    assert "stale_agent_lifecycle" in db_source
    assert "stale_agent_notifications" in db_source
    assert "agents: list[dict]" in source
    assert '"\\n".join(device_lines)' in source


def test_telemetry_endpoint_requires_a_per_customer_agent_token():
    source = (REPO / "admin" / "app.py").read_text()
    assert "X-Sentinel-Agent-Token" in source
    # The caller's token must match the stored token for the supplied tenant.
    assert "compare_digest(submitted, stored)" in source
    # An empty or missing token is rejected before any write.
    assert 'status_code=401' in source


def test_telemetry_client_attaches_the_agent_token_header():
    source = (REPO / "license.py").read_text()
    assert "_telemetry_agent_token" in source
    assert "X-Sentinel-Agent-Token" in source


def test_broker_uses_separate_scoped_tokens_for_deploy_and_lifecycle():
    broker = (REPO / "deploy" / "gcp" / "deployer" / "server.py").read_text()
    assert "DEPLOY_OP_TOKEN_FILE" in broker
    assert "_read_op_token" in broker
    assert "_authorized" in broker
    # /deploy is gated by the op token, not the lifecycle token.
    assert 'self.path == "/deploy"' in broker


def test_admin_uses_the_op_token_only_for_the_deploy_route():
    source = (REPO / "admin" / "app.py").read_text()
    assert "DEPLOY_OP_TOKEN" in source
    assert "_load_deploy_op_token" in source
    # The deploy route sends the op token, not the lifecycle token.
    deploy_section = source[source.index('"/admin/deploy"'):]
    assert "DEPLOY_OP_TOKEN" in deploy_section
