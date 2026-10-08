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
