from pathlib import Path


REPO = Path(__file__).resolve().parents[1]


def test_admin_monitor_queries_the_authenticated_host_broker():
    source = (REPO / "admin" / "monitor.py").read_text()
    assert 'http://sentinel-deployer:9000/usage/{customer_id}' in source
    assert 'X-Arckon-Deploy-Token' in source


def test_shadow_ai_lookup_uses_the_customer_container_database_path():
    source = (REPO / "admin" / "app.py").read_text()
    assert "db = sqlite3.connect('/app/data/agents.db')" in source
