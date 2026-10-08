from pathlib import Path


REPO = Path(__file__).resolve().parents[1]


def test_admin_monitor_queries_the_production_customer_database_path():
    source = (REPO / "admin" / "monitor.py").read_text()
    assert 'db_path = "/app/data/agents.db"' in source
    assert "/app/data/customers/{customer_id}/agents.db" not in source


def test_shadow_ai_lookup_uses_the_customer_container_database_path():
    source = (REPO / "admin" / "app.py").read_text()
    assert "db = sqlite3.connect('/app/data/agents.db')" in source
