from pathlib import Path
import importlib.util


REPO = Path(__file__).resolve().parents[1]
APP_SOURCE = (REPO / "admin" / "app.py").read_text()


def test_customer_schema_migrates_service_suspension_columns(tmp_path):
    spec = importlib.util.spec_from_file_location("admin_db", REPO / "admin" / "db.py")
    db = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(db)
    db.DB_PATH = str(tmp_path / "customers.db")
    db.init_db()
    with db.get_conn() as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(customers)")}
    assert {"service_suspended", "service_suspended_at", "service_suspended_by"} <= columns


def test_agent_lookup_denies_suspended_customer_tokens():
    assert "COALESCE(service_suspended,0)=0" in APP_SOURCE
    assert APP_SOURCE.count("COALESCE(service_suspended,0)=0") == 2


def test_suspend_and_resume_are_super_admin_actions_with_audit_log():
    assert '@app.post("/customers/suspend")' in APP_SOURCE
    assert '@app.post("/customers/resume-service")' in APP_SOURCE
    assert "customer_service_suspended" in APP_SOURCE
    assert "customer_service_resumed" in APP_SOURCE
