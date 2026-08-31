import importlib.util
import sys
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
ADMIN = REPO / "admin"


def _load_monitor():
    sys.path.insert(0, str(ADMIN))
    try:
        spec = importlib.util.spec_from_file_location("admin_monitor", ADMIN / "monitor.py")
        monitor = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(monitor)
        return monitor
    finally:
        sys.path.pop(0)


def test_reminder_windows_start_ninety_days_before_expiry():
    monitor = _load_monitor()
    assert monitor._renewal_milestone(91) is None
    assert monitor._renewal_milestone(90) == 90
    assert monitor._renewal_milestone(61) == 90
    assert monitor._renewal_milestone(60) == 60
    assert monitor._renewal_milestone(30) == 30
    assert monitor._renewal_milestone(14) == 14
    assert monitor._renewal_milestone(7) == 7
    assert monitor._renewal_milestone(1) == 1
    assert monitor._renewal_milestone(0) == 1
    assert monitor._renewal_milestone(-1) is None


def test_renewal_reminder_schema_tracks_each_recipient_once(tmp_path):
    spec = importlib.util.spec_from_file_location("admin_db", ADMIN / "db.py")
    db = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(db)
    db.DB_PATH = str(tmp_path / "customers.db")
    db.init_db()
    with db.get_conn() as conn:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(renewal_reminders)")}
        assert {"customer_id", "days_before", "recipient", "recipient_type", "sent_at"} <= columns
        conn.execute("INSERT INTO customers (id,name,created_at) VALUES ('acme','Acme','2026-01-01')")
        conn.execute(
            "INSERT INTO renewal_reminders (customer_id,days_before,recipient,recipient_type,sent_at) "
            "VALUES ('acme',90,'admin@acme.example','customer','2026-01-01')"
        )
        try:
            conn.execute(
                "INSERT INTO renewal_reminders (customer_id,days_before,recipient,recipient_type,sent_at) "
                "VALUES ('acme',90,'admin@acme.example','customer','2026-01-01')"
            )
        except Exception:
            pass
        else:
            raise AssertionError("duplicate renewal delivery was accepted")
