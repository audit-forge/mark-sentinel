from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
APP_SOURCE = (REPO / "admin" / "app.py").read_text()
TEMPLATE_SOURCE = (REPO / "admin" / "templates" / "communications.html").read_text()


def test_communications_are_super_admin_only_and_use_active_customer_admins():
    assert '@app.get("/communications"' in APP_SOURCE
    assert '@app.post("/communications/send")' in APP_SOURCE
    assert "require_super_admin(request)" in APP_SOURCE
    assert "role='customer_admin' AND active=1" in APP_SOURCE


def test_communications_validate_and_audit_each_send():
    assert 'template not in {"general", "maintenance", "renewal"}' in APP_SOURCE
    assert '"\\n" in subject or "\\r" in subject' in APP_SOURCE
    assert '"customer_communication_sent"' in APP_SOURCE
    assert "send_communication(recipient, subject, message)" in APP_SOURCE


def test_communications_include_prebuilt_renewal_and_maintenance_templates():
    assert "Renewal reminder" in TEMPLATE_SOURCE
    assert "Scheduled maintenance notice" in TEMPLATE_SOURCE
    assert "Send Test Email" in TEMPLATE_SOURCE
