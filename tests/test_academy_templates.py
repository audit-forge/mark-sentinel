from pathlib import Path

from academy import build


ROOT = Path(__file__).resolve().parents[1]


def test_academy_includes_customer_safe_policy_templates():
    page = build(ROOT, 'templates').decode('utf-8')

    assert 'AI Incident Response Plan' in page
    assert 'AI Data Retention Policy' in page
    assert 'AI Asset Inventory' in page
    assert 'AI Runtime Audit Configuration' in page
    assert 'M. F. Dynamics' not in page
