import pytest

from server import _build_fleet_html


@pytest.mark.parametrize('role', ['admin', 'customer_admin', 'super_admin', 'viewer', 'client_viewer'])
def test_governance_audit_is_admin_only_and_escaped(role):
    event = dict(changed_at=1, tool_name='<script>tool</script>', client_org_id='org-a',
                 old_status=None, new_status='sanctioned', changed_by='<img src=x>')
    page = _build_fleet_html([], current_user_role=role, ai_governance_audit=[event])
    assert '<script>tool</script>' not in page
    assert '<img src=x>' not in page
    if role in ('admin', 'customer_admin', 'super_admin'):
        assert 'Recent Governance Changes' in page
        assert '&lt;script&gt;tool&lt;/script&gt;' in page
        assert 'Agent default' in page
    else:
        assert 'Recent Governance Changes' not in page
