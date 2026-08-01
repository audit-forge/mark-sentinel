import agent


def _finding(check_id, evidence):
    return {
        'check_id': check_id,
        'status': 'WARN',
        'details': check_id,
        'evidence': evidence,
    }


def test_windows_profile_dirs_excludes_templates_and_system_profiles(tmp_path):
    users = tmp_path / 'Users'
    users.mkdir()
    for name in ('Keith', 'Analyst', 'Default', 'Public', 'systemprofile'):
        (users / name).mkdir()

    assert [path.name for path in agent._windows_profile_dirs(users)] == ['Analyst', 'Keith']


def test_default_windows_scan_targets_all_user_profiles(monkeypatch, tmp_path):
    profiles = [tmp_path / 'Analyst', tmp_path / 'Keith']
    monkeypatch.setattr(agent.sys, 'platform', 'win32')
    monkeypatch.setattr(agent, '_windows_profile_dirs', lambda: profiles)

    assert agent._scan_targets({'target': '~'}) == [str(profile) for profile in profiles]
    assert agent._scan_targets({'target': r'C:\Specific\Project'}) == [r'C:\Specific\Project']


def test_merge_reports_keeps_each_profile_inventory_evidence():
    first = {
        'profile': 'default',
        'findings': [_finding('AI-SUPPLY-005', ['Models detected: gpt-4o (floating)'])],
        'inventory_findings': [_finding('AI-SUPPLY-005', ['Models detected: gpt-4o (floating)'])],
        'summary': {},
    }
    second = {
        'profile': 'default',
        'findings': [_finding('AI-SUPPLY-005', ['Models detected: claude-3-5-sonnet (pinned)'])],
        'inventory_findings': [_finding('AI-SUPPLY-005', ['Models detected: claude-3-5-sonnet (pinned)'])],
        'summary': {},
    }

    merged = agent._merge_reports([first, second])

    assert len(merged['inventory_findings']) == 2
    assert merged['inventory_findings'][1]['evidence'] == [
        'Models detected: claude-3-5-sonnet (pinned)'
    ]
