import agent


def test_update_check_runs_at_startup_and_hourly():
    assert agent._update_check_due(0.0, 1.0)
    assert not agent._update_check_due(100.0, 100.0 + agent._UPDATE_CHECK_INTERVAL - 1)
    assert agent._update_check_due(100.0, 100.0 + agent._UPDATE_CHECK_INTERVAL)
