import agent


class _Response:
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


def test_ai_session_reporting_uses_configured_https_client(monkeypatch):
    captured = {}

    def fake_urlopen(request, timeout):
        captured['request'] = request
        captured['timeout'] = timeout
        return _Response()

    monkeypatch.setattr(agent, '_urlopen', fake_urlopen)
    assert agent._report_ai_sessions(
        [{'tool_name': 'OpenCode', 'duration_seconds': 60}],
        {'server': 'https://arckon.example', 'token': 'test-token'},
    )
    assert captured['request'].full_url == 'https://arckon.example/api/agent/ai-sessions'
    assert captured['request'].get_header('Authorization') == 'Bearer test-token'
    assert captured['timeout'] == 15


def test_active_ai_sessions_report_after_one_minute_then_every_five(monkeypatch):
    now = [1_000]
    reports = []
    agent._active_ai_sessions.clear()
    monkeypatch.setattr(agent.time, 'time', lambda: now[0])
    monkeypatch.setattr(agent.time, 'strftime', lambda *_args: '2026-09-24')
    monkeypatch.setattr(agent, '_device_id', lambda: 'device-1')
    monkeypatch.setattr(agent, '_scan_ai_tool_processes', lambda: [{
        'pid': 42,
        'tool_name': 'OpenCode',
        'tool_category': 'coding_assistant',
        'create_time': 900,
    }])
    monkeypatch.setattr(agent, '_report_ai_sessions', lambda sessions, _cfg: reports.append(sessions))

    agent.run_ai_session_cycle({})
    assert reports[-1][0]['duration_seconds'] == 100

    now[0] = 1_100
    agent.run_ai_session_cycle({})
    assert len(reports) == 1

    now[0] = 1_301
    agent.run_ai_session_cycle({})
    assert reports[-1][0]['duration_seconds'] == 401
    agent._active_ai_sessions.clear()
