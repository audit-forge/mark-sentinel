from pathlib import Path

import agent


def test_windows_scan_prefers_packaged_audit_executable(monkeypatch, tmp_path):
    (tmp_path / 'audit.exe').write_bytes(b'audit')
    monkeypatch.setattr(agent, 'ROOT', tmp_path)
    monkeypatch.setattr(agent.sys, 'platform', 'win32')
    captured = {}

    class Result:
        returncode = 0
        stdout = '{"mark_sentinel_version":"1.0.6"}'
        stderr = ''

    def fake_run(command, **kwargs):
        captured['command'] = command
        return Result()

    monkeypatch.setattr(agent.subprocess, 'run', fake_run)

    # os.access is platform-dependent in this test; only the chosen command matters.
    monkeypatch.setattr(agent.os, 'access', lambda path, mode: Path(path).name == 'audit.exe')
    assert agent.run_scan(r'C:\Users\kferg', 'default')['mark_sentinel_version'] == '1.0.6'
    assert captured['command'][0] == str(tmp_path / 'audit.exe')
