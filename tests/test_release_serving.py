from pathlib import Path

import server


def test_release_file_resolves_only_within_static_release_directory(tmp_path, monkeypatch):
    release_dir = tmp_path / 'releases' / 'current'
    release_dir.mkdir(parents=True)
    artifact = release_dir / 'manifest.json'
    artifact.write_bytes(b'{}')
    monkeypatch.setattr(server, 'RELEASE_DIR', release_dir)

    assert server._release_file('/releases/current/manifest.json') == artifact
    assert server._release_file('/releases/current/../agent.py') is None
    assert server._release_file('/releases/current/%2e%2e/agent.py') is None
    assert server._release_file('/releases/current/') is None


def test_release_route_is_agent_bearer_gated(monkeypatch):
    handler = server._Handler.__new__(server._Handler)
    handler.path = '/releases/current/manifest.json'
    served = []
    monkeypatch.setattr(handler, '_get_agent_customer', lambda: {'id': 'customer'})
    monkeypatch.setattr(handler, '_serve_release_file', lambda path: served.append(path))

    handler._do_GET_inner()

    assert served == ['/releases/current/manifest.json']

    denied = []
    monkeypatch.setattr(handler, '_get_agent_customer', lambda: None)
    monkeypatch.setattr(handler, '_send', lambda status, body, content_type: denied.append(status))
    handler._do_GET_inner()

    assert denied == [401]
