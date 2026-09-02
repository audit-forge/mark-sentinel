import base64
import hashlib
import io
import json
import tarfile

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import agent


def _signed_manifest(private_key, **overrides):
    manifest = {
        'artifact': 'sentinel.tar.gz',
        'product': 'sentinel-agent',
        'sha256': hashlib.sha256(b'update').hexdigest(),
        'size': 6,
        'version': '1.0.1',
        'platform': 'linux',
    }
    manifest.update(overrides)
    data = json.dumps(manifest, sort_keys=True, separators=(',', ':')).encode()
    return data, private_key.sign(data)


@pytest.fixture
def release_key(monkeypatch):
    private_key = Ed25519PrivateKey.generate()
    public_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    monkeypatch.setattr(agent, 'PINNED_UPDATE_PUBLIC_KEY_DER_B64', base64.b64encode(public_der).decode())
    return private_key


def test_valid_signed_manifest_is_accepted(release_key):
    data, signature = _signed_manifest(release_key)

    assert agent._validate_update_manifest(data, signature)['artifact'] == 'sentinel.tar.gz'


@pytest.mark.parametrize('overrides', [
    {'product': 'other-agent'},
    {'artifact': '../outside.tar.gz'},
    {'artifact': 'nested\\outside.tar.gz'},
    {'sha256': 'A' * 64},
    {'size': True},
    {'version': '1.0'},
    {'platform': 'invalid'},
])
def test_manifest_schema_and_fields_are_strict(release_key, overrides):
    data, signature = _signed_manifest(release_key, **overrides)

    with pytest.raises(ValueError):
        agent._validate_update_manifest(data, signature)


def test_tampered_manifest_is_rejected(release_key):
    data, signature = _signed_manifest(release_key)

    with pytest.raises(ValueError, match='signature'):
        agent._validate_update_manifest(data.replace(b'1.0.1', b'9.9.9'), signature)


def test_noncanonical_signed_manifest_is_rejected(release_key):
    data, _ = _signed_manifest(release_key)
    manifest = json.loads(data)
    noncanonical = json.dumps(manifest, indent=2).encode()

    with pytest.raises(ValueError, match='canonical'):
        agent._validate_update_manifest(noncanonical, release_key.sign(noncanonical))


def test_self_update_rejects_equal_or_older_release_before_artifact_download(release_key, monkeypatch):
    import platform as _platform
    monkeypatch.setattr(_platform, 'system', lambda: 'Linux')
    data, signature = _signed_manifest(release_key, version=agent.VERSION)
    requests = []

    def fake_read(url, headers, timeout=60):
        requests.append(url)
        return data if url.endswith('manifest.json') else signature

    monkeypatch.setattr(agent, '_read_update_url', fake_read)

    assert agent.self_update({'server': 'https://updates.example.test', 'token': 'test'}) is False
    assert requests == [
        'https://updates.example.test/releases/linux/manifest.json',
        'https://updates.example.test/releases/linux/manifest.sig',
    ]


def test_self_update_rejects_non_https_server_without_fetching(monkeypatch):
    monkeypatch.setattr(agent, '_read_update_url', lambda *args: pytest.fail('must not fetch'))

    assert agent.self_update({'server': 'http://updates.example.test'}) is False


def test_signed_update_opener_uses_the_agent_ca_context(monkeypatch):
    captured = {}

    class Opener:
        def open(self, request, timeout):
            captured['request'] = request
            captured['timeout'] = timeout
            return type('Response', (), {
                '__enter__': lambda self: self,
                '__exit__': lambda self, *args: None,
                'status': 200,
                'read': lambda self: b'ok',
            })()

    def build_opener(*handlers):
        captured['handlers'] = handlers
        return Opener()

    monkeypatch.setattr(agent._urlreq, 'build_opener', build_opener)

    assert agent._read_update_url('https://updates.example.test/manifest.json', {}) == b'ok'
    https_handler = next(h for h in captured['handlers'] if isinstance(h, agent._urlreq.HTTPSHandler))
    assert https_handler._context is agent._HTTPS_CONTEXT


def test_self_update_stages_and_activates_windows_executable(release_key, monkeypatch, tmp_path):
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode='w:gz') as tar:
        info = tarfile.TarInfo('sentinel/agent.exe')
        payload = b'new windows agent'
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    artifact = archive.getvalue()
    data, signature = _signed_manifest(
        release_key,
        artifact='agent.tar.gz',
        sha256=hashlib.sha256(artifact).hexdigest(),
        size=len(artifact),
        version='9.9.9',
        platform='windows',
    )
    monkeypatch.setattr(agent.platform, 'system', lambda: 'Windows')
    monkeypatch.setattr(agent.sys, 'platform', 'win32')
    monkeypatch.setattr(agent, 'ROOT', tmp_path)
    monkeypatch.setattr(
        agent,
        '_read_update_url',
        lambda url, headers, timeout=60: (
            data if url.endswith('manifest.json') else signature
            if url.endswith('manifest.sig') else artifact
        ),
    )
    activated = []
    monkeypatch.setattr(
        agent,
        '_restart_windows_service_after_update',
        lambda staged, live: activated.append((staged, live)) or True,
    )

    assert agent.self_update({'server': 'https://updates.example.test'}) is True
    assert (tmp_path / 'agent.exe.new').read_bytes() == b'new windows agent'
    assert activated == [(tmp_path / 'agent.exe.new', tmp_path / 'agent.exe')]


def test_self_update_uses_the_packaged_windows_agent_filename(release_key, monkeypatch, tmp_path):
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode='w:gz') as tar:
        info = tarfile.TarInfo('sentinel/agent')
        payload = b'new windows agent without extension'
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    artifact = archive.getvalue()
    data, signature = _signed_manifest(
        release_key,
        artifact='agent.tar.gz',
        sha256=hashlib.sha256(artifact).hexdigest(),
        size=len(artifact),
        version='9.9.9',
        platform='windows',
    )
    monkeypatch.setattr(agent.platform, 'system', lambda: 'Windows')
    monkeypatch.setattr(agent.sys, 'platform', 'win32')
    monkeypatch.setattr(agent, 'ROOT', tmp_path)
    monkeypatch.setattr(
        agent,
        '_read_update_url',
        lambda url, headers, timeout=60: (
            data if url.endswith('manifest.json') else signature
            if url.endswith('manifest.sig') else artifact
        ),
    )
    activated = []
    monkeypatch.setattr(
        agent,
        '_restart_windows_service_after_update',
        lambda staged, live: activated.append((staged, live)) or True,
    )

    assert agent.self_update({'server': 'https://updates.example.test'}) is True
    assert activated == [(tmp_path / 'agent.new', tmp_path / 'agent')]


def test_restore_agent_binary_repairs_missing_live_from_staged(tmp_path, monkeypatch):
    monkeypatch.setattr(agent.sys, 'platform', 'win32')
    (tmp_path / 'agent.exe.new').write_bytes(b'staged binary')
    old_root = agent.ROOT
    try:
        agent.ROOT = tmp_path
        assert agent._restore_agent_binary() is True
        assert (tmp_path / 'agent.exe').read_bytes() == b'staged binary'
    finally:
        agent.ROOT = old_root


def test_restore_agent_binary_repairs_missing_live_from_backup(tmp_path, monkeypatch):
    monkeypatch.setattr(agent.sys, 'platform', 'win32')
    (tmp_path / 'agent.exe.bak').write_bytes(b'backup binary')
    old_root = agent.ROOT
    try:
        agent.ROOT = tmp_path
        assert agent._restore_agent_binary() is True
        assert (tmp_path / 'agent.exe').read_bytes() == b'backup binary'
    finally:
        agent.ROOT = old_root


def test_restore_agent_binary_is_noop_when_live_exists(tmp_path, monkeypatch):
    monkeypatch.setattr(agent.sys, 'platform', 'win32')
    (tmp_path / 'agent.exe').write_bytes(b'live binary')
    (tmp_path / 'agent.exe.new').write_bytes(b'staged binary')
    old_root = agent.ROOT
    try:
        agent.ROOT = tmp_path
        assert agent._restore_agent_binary() is True
        assert (tmp_path / 'agent.exe').read_bytes() == b'live binary'
    finally:
        agent.ROOT = old_root


def test_windows_update_activation_creates_backup_and_script(tmp_path, monkeypatch):
    monkeypatch.setattr(agent.sys, 'platform', 'win32')
    monkeypatch.setattr(agent, 'ROOT', tmp_path)
    staged = tmp_path / 'agent.exe.new'
    live = tmp_path / 'agent.exe'
    staged.write_bytes(b'new windows agent')
    live.write_bytes(b'old windows agent')

    # Prevent the script from actually executing by patching Popen.
    executed = []
    monkeypatch.setattr(
        agent.subprocess,
        'Popen',
        lambda *args, **kwargs: executed.append((args, kwargs)) or type('P', (), {'pid': 123})(),
    )

    assert agent._restart_windows_service_after_update(staged, live) is True
    backup = tmp_path / 'agent.exe.bak'
    assert backup.exists() and backup.read_bytes() == b'old windows agent'
    script = tmp_path / 'activate-agent-update.cmd'
    assert script.exists()
    script_text = script.read_text(encoding='utf-8')
    assert 'move /y' in script_text
    assert 'copy /y "%BACKUP%" "%LIVE%"' in script_text
    assert 'sc start ArckonAgent' in script_text
    assert len(executed) == 1
