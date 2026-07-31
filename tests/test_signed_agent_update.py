import base64
import hashlib
import json

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
    data, signature = _signed_manifest(release_key, version=agent.VERSION)
    requests = []

    def fake_read(url, headers, timeout=60):
        requests.append(url)
        return data if url.endswith('manifest.json') else signature

    monkeypatch.setattr(agent, '_read_update_url', fake_read)

    assert agent.self_update({'server': 'https://updates.example.test', 'token': 'test'}) is False
    assert requests == [
        'https://updates.example.test/releases/current/manifest.json',
        'https://updates.example.test/releases/current/manifest.sig',
    ]


def test_self_update_rejects_non_https_server_without_fetching(monkeypatch):
    monkeypatch.setattr(agent, '_read_update_url', lambda *args: pytest.fail('must not fetch'))

    assert agent.self_update({'server': 'http://updates.example.test'}) is False
