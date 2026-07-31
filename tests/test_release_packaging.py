import base64
import hashlib
import tarfile

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import agent
from scripts import create_release, package_release


def test_release_package_is_allowlisted_and_signed_by_the_agent_key(tmp_path, monkeypatch):
    root = tmp_path / 'source'
    (root / 'dist').mkdir(parents=True)
    (root / 'profiles').mkdir()
    (root / 'dist' / 'agent').write_bytes(b'agent')
    (root / 'dist' / 'audit').write_bytes(b'audit')
    (root / 'profiles' / 'default.json').write_text('{}')
    (root / 'output').mkdir()
    (root / 'output' / 'secret.txt').write_text('must not ship')
    (root / 'secrets.txt').write_text('must not ship')

    artifact = tmp_path / 'sentinel-agent-1.0.1-linux-amd64.tar.gz'
    package_release.package_release(root, artifact, platform_name='linux')

    with tarfile.open(artifact, 'r:gz') as archive:
        assert archive.getnames() == [
            'sentinel/agent',
            'sentinel/audit',
            'sentinel/profiles/default.json',
        ]
        assert all(member.isfile() for member in archive.getmembers())

    private_key = Ed25519PrivateKey.generate()
    public_der = private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    pinned_key = base64.b64encode(public_der).decode()
    monkeypatch.setattr(create_release, '_PINNED_PUBLIC_KEY_DER_B64', pinned_key)
    monkeypatch.setattr(agent, 'PINNED_UPDATE_PUBLIC_KEY_DER_B64', pinned_key)
    encoded_key = base64.b64encode(private_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )).decode()
    release_dir = tmp_path / 'releases' / 'linux'
    create_release.create_release(artifact, '1.0.1', release_dir, encoded_key, platform='linux')

    manifest = agent._validate_update_manifest(
        (release_dir / 'manifest.json').read_bytes(),
        (release_dir / 'manifest.sig').read_bytes(),
    )
    assert manifest['sha256'] == hashlib.sha256(artifact.read_bytes()).hexdigest()
    assert manifest['size'] == artifact.stat().st_size


def test_release_package_rejects_symlinked_inputs(tmp_path):
    root = tmp_path / 'source'
    (root / 'dist').mkdir(parents=True)
    (root / 'profiles').mkdir()
    target = root / 'outside-agent'
    target.write_bytes(b'agent')
    (root / 'dist' / 'agent').symlink_to(target)
    (root / 'dist' / 'audit').write_bytes(b'audit')
    (root / 'profiles' / 'default.json').write_text('{}')

    with pytest.raises(ValueError, match='regular file'):
        package_release.package_release(root, tmp_path / 'release.tar.gz', platform_name='linux')
