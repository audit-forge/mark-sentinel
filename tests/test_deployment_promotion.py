import argparse
import base64
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts import create_release
from scripts import promote_deployment as promotion


REPO = Path(__file__).resolve().parents[1]


def build_catalog(key, directory, release_version):
    directory.mkdir()
    for platform in promotion.PLATFORMS:
        parent = directory / platform
        parent.mkdir()
        artifact_name = next(name.split('/')[1] for name in promotion.catalog_files(release_version)
                             if name.startswith(platform + '/') and name.endswith('.tar.gz'))
        artifact = parent / artifact_name
        artifact.write_bytes((platform + release_version + '-agent-archive').encode())
        value = {'product': 'sentinel-agent', 'version': release_version, 'platform': platform,
                 'artifact': artifact.name, 'size': artifact.stat().st_size, 'sha256': promotion.digest(artifact)}
        raw = promotion.canonical(value)
        (parent / 'manifest.json').write_bytes(raw)
        (parent / 'manifest.sig').write_bytes(key.sign(raw))


def refresh_catalog(release, value):
    key, args = release
    directory = args.directory / ('catalog-' + value['version'])
    build_catalog(key, directory, value['version'])
    archive = args.directory / 'catalog.tar.gz'
    promotion.pack_catalog(directory, archive, value['version'])
    value['catalog'] = {'archive': archive.name, 'size': archive.stat().st_size, 'sha256': promotion.digest(archive)}


@pytest.fixture
def release(tmp_path, monkeypatch):
    key = Ed25519PrivateKey.generate()
    pin = base64.b64encode(key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
    monkeypatch.setattr(promotion, '_PINNED_PUBLIC_KEY_DER_B64', pin)
    monkeypatch.setenv('ARCKON_RELEASE_SIGNING_KEY', base64.b64encode(key.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption())).decode())
    directory = tmp_path / 'artifacts'
    directory.mkdir()
    for role in ('tenant', 'admin'):
        (directory / (role + '.docker.tar.gz')).write_bytes((role + '-complete-image').encode())
    args = argparse.Namespace(directory=directory, revision='a' * 40, version='1.2.3',
                              tenant_image='sha256:' + '1' * 64, admin_image='sha256:' + '2' * 64)
    build_catalog(key, directory / 'catalog-source', args.version)
    promotion.pack_catalog(directory / 'catalog-source', directory / 'catalog.tar.gz', args.version)
    promotion.create(args)
    return key, args


def manifest(release):
    return json.loads((release[1].directory / 'manifest.json').read_bytes())


def resign(release, value):
    raw = promotion.canonical(value)
    (release[1].directory / 'manifest.json').write_bytes(raw)
    (release[1].directory / 'manifest.sig').write_bytes(release[0].sign(raw))


@pytest.fixture
def host(release, tmp_path, monkeypatch):
    state = tmp_path / 'state'
    state.mkdir(mode=0o700)
    args = argparse.Namespace(bucket='gs://arckon-deploy-artifacts', state_dir=state)
    catalog_root = tmp_path / 'releases'
    catalog_root.mkdir()
    monkeypatch.setattr(promotion, 'CATALOG_ROOT', catalog_root)
    build_catalog(release[0], catalog_root / 'v1.2.2', '1.2.2')
    for name, target in promotion.catalog_links('1.2.2').items():
        (catalog_root / name).symlink_to(target)
    monkeypatch.setattr(promotion.os, 'geteuid', lambda: 0)
    # Tests may run as an unprivileged CI user. Preserve all other stat checks.
    original_stat = Path.stat

    def host_stat(path, *a, **kw):
        result = original_stat(path, *a, **kw)
        if path in (state, catalog_root):
            import os
            values = list(result)
            values[4] = 0
            return os.stat_result(values)
        return result

    monkeypatch.setattr(Path, 'stat', host_stat)
    calls = []
    real_popen = subprocess.Popen

    def popen(argv, **kwargs):
        calls.append(argv)
        assert argv[:2] == ['gsutil', 'cat']
        name = argv[2].rsplit('/', 1)[-1]
        assert argv[2].startswith(args.bucket + '/')
        data = (release[1].directory / name).read_bytes()
        # Exercise the real bounded streaming reader without a cloud connection.
        return real_popen([sys.executable, '-c', 'import sys; sys.stdout.buffer.write(' + repr(data) + ')'], **kwargs)

    def run(argv, **kwargs):
        calls.append(argv)
        if argv[:3] == ['docker', 'image', 'inspect']:
            return subprocess.CompletedProcess(argv, 0, stdout=argv[-1] + '\n')
        if len(argv) > 1 and argv[1] == '/opt/sentinel/scripts/deploy_images.py':
            value = manifest(release)
            promotion.served_catalog(value)
            promotion.save(state / 'successful.json', {
                'status': 'succeeded', 'revision': value['revision'],
                'tenant_image': value['images']['tenant']['id'],
                'admin_image': value['images']['admin']['id']})
        else:
            assert argv[:2] == ['docker', 'load']
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(promotion.subprocess, 'Popen', popen)
    monkeypatch.setattr(promotion.subprocess, 'run', run)
    return args, calls


def mutations(calls):
    return [call for call in calls if call[0] != 'gsutil']


def test_pin_matches_existing_agent_trust_root():
    assert promotion._PINNED_PUBLIC_KEY_DER_B64 == create_release._PINNED_PUBLIC_KEY_DER_B64
    assert promotion._PINNED_PUBLIC_KEY_DER_B64 in (REPO / 'agent.py').read_text()


def test_create_verify_and_wrong_key_never_logged(release, monkeypatch, capsys):
    directory = release[1].directory
    assert promotion.main(['verify', '--directory', str(directory)]) == 0
    secret = 'secret-not-a-valid-private-key'
    monkeypatch.setenv('ARCKON_RELEASE_SIGNING_KEY', secret)
    assert promotion.main(['create', '--directory', str(directory), '--revision', 'a' * 40,
                           '--version', '1.2.3', '--tenant-image', 'sha256:' + '1' * 64,
                           '--admin-image', 'sha256:' + '2' * 64]) == 1
    assert secret not in capsys.readouterr().err


def test_signing_requires_existing_pin_not_just_valid_ed25519(release, monkeypatch):
    foreign = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode()
    monkeypatch.setenv('ARCKON_RELEASE_SIGNING_KEY', foreign)
    with pytest.raises(ValueError):
        promotion.create(release[1])


def test_successful_poll_and_same_revision_noop(release, host):
    args, calls = host
    promotion.poll(args)
    assert [call[:2] for call in mutations(calls)][:2] == [['docker', 'load'], ['docker', 'load']]
    engine = [call for call in calls if 'deploy_images.py' in ' '.join(call)]
    assert len(engine) == 1
    assert '--revision' in engine[0] and '--tenant-image' in engine[0] and '--admin-image' in engine[0]
    assert (args.state_dir / 'applied.json').exists()
    calls.clear()
    promotion.poll(args)
    assert not mutations(calls)
    assert not any('latest/manifest.json' in ' '.join(call) for call in calls)


@pytest.mark.parametrize('kind', ['manifest', 'signature', 'tenant', 'admin', 'pointer'])
def test_tamper_never_loads_or_deploys(release, host, kind):
    args, calls = host
    names = {'manifest': 'manifest.json', 'signature': 'manifest.sig',
             'tenant': 'tenant.docker.tar.gz', 'admin': 'admin.docker.tar.gz', 'pointer': 'deployment.json'}
    path = release[1].directory / names[kind]
    path.write_bytes(path.read_bytes() + b'x')
    with pytest.raises(Exception):
        promotion.poll(args)
    assert not mutations(calls)
    assert not (args.state_dir / 'applied.json').exists()


@pytest.mark.parametrize('kind', ['path', 'url', 'size', 'bool-size', 'image', 'revision', 'version', 'future', 'extra', 'missing-admin'])
def test_signed_invalid_schema_fails_before_docker(release, host, kind):
    value = manifest(release)
    if kind == 'path':
        value['images']['tenant']['archive'] = '../tenant.docker.tar.gz'
    elif kind == 'url':
        value['images']['tenant']['archive'] = 'gs://attacker/image'
    elif kind == 'size':
        value['images']['admin']['size'] = promotion.MAX_ARCHIVE + 1
    elif kind == 'bool-size':
        value['images']['admin']['size'] = True
    elif kind == 'image':
        value['images']['tenant']['id'] = 'latest'
    elif kind == 'revision':
        value['revision'] = 'b' * 40
    elif kind == 'version':
        value['version'] = 'v1.2.3'
    elif kind == 'future':
        value['created'] = '2999-01-01T00:00:00Z'
    elif kind == 'extra':
        value['script'] = 'execute-me'
    else:
        del value['images']['admin']
    resign(release, value)
    with pytest.raises(Exception):
        promotion.poll(host[0])
    assert not mutations(host[1])


def test_noncanonical_and_foreign_signatures_rejected(release):
    value = manifest(release)
    raw = json.dumps(value, indent=2).encode()
    with pytest.raises(ValueError):
        promotion.verify(raw, release[0].sign(raw))
    raw = promotion.canonical(value)
    with pytest.raises(Exception):
        promotion.verify(raw, Ed25519PrivateKey.generate().sign(raw))


@pytest.mark.parametrize('kind', ['older-time', 'same-version', 'older-version', 'same-revision-changed'])
def test_replay_rejected(release, host, kind):
    args, calls = host
    promotion.poll(args)
    calls.clear()
    value = manifest(release)
    value['revision'] = 'b' * 40
    if kind == 'older-time':
        value['version'] = '1.2.4'
        value['created'] = '2020-01-01T00:00:00Z'
    elif kind == 'older-version':
        value['version'] = '1.2.2'
    elif kind == 'same-revision-changed':
        value['revision'] = 'a' * 40
        value['version'] = '1.2.4'
    resign(release, value)
    (release[1].directory / 'deployment.json').write_bytes(promotion.canonical({'revision': value['revision']}))
    with pytest.raises(ValueError):
        promotion.poll(args)
    assert not mutations(calls)


def test_load_identity_failure_never_deploys(release, host, monkeypatch):
    original = promotion.subprocess.run

    def wrong_id(argv, **kwargs):
        if argv[:3] == ['docker', 'image', 'inspect']:
            return subprocess.CompletedProcess(argv, 0, stdout='sha256:' + '0' * 64)
        return original(argv, **kwargs)

    monkeypatch.setattr(promotion.subprocess, 'run', wrong_id)
    with pytest.raises(ValueError):
        promotion.poll(host[0])
    assert not any('deploy_images.py' in ' '.join(call) for call in host[1])
    assert not (host[0].state_dir / 'applied.json').exists()


def test_equal_size_archive_hash_tamper_never_loads(release, host):
    path = release[1].directory / 'admin.docker.tar.gz'
    path.write_bytes(b'x' * path.stat().st_size)
    with pytest.raises(ValueError):
        promotion.poll(host[0])
    assert not mutations(host[1])


@pytest.mark.parametrize('stage', ['load', 'engine'])
def test_command_failure_does_not_advance_applied_state(release, host, monkeypatch, stage):
    original = promotion.subprocess.run

    def failure(argv, **kwargs):
        if (stage == 'load' and argv[:2] == ['docker', 'load']) or (
                stage == 'engine' and 'deploy_images.py' in ' '.join(argv)):
            raise subprocess.CalledProcessError(1, argv)
        return original(argv, **kwargs)

    monkeypatch.setattr(promotion.subprocess, 'run', failure)
    with pytest.raises(subprocess.CalledProcessError):
        promotion.poll(host[0])
    assert not (host[0].state_dir / 'applied.json').exists()
    assert (host[0].state_dir / 'pending.json').exists()
    # A failed candidate cannot be replaced by a lower-version signed release.
    value = manifest(release)
    value['revision'], value['version'] = 'b' * 40, '1.2.2'
    resign(release, value)
    (release[1].directory / 'deployment.json').write_bytes(promotion.canonical({'revision': value['revision']}))
    host[1].clear()
    with pytest.raises(ValueError):
        promotion.poll(host[0])
    assert not mutations(host[1])


def test_newer_version_and_timestamp_can_advance(release, host):
    value = manifest(release)
    value['created'] = '2020-01-01T00:00:00Z'
    resign(release, value)
    promotion.poll(host[0])
    value['revision'], value['version'], value['created'] = 'b' * 40, '1.2.4', '2021-01-01T00:00:00Z'
    refresh_catalog(release, value)
    resign(release, value)
    (release[1].directory / 'deployment.json').write_bytes(promotion.canonical({'revision': value['revision']}))
    promotion.poll(host[0])
    assert json.loads((host[0].state_dir / 'applied.json').read_bytes()) == value


def test_poll_lock_is_separate_and_exclusive(host):
    import fcntl
    args, calls = host
    with (args.state_dir / 'poll.lock').open('w') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(BlockingIOError):
            promotion.poll(args)
    assert not calls
    assert not (args.state_dir / 'deploy.lock').exists()


def test_root_and_bucket_boundaries(host, monkeypatch):
    args, calls = host
    args.bucket = 'https://attacker.invalid/bucket'
    with pytest.raises(ValueError):
        promotion.poll(args)
    args.bucket = 'gs://arckon-deploy-artifacts'
    monkeypatch.setattr(promotion.os, 'geteuid', lambda: 1000)
    with pytest.raises(ValueError):
        promotion.poll(args)
    assert not calls


def test_legacy_pointer_is_not_a_fallback(release, host):
    (release[1].directory / 'deployment.json').unlink()
    (release[1].directory / 'manifest.json').write_bytes(b'{"sha":"legacy-unsafe"}')
    with pytest.raises(FileNotFoundError):
        promotion.poll(host[0])
    assert not mutations(host[1])
    assert not any('latest/manifest.json' in ' '.join(call) for call in host[1])


def test_crash_after_engine_success_recovers_without_redeploy(release, host, monkeypatch):
    original = promotion.save

    def interrupted(path, value):
        if path.name == 'applied.json':
            raise OSError('simulated crash')
        original(path, value)

    monkeypatch.setattr(promotion, 'save', interrupted)
    with pytest.raises(OSError):
        promotion.poll(host[0])
    monkeypatch.setattr(promotion, 'save', original)
    host[1].clear()
    promotion.poll(host[0])
    assert not mutations(host[1])
    assert (host[0].state_dir / 'applied.json').exists()


def test_local_scripts_and_workflow_have_no_hotpatch():
    script = (REPO / 'scripts/arckon-deploy.sh').read_text()
    workflow = (REPO / '.github/workflows/deploy.yml').read_text()
    for unsafe in ('docker cp', 'docker restart', 'app.tar.gz', 'latest/manifest.json', 'pip install'):
        assert unsafe not in script
    assert 'app.tar.gz' not in workflow
    assert 'workflow_dispatch:' in workflow
    assert "inputs.confirm_gcp_upload == 'PROMOTE_SIGNED_RELEASE'" in workflow
    assert '--if-generation-match=0' in workflow
    assert workflow.index('--if-generation-match=0') < workflow.index('latest/deployment.json')
    assert 'ARCKON_RELEASE_SIGNING_KEY' in workflow
    assert 'refs/tags/${{ inputs.release_tag }}' in workflow
    assert '/opt/sentinel/venv/bin/python' in script
    assert '-r admin/requirements.txt pytest httpx' in workflow
    assert 'python -m pytest -q\n' in workflow
    assert 'SECRET_KEY: ci-only-' in workflow
    assert 'catalog.tar.gz manifest.json manifest.sig' in workflow


def live_links():
    return {name: os.readlink(promotion.CATALOG_ROOT / name) for name in (*promotion.PLATFORMS, 'current')}


def rewrite_catalog(release, kind):
    key, args = release
    members = []
    for name in sorted(promotion.catalog_files(args.version)):
        data = (args.directory / 'catalog-source' / name).read_bytes()
        info = tarfile.TarInfo(name)
        info.size = len(data)
        members.append((info, data))
    index = next(i for i, (info, _) in enumerate(members) if info.name == 'linux/manifest.json')
    info, data = members[index]
    if kind in ('signature', 'hash'):
        ending = 'manifest.sig' if kind == 'signature' else '.tar.gz'
        index = next(i for i, (info, _) in enumerate(members) if info.name.startswith('linux/') and info.name.endswith(ending))
        info, data = members[index]
        members[index] = (info, b'x' * len(data))
    elif kind in ('version', 'platform'):
        value = json.loads(data)
        value[kind] = '9.9.9' if kind == 'version' else 'windows'
        data = promotion.canonical(value)
        info.size = len(data)
        members[index] = (info, data)
        sig_index = next(i for i, (entry, _) in enumerate(members) if entry.name == 'linux/manifest.sig')
        members[sig_index] = (members[sig_index][0], key.sign(data))
    elif kind == 'duplicate':
        members.append(members[0])
    elif kind == 'missing':
        members.pop()
    elif kind == 'traversal':
        info.name = '../escape'
    elif kind == 'absolute':
        info.name = '/tmp/escape'
    elif kind == 'extra':
        info.name = 'linux/execute.py'
    elif kind in ('symlink', 'hardlink'):
        info.type = tarfile.SYMTYPE if kind == 'symlink' else tarfile.LNKTYPE
        info.linkname = '/tmp/escape'
        info.size = 0
    elif kind == 'directory':
        info.type, info.size = tarfile.DIRTYPE, 0
    archive_path = args.directory / 'catalog.tar.gz'
    if kind == 'oversize':
        import gzip
        info = tarfile.TarInfo('linux/manifest.json')
        info.size = 16385
        archive_path.write_bytes(gzip.compress(info.tobuf(format=tarfile.USTAR_FORMAT) + b'\x00' * 1024))
    else:
        with tarfile.open(archive_path, 'w:gz', format=tarfile.PAX_FORMAT if kind == 'pax' else tarfile.USTAR_FORMAT) as archive:
            for info, data in members:
                if kind == 'pax':
                    info.pax_headers = {'comment': 'untrusted extension'}
                archive.addfile(info, io.BytesIO(data))
    value = manifest(release)
    value['catalog'] = {'archive': archive_path.name, 'size': archive_path.stat().st_size,
                        'sha256': promotion.digest(archive_path)}
    resign(release, value)


@pytest.mark.parametrize('kind', ['traversal', 'absolute', 'extra', 'symlink', 'hardlink', 'directory',
                                 'duplicate', 'missing', 'pax', 'oversize', 'signature', 'hash', 'version', 'platform'])
def test_bad_catalog_never_changes_live_catalog_or_docker(release, host, kind):
    before = live_links()
    rewrite_catalog(release, kind)
    with pytest.raises(Exception):
        promotion.poll(host[0])
    assert not mutations(host[1])
    assert live_links() == before
    assert not (promotion.CATALOG_ROOT / 'v1.2.3').exists()
    assert not (host[0].state_dir / 'applied.json').exists()


@pytest.mark.parametrize('field,value', [('archive', '../catalog.tar.gz'), ('archive', 'gs://evil/catalog.tar.gz'),
                                       ('size', True), ('size', promotion.MAX_CATALOG + 1), ('sha256', 'invalid')])
def test_catalog_descriptor_is_strict(release, host, field, value):
    before = live_links()
    metadata = manifest(release)
    metadata['catalog'][field] = value
    resign(release, metadata)
    with pytest.raises(ValueError):
        promotion.poll(host[0])
    assert live_links() == before
    assert not mutations(host[1])


def test_catalog_outer_hash_checked_before_unpack(release, host):
    path = release[1].directory / 'catalog.tar.gz'
    path.write_bytes(b'x' * path.stat().st_size)
    before = live_links()
    with pytest.raises(ValueError):
        promotion.poll(host[0])
    assert live_links() == before
    assert not mutations(host[1])


def test_engine_failure_quarantines_revision_restores_catalog_and_allows_newer(release, host, monkeypatch):
    before = live_links()
    value = manifest(release)
    value['created'] = '2020-01-01T00:00:00Z'
    resign(release, value)
    original = promotion.subprocess.run

    def failure(argv, **kwargs):
        if 'deploy_images.py' in ' '.join(argv):
            promotion.served_catalog(value)
            raise subprocess.CalledProcessError(1, argv)
        return original(argv, **kwargs)

    monkeypatch.setattr(promotion.subprocess, 'run', failure)
    with pytest.raises(subprocess.CalledProcessError):
        promotion.poll(host[0])
    assert live_links() == before
    assert (host[0].state_dir / 'failed-revisions' / ('a' * 40 + '.json')).exists()
    for _ in range(2):
        host[1].clear()
        with pytest.raises(ValueError):
            promotion.poll(host[0])
        assert len(host[1]) == 1 and host[1][0][2].endswith('/latest/deployment.json')
        assert live_links() == before
    monkeypatch.setattr(promotion.subprocess, 'run', original)
    value['revision'], value['version'], value['created'] = 'b' * 40, '1.2.4', '2021-01-01T00:00:00Z'
    refresh_catalog(release, value)
    resign(release, value)
    (release[1].directory / 'deployment.json').write_bytes(promotion.canonical({'revision': value['revision']}))
    promotion.poll(host[0])
    promotion.served_catalog(value)
    assert json.loads((host[0].state_dir / 'applied.json').read_bytes()) == value


def test_success_requires_current_served_catalog_integrity(release, host):
    promotion.poll(host[0])
    host[1].clear()
    (promotion.CATALOG_ROOT / 'v1.2.3/linux/manifest.sig').write_bytes(b'x' * 64)
    with pytest.raises(Exception):
        promotion.poll(host[0])
    assert not mutations(host[1])


def test_partial_catalog_switch_crash_recovers_previous_links(release, host, monkeypatch):
    before = live_links()
    original = promotion.replace_links

    def crash(links):
        original({'linux': links['linux']})
        raise KeyboardInterrupt('simulated process death')

    monkeypatch.setattr(promotion, 'replace_links', crash)
    with pytest.raises(KeyboardInterrupt):
        promotion.poll(host[0])
    assert live_links() != before
    assert (host[0].state_dir / 'catalog-transaction.json').exists()
    monkeypatch.setattr(promotion, 'replace_links', original)
    promotion.save(host[0].state_dir / 'transaction.json', {'status': 'deploying'})
    host[1].clear()
    with pytest.raises(ValueError):
        promotion.poll(host[0])
    assert live_links() == before
    assert not mutations(host[1])
    assert not (host[0].state_dir / 'catalog-transaction.json').exists()


def test_legacy_real_catalog_directories_require_operator_migration(release, host):
    (promotion.CATALOG_ROOT / 'linux').unlink()
    (promotion.CATALOG_ROOT / 'linux').mkdir()
    with pytest.raises(ValueError):
        promotion.poll(host[0])
    assert (promotion.CATALOG_ROOT / 'linux').is_dir()
    assert not (promotion.CATALOG_ROOT / 'linux').is_symlink()
    assert not any('deploy_images.py' in ' '.join(call) for call in host[1])


def test_quarantine_survives_crash_during_catalog_rollback(release, host, monkeypatch):
    before = live_links()
    original_run = promotion.subprocess.run
    original_replace = promotion.replace_links

    def failure(argv, **kwargs):
        result = original_run(argv, **kwargs)
        if 'deploy_images.py' in ' '.join(argv):
            # Even a matching engine success marker cannot override quarantine.
            raise subprocess.CalledProcessError(1, argv)
        return result

    def interrupted_rollback(links):
        if links == before:
            original_replace({'linux': links['linux']})
            raise KeyboardInterrupt('simulated process death during rollback')
        original_replace(links)

    monkeypatch.setattr(promotion.subprocess, 'run', failure)
    monkeypatch.setattr(promotion, 'replace_links', interrupted_rollback)
    with pytest.raises(KeyboardInterrupt):
        promotion.poll(host[0])
    assert (host[0].state_dir / 'failed-revisions' / ('a' * 40 + '.json')).exists()
    assert (host[0].state_dir / 'catalog-transaction.json').exists()
    monkeypatch.setattr(promotion, 'replace_links', original_replace)
    host[1].clear()
    with pytest.raises(ValueError):
        promotion.poll(host[0])
    assert live_links() == before
    assert not mutations(host[1])
    assert len(host[1]) == 1
    assert not (host[0].state_dir / 'applied.json').exists()


def test_workflow_run_blocks_are_valid_bash():
    import yaml
    workflow = yaml.safe_load((REPO / '.github/workflows/deploy.yml').read_text())
    for step in workflow['jobs']['build-and-deploy']['steps']:
        if 'run' in step:
            result = subprocess.run(['bash', '-n'], input=step['run'], text=True, capture_output=True)
            assert result.returncode == 0, step['name'] + ': ' + result.stderr


def test_host_service_uses_supported_executable_condition():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    source = (root / 'deploy/gcp/arckon-deploy.service').read_text()
    assert 'ConditionFileIsExecutable=/opt/sentinel/venv/bin/python' in source
    assert 'ConditionPathIsExecutable' not in source
    assert 'NoNewPrivileges=true' in source
    assert 'PrivateTmp=true' in source
    assert source.index('/snap/google-cloud-cli/current/bin') < source.index(':/snap/bin')
