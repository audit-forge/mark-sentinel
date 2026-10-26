"""Offline host workflow with disposable stores; Docker and ownership are simulated."""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from crypto import decrypt_field, encrypt_field
from scripts import upgrade_customer_security as upgrade
from scripts.migrate_field_encryption import migrate


@pytest.fixture
def host(tmp_path, monkeypatch):
    data_root = tmp_path / 'data'
    data = data_root / 'tenant'
    data.mkdir(parents=True)
    secrets = tmp_path / 'secrets'
    secrets.mkdir(mode=0o700)
    tenant_secrets = secrets / 'tenant'
    tenant_secrets.mkdir(mode=0o700)
    legacy = hashlib.sha256(b'arckon-dev-key-DO-NOT-USE-IN-PROD').digest()
    db = data / 'agents.db'
    # Keep WAL open to prove backups include committed, uncheckpointed records.
    conn = sqlite3.connect(db)
    conn.execute('PRAGMA journal_mode=WAL')
    for table in ('protected_paths', 'protected_paths_audit'):
        conn.execute(f'CREATE TABLE {table} (id INTEGER PRIMARY KEY, path TEXT)')
        conn.execute(f'INSERT INTO {table} VALUES (1, ?)', (encrypt_field('/private', legacy),))
    conn.commit()
    old_siem = json.dumps({'splunk': {'hec_token': encrypt_field('old-secret', legacy)}}).encode()
    calls = []
    ownership = []
    # Simulate Linux root/uid999 on unprivileged macOS without changing real IDs.
    monkeypatch.setattr(upgrade, 'os', SimpleNamespace(**{
        **{name: getattr(os, name) for name in dir(os)},
        'geteuid': lambda: 0, 'chown': lambda *args: ownership.append(args)}))
    real_stat = Path.stat

    def stat_path(path, *args, **kwargs):
        result = real_stat(path, *args, **kwargs)
        if path in (secrets, tenant_secrets):
            return SimpleNamespace(st_uid=0, st_mode=result.st_mode)
        return result

    monkeypatch.setattr(Path, 'stat', stat_path)
    real_private = upgrade.private_file
    monkeypatch.setattr(upgrade, 'private_file', lambda path, owner, mode:
                        real_private(path, os.geteuid(), mode))
    prepared = Mock()
    monkeypatch.setattr(upgrade, 'prepare', prepared)
    env = []

    def docker(*args):
        calls.append(args)
        if args[0] == 'inspect':
            return json.dumps([{'Config': {'Env': env}, 'State': {'Running': not any(
                c[0] == 'stop' for c in calls)}, 'Mounts': [{'Destination': '/app/data',
                'Source': str(data), 'Type': 'bind', 'RW': True}]}])
        if args[:2] == ('image', 'inspect'):
            return '[{"Id": "sha256:reviewed"}]'
        if '--help' in args or args[0] == 'stop':
            return ''
        if upgrade.BACKUP in args:
            directory = tenant_secrets / Path(args[-1]).relative_to('/field-secrets')
            directory.mkdir(mode=0o700)
            with sqlite3.connect(directory / 'database.sqlite') as target:
                conn.backup(target)
            shutil.copyfile(data / 'siem_config.json', directory / 'siem_config.json')
            return ''
        if '--new-key-file' in args:
            key = tenant_secrets / 'master-key'
            backup = (tenant_secrets / Path(args[-1]).relative_to('/field-secrets')
                      if '--apply' in args else None)
            counts = migrate(db, data / 'siem_config.json', key,
                             apply='--apply' in args, legacy_dev_key=True, backup_dir=backup)
            return 'Check passed: ' + json.dumps(counts)
        assert '999:999' in args
        assert ownership[-1] == (tenant_secrets / 'master-key', 999, 999)
        assert (tenant_secrets / 'master-key').stat().st_mode & 0o777 == 0o400
        return ''

    def copy(args, **kwargs):
        assert args[:2] == ['docker', 'cp']
        Path(args[-1]).write_bytes(old_siem)
        return SimpleNamespace(returncode=0, stdout='', stderr='')

    monkeypatch.setattr(upgrade, 'docker', docker)
    monkeypatch.setattr(upgrade.subprocess, 'run', copy)
    yield SimpleNamespace(**locals())
    conn.close()


def test_offline_migration_preserves_siem_backup_and_hands_off_key(host):
    h = host
    upgrade.upgrade('tenant', 'reviewed', h.data_root, h.secrets,
                    maintenance=True, legacy_dev_key=True)
    key = base64.b64decode((h.tenant_secrets / 'master-key').read_bytes())
    cfg = json.loads((h.data / 'siem_config.json').read_bytes())
    assert decrypt_field(cfg['splunk']['hec_token'], key) == 'old-secret'
    assert decrypt_field(h.conn.execute('SELECT path FROM protected_paths').fetchone()[0], key) == '/private'
    backup = next(h.tenant_secrets.glob('upgrade-*/before'))
    assert (backup / 'siem_config.json').read_bytes() == h.old_siem
    with sqlite3.connect(backup / 'database.sqlite') as saved:
        assert decrypt_field(saved.execute('SELECT path FROM protected_paths').fetchone()[0], h.legacy) == '/private'
    assert h.prepared.call_count == 1
    assert [c[0] for c in h.calls].count('stop') == 1
    assert not any(c[0] in ('restart', 'rm', 'cp') for c in h.calls)


def test_conflicting_siem_is_not_overwritten(host):
    h = host
    config = h.data / 'siem_config.json'
    config.write_bytes(b'{"different": true}')
    with pytest.raises(ValueError, match='Conflicting'):
        upgrade.upgrade('tenant', 'reviewed', h.data_root, h.secrets,
                        maintenance=True, legacy_dev_key=True)
    assert config.read_bytes() == b'{"different": true}'
    assert not (h.tenant_secrets / 'master-key').exists()
    h.prepared.assert_not_called()


@pytest.mark.parametrize('env', [['ARCKON_MASTER_KEY=DO-NOT-PRINT'], ['ARCKON_MASTER_KEY_FILE=/secret']])
def test_configured_key_is_never_assumed_legacy(host, env, capsys):
    h = host
    h.env.extend(env)
    with pytest.raises(ValueError, match='Configured key'):
        upgrade.upgrade('tenant', 'reviewed', h.data_root, h.secrets,
                        maintenance=True, legacy_dev_key=True)
    assert not any(c[0] == 'stop' for c in h.calls)
    assert 'DO-NOT-PRINT' not in capsys.readouterr().out


def test_explicit_authorization_required_before_docker(host):
    with pytest.raises(ValueError, match='explicit'):
        upgrade.upgrade('tenant', 'reviewed', host.data_root, host.secrets,
                        maintenance=True, legacy_dev_key=False)
    assert not host.calls


@pytest.mark.parametrize('kind', ['runtime-key', 'public-key', 'pending'])
def test_key_ownership_preflight_leaves_tenant_untouched(host, kind):
    key = host.tenant_secrets / 'master-key'
    if kind == 'pending':
        key.with_name('master-key.migration-pending').write_text('recovery required')
    else:
        key.write_text(os.urandom(32).hex())
        key.chmod(0o400 if kind == 'runtime-key' else 0o644)
    with pytest.raises(ValueError):
        upgrade.upgrade('tenant', 'reviewed', host.data_root, host.secrets,
                        maintenance=True, legacy_dev_key=True)
    assert not host.calls
    assert not host.ownership


def test_identical_persistent_siem_is_accepted(host):
    (host.data / 'siem_config.json').write_bytes(host.old_siem)
    upgrade.upgrade('tenant', 'reviewed', host.data_root, host.secrets,
                    maintenance=True, legacy_dev_key=True)
    assert host.prepared.call_count == 1


def test_copy_failure_is_not_treated_as_missing_siem(host, monkeypatch):
    monkeypatch.setattr(upgrade.subprocess, 'run', lambda *args, **kwargs:
                        SimpleNamespace(returncode=1, stderr='daemon unavailable'))
    with pytest.raises(RuntimeError, match='preserve old SIEM'):
        upgrade.upgrade('tenant', 'reviewed', host.data_root, host.secrets,
                        maintenance=True, legacy_dev_key=True)
    assert not (host.data / 'siem_config.json').exists()
    assert not host.ownership


def test_failed_verification_never_hands_off(host, monkeypatch):
    real = upgrade.docker
    checks = 0

    def fail(*args):
        nonlocal checks
        if '--check' in args:
            checks += 1
            if checks == 2:
                raise RuntimeError('verification failed')
        return real(*args)

    monkeypatch.setattr(upgrade, 'docker', fail)
    with pytest.raises(RuntimeError, match='verification'):
        upgrade.upgrade('tenant', 'reviewed', host.data_root, host.secrets,
                        maintenance=True, legacy_dev_key=True)
    assert not host.ownership
    assert (host.tenant_secrets / 'master-key').stat().st_mode & 0o777 == 0o600
    host.prepared.assert_not_called()


@pytest.mark.parametrize('script', ['scripts/arckon-deploy.sh', 'deploy/gcp/deployer/deploy.sh'])
def test_hotpatch_scripts_fail_before_any_deployment(script):
    result = subprocess.run(['bash', str(Path(__file__).resolve().parents[1] / script)],
                            capture_output=True, text=True)
    assert result.returncode == 1
    assert ('upgrade_customer_security.py' in result.stderr
            or 'approved signed-image promotion workflow' in result.stderr)
    assert 'No files copied or containers restarted' in result.stderr
