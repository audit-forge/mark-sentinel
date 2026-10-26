"""Fail-closed runtime keys and offline migration safety, using disposable data."""
import base64
import hashlib
import json
import os
from pathlib import Path
import sqlite3
from unittest.mock import patch

import pytest

import crypto
from connectors.siem_connector import load_siem_config, save_siem_config
from scripts.migrate_field_encryption import migrate
from storage import AgentStore


@pytest.fixture(autouse=True)
def isolated_keys(monkeypatch):
    monkeypatch.delenv('ARCKON_MASTER_KEY', raising=False)
    monkeypatch.delenv('ARCKON_MASTER_KEY_FILE', raising=False)


def test_missing_key_fails_closed():
    with pytest.raises(ValueError):
        crypto.encrypt_field('secret')
    ciphertext = crypto.encrypt_field('secret', b'a' * 32)
    with pytest.raises(ValueError):
        crypto.decrypt_field(ciphertext)


@pytest.mark.parametrize('value', ['', 'garbage', 'x' * 32, 'f' * 63,
                                  base64.b64encode(b'x' * 16).decode(), '\u00e9' * 32])
def test_invalid_env_never_falls_back(monkeypatch, value):
    monkeypatch.setenv('ARCKON_MASTER_KEY', value)
    with pytest.raises(ValueError):
        crypto._load_master_key()


@pytest.mark.parametrize('key', [b'', b'x' * 16, b'x' * 24, b'x' * 33, 'x' * 32])
def test_explicit_keys_require_256_bits(key):
    with pytest.raises(ValueError):
        crypto.encrypt_field('secret', key)
    with pytest.raises(ValueError):
        crypto.decrypt_field('legacy plaintext', key)


@pytest.mark.parametrize('encoding', ['hex', 'base64'])
def test_env_and_file_key(monkeypatch, tmp_path, encoding):
    key = os.urandom(32)
    encoded = key.hex() if encoding == 'hex' else base64.b64encode(key).decode()
    monkeypatch.setenv('ARCKON_MASTER_KEY', encoded)
    assert crypto._load_master_key() == key
    key_file = tmp_path / 'key'
    key_file.write_text(encoded + '\n')
    key_file.chmod(0o600)
    monkeypatch.setenv('ARCKON_MASTER_KEY_FILE', str(key_file))
    with pytest.raises(ValueError):
        crypto._load_master_key()
    monkeypatch.delenv('ARCKON_MASTER_KEY')
    assert crypto.decrypt_field(crypto.encrypt_field('secret')) == 'secret'
    key_file.chmod(0o644)
    with pytest.raises(ValueError):
        crypto._load_master_key()
    key_file.chmod(0o600)
    key_file.write_text('invalid')
    with pytest.raises(ValueError):
        crypto._load_master_key()
    key_file.unlink()
    with pytest.raises(OSError):
        crypto._load_master_key()


def test_key_file_rejects_symlink(monkeypatch, tmp_path):
    key = tmp_path / 'key'
    key.write_text(os.urandom(32).hex())
    key.chmod(0o600)
    link = tmp_path / 'link'
    link.symlink_to(key)
    monkeypatch.setenv('ARCKON_MASTER_KEY_FILE', str(link))
    with pytest.raises(OSError):
        crypto._load_master_key()


def test_siem_errors_visible_and_atomic_save(monkeypatch, tmp_path):
    config = tmp_path / 'siem.json'
    monkeypatch.setenv('ARCKON_MASTER_KEY', os.urandom(32).hex())
    save_siem_config({'splunk': {'hec_token': 'secret'}}, config)
    original = config.read_bytes()
    assert b'secret' not in original
    assert load_siem_config(config)['splunk']['hec_token'] == 'secret'
    with patch('os.replace', side_effect=OSError('failure')):
        with pytest.raises(OSError):
            save_siem_config({'splunk': {'hec_token': 'replacement'}}, config)
    assert config.read_bytes() == original
    monkeypatch.setenv('ARCKON_MASTER_KEY', os.urandom(32).hex())
    with pytest.raises(RuntimeError, match='Unable to load/decrypt'):
        load_siem_config(config)
    with pytest.raises(Exception):
        save_siem_config(json.loads(original), config)
    assert config.read_bytes() == original
    config.write_text('{bad json with secret')
    with pytest.raises(RuntimeError) as error:
        load_siem_config(config)
    assert 'secret' not in str(error.value)


@pytest.fixture
def old_data(tmp_path, monkeypatch):
    db, siem, key_file = (tmp_path / name for name in ('data.sqlite', 'siem.json', 'key'))
    legacy = hashlib.sha256(b'arckon-dev-key-DO-NOT-USE-IN-PROD').digest()
    monkeypatch.setenv('ARCKON_MASTER_KEY', legacy.hex())
    store = AgentStore(db)
    store.add_protected_path('dev1', '/sensitive/current', created_by='operator')
    removed = store.add_protected_path('dev1', '/sensitive/removed', created_by='operator')
    store.remove_protected_path(removed, changed_by='operator')
    store.ingest_access_events([
        {'ts': 1700000000, 'device_id': 'dev1', 'process': 'claude',
         'path': '/sensitive/current', 'action': 'read'},
        {'ts': 1700000001, 'device_id': 'dev1', 'process': 'cursor',
         'path': '/sensitive/removed', 'action': 'write'},
    ])
    save_siem_config({'splunk': {'hec_token': 'legacy-secret', 'enabled': True}}, siem)
    store._conn().close()
    monkeypatch.delenv('ARCKON_MASTER_KEY')
    return db, siem, key_file


def snapshot(db):
    with sqlite3.connect(db) as conn:
        return {table: conn.execute(f'SELECT * FROM {table} ORDER BY id').fetchall()
                for table in ('protected_paths', 'protected_paths_audit', 'access_events')}


def test_migration_roundtrip_audit_chain_and_idempotence(old_data, tmp_path, monkeypatch):
    db, siem, key_file = old_data
    before, original = snapshot(db), siem.read_bytes()
    counts = migrate(db, siem, key_file, apply=False, legacy_dev_key=True)
    assert counts == {'protected_paths': 1, 'protected_paths_audit': 3, 'siem_secrets': 1}
    assert not key_file.exists()
    assert snapshot(db) == before and siem.read_bytes() == original
    backups = tmp_path / 'backups'
    assert migrate(db, siem, key_file, apply=True, legacy_dev_key=True,
                   backup_dir=backups) == counts
    assert key_file.stat().st_mode & 0o777 == 0o600
    assert backups.stat().st_mode & 0o777 == 0o700
    assert snapshot(backups / 'database.sqlite') == before
    assert (backups / 'siem_config.json').read_bytes() == original
    monkeypatch.setenv('ARCKON_MASTER_KEY_FILE', str(key_file))
    store = AgentStore(db)
    assert store.get_protected_paths()[0]['path'] == os.path.realpath('/sensitive/current')
    audit = store.get_protected_paths_audit_log()
    assert len(audit) == 3
    assert {r['path'] for r in audit} == {os.path.realpath('/sensitive/current'),
                                        os.path.realpath('/sensitive/removed')}
    assert store.verify_access_event_chain()
    store._conn().close()
    assert load_siem_config(siem)['splunk']['hec_token'] == 'legacy-secret'
    after = snapshot(db)
    assert after['access_events'] == before['access_events']
    # Compare all non-path columns, including path_hash and audit attribution.
    with sqlite3.connect(db) as conn:
        for table in ('protected_paths', 'protected_paths_audit'):
            cols = [r[1] for r in conn.execute(f'PRAGMA table_info({table})')]
            index = cols.index('path')
            assert [r[:index] + r[index + 1:] for r in before[table]] == [
                r[:index] + r[index + 1:] for r in after[table]]
    migrated_siem, persisted_key = siem.read_bytes(), key_file.read_bytes()
    assert not any(migrate(db, siem, key_file, apply=True, legacy_dev_key=True,
                           backup_dir=backups).values())
    assert snapshot(db) == after and siem.read_bytes() == migrated_siem
    assert key_file.read_bytes() == persisted_key


@pytest.mark.parametrize('target', ['protected_paths', 'protected_paths_audit', 'siem'])
def test_wrong_key_aborts_all_updates(old_data, tmp_path, target):
    db, siem, key_file = old_data
    foreign = crypto.encrypt_field('/unknown', os.urandom(32))
    if target == 'siem':
        cfg = json.loads(siem.read_bytes())
        cfg['splunk']['hec_token'] = foreign
        siem.write_text(json.dumps(cfg))
    else:
        with sqlite3.connect(db) as conn:
            conn.execute(f'UPDATE {target} SET path=? WHERE id=(SELECT MAX(id) FROM {target})',
                         (foreign,))
    before, original = snapshot(db), siem.read_bytes()
    db_bytes = db.read_bytes()
    for apply in (False, True):
        with pytest.raises(Exception):
            migrate(db, siem, key_file, apply=apply, legacy_dev_key=True,
                    backup_dir=tmp_path / 'backups')
        assert snapshot(db) == before and siem.read_bytes() == original
        assert db.read_bytes() == db_bytes
        assert not key_file.exists() and not (tmp_path / 'backups').exists()


def test_protected_getters_never_return_bad_ciphertext(old_data, monkeypatch):
    db, _, _ = old_data
    monkeypatch.setenv('ARCKON_MASTER_KEY', os.urandom(32).hex())
    store = AgentStore(db)
    try:
        for getter in (store.get_protected_paths, store.get_protected_paths_audit_log,
                       lambda: store.get_protected_paths_for_agent('dev1')):
            with pytest.raises(RuntimeError):
                getter()
    finally:
        store._conn().close()


def test_failed_siem_swap_rolls_back_and_reuses_key(old_data, tmp_path):
    db, siem, key_file = old_data
    before, original = snapshot(db), siem.read_bytes()
    with patch('scripts.migrate_field_encryption.os.replace', side_effect=OSError('failure')):
        with pytest.raises(OSError):
            migrate(db, siem, key_file, apply=True, legacy_dev_key=True,
                    backup_dir=tmp_path / 'first-backup')
    assert snapshot(db) == before and siem.read_bytes() == original
    persisted = key_file.read_bytes()
    assert not key_file.with_name('key.migration-pending').exists()
    migrate(db, siem, key_file, apply=True, legacy_dev_key=True,
            backup_dir=tmp_path / 'second-backup')
    assert key_file.read_bytes() == persisted


def test_pending_marker_blocks_retries(old_data, tmp_path):
    db, siem, key_file = old_data
    pending = key_file.with_name('key.migration-pending')
    pending.write_text('recovery required')
    before, original = snapshot(db), siem.read_bytes()
    with pytest.raises(RuntimeError, match='Pending migration'):
        migrate(db, siem, key_file, apply=True, legacy_dev_key=True,
                backup_dir=tmp_path / 'backups')
    assert snapshot(db) == before and siem.read_bytes() == original


def test_failure_after_siem_swap_restores_both_stores(old_data, tmp_path):
    from scripts import migrate_field_encryption as migration
    db, siem, key_file = old_data
    before, original = snapshot(db), siem.read_bytes()
    real_sync = migration._sync_dir
    swapped = False
    real_replace = os.replace

    def replace(source, destination):
        nonlocal swapped
        real_replace(source, destination)
        swapped = True

    # Only the first post-replacement sync fails; rollback must remain possible.
    failed = False

    def sync_once(path):
        nonlocal failed
        if not failed and swapped:
            failed = True
            raise OSError('post-swap directory sync failure')
        real_sync(path)

    with patch.object(migration.os, 'replace', side_effect=replace):
        with patch.object(migration, '_sync_dir', side_effect=sync_once):
            with pytest.raises(OSError):
                migrate(db, siem, key_file, apply=True, legacy_dev_key=True,
                        backup_dir=tmp_path / 'backups')
    assert snapshot(db) == before and siem.read_bytes() == original
    assert not key_file.with_name('key.migration-pending').exists()


def test_uncertain_commit_retains_recovery_marker(old_data, tmp_path):
    db, siem, key_file = old_data
    before, original = snapshot(db), siem.read_bytes()
    real_connect = sqlite3.connect

    class FailingCommit(sqlite3.Connection):
        def commit(self):
            raise sqlite3.OperationalError('simulated commit failure')

    def connect(*args, **kwargs):
        if kwargs.get('timeout') == 0:
            kwargs['factory'] = FailingCommit
        return real_connect(*args, **kwargs)

    with patch('scripts.migrate_field_encryption.sqlite3.connect', side_effect=connect):
        with pytest.raises(sqlite3.OperationalError):
            migrate(db, siem, key_file, apply=True, legacy_dev_key=True,
                    backup_dir=tmp_path / 'backups')
    assert snapshot(db) == before and siem.read_bytes() == original
    marker = key_file.with_name('key.migration-pending')
    assert marker.exists()
    assert json.loads(marker.read_bytes())['backup_dir'] == str(tmp_path / 'backups')
    with pytest.raises(RuntimeError, match='Pending migration'):
        migrate(db, siem, key_file, apply=False, legacy_dev_key=True)


def test_migration_includes_plaintext_and_reuses_mixed_destination_key(old_data, tmp_path):
    db, siem, key_file = old_data
    new_key = os.urandom(32)
    key_file.write_text(new_key.hex())
    key_file.chmod(0o600)
    already_migrated = crypto.encrypt_field('/already/migrated', new_key)
    with sqlite3.connect(db) as conn:
        conn.execute('UPDATE protected_paths_audit SET path=? WHERE id=1', (already_migrated,))
        conn.execute('UPDATE protected_paths_audit SET path=? WHERE id=2', ('/legacy/plaintext',))
    migrate(db, siem, key_file, apply=True, legacy_dev_key=True,
            backup_dir=tmp_path / 'backups')
    with sqlite3.connect(db) as conn:
        rows = conn.execute('SELECT path FROM protected_paths_audit ORDER BY id').fetchall()
    assert rows[0][0] == already_migrated
    assert crypto.decrypt_field(rows[1][0], new_key) == '/legacy/plaintext'


def test_cli_decryption_failure_does_not_log_secret(old_data, capsys):
    from scripts.migrate_field_encryption import main
    db, siem, key_file = old_data
    siem.write_text('{malformed-SECRET-CONTENT')
    with patch('sys.argv', ['migrate', '--check', '--db', str(db), '--siem-config', str(siem),
                            '--new-key-file', str(key_file), '--legacy-dev-key']):
        assert main() == 1
    output = capsys.readouterr()
    assert 'SECRET-CONTENT' not in output.err + output.out


@pytest.mark.parametrize('kind', ['invalid', 'insecure', 'legacy'])
def test_invalid_destination_key_never_replaced(old_data, tmp_path, kind):
    db, siem, key_file = old_data
    value = ('invalid' if kind == 'invalid' else
             hashlib.sha256(b'arckon-dev-key-DO-NOT-USE-IN-PROD').hexdigest()
             if kind == 'legacy' else os.urandom(32).hex())
    key_file.write_text(value)
    key_file.chmod(0o644 if kind == 'insecure' else 0o600)
    before, original = snapshot(db), siem.read_bytes()
    with pytest.raises(ValueError):
        migrate(db, siem, key_file, apply=True, legacy_dev_key=True,
                backup_dir=tmp_path / 'backups')
    assert snapshot(db) == before and siem.read_bytes() == original
    assert key_file.read_text() == value
    assert not (tmp_path / 'backups').exists()


def test_committed_but_interrupted_migration_requires_paired_restore(old_data, tmp_path):
    db, siem, key_file = old_data
    before, original = snapshot(db), siem.read_bytes()
    backups = tmp_path / 'backups'
    real_connect = sqlite3.connect

    class UncertainCommit(sqlite3.Connection):
        def commit(self):
            super().commit()
            raise sqlite3.OperationalError('commit succeeded but acknowledgement lost')

    def connect(*args, **kwargs):
        if kwargs.get('timeout') == 0:
            kwargs['factory'] = UncertainCommit
        return real_connect(*args, **kwargs)

    with patch('scripts.migrate_field_encryption.sqlite3.connect', side_effect=connect):
        with pytest.raises(sqlite3.OperationalError):
            migrate(db, siem, key_file, apply=True, legacy_dev_key=True, backup_dir=backups)
    assert snapshot(db) != before  # The DB really committed; rollback cannot undo this.
    marker = key_file.with_name('key.migration-pending')
    assert marker.exists()
    # Operator recovery: SQLite backup API restores DB including WAL safely;
    # restore the matching SIEM backup, then and only then clear the marker.
    with sqlite3.connect(backups / 'database.sqlite') as source:
        with sqlite3.connect(db) as target:
            source.backup(target)
    siem.write_bytes((backups / 'siem_config.json').read_bytes())
    marker.unlink()
    assert snapshot(db) == before and siem.read_bytes() == original
    persisted = key_file.read_bytes()
    migrate(db, siem, key_file, apply=True, legacy_dev_key=True,
            backup_dir=tmp_path / 'retry-backups')
    assert key_file.read_bytes() == persisted
