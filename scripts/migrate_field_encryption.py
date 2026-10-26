#!/usr/bin/env python3
"""Offline field-key migration. Stop ALL DB/config writers before either mode.

--check opens SQLite read-only and writes no data, backups, or key (SQLite may
maintain WAL sidecars). --apply persists/reuses a random key,
backs up both stores, and changes only protected policy/audit paths and SIEM
secret fields. Access-event chains and path hashes are never rewritten.

SQLite and a JSON file cannot share an atomic commit. A durable pending marker
beside the key blocks retries after an interrupted/uncertain commit. In that
case, keep writers stopped and restore BOTH stores from the indicated backup
directory (SQLite backup API, not copying over a live WAL database), then remove
the marker and retry with the SAME key. Never delete/regenerate the key.
Backups may contain plaintext/legacy ciphertext: protect them like secrets.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from crypto import _load_key_file, decrypt_field, encrypt_field
from connectors.siem_connector import _SIEM_SECRET_FIELDS


def _sync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _private_write(path: Path, payload: bytes) -> None:
    # O_EXCL prevents replacing a key/backup from an earlier attempt.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    _sync_dir(path.parent)


def _stage(path: Path, payload: bytes) -> Path:
    fd, name = tempfile.mkstemp(prefix='.field-migration-', dir=path.parent)
    staged = Path(name)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        return staged
    except BaseException:
        staged.unlink(missing_ok=True)
        raise


def migrate(db: Path, siem: Path, key_file: Path, *, apply: bool,
            legacy_dev_key: bool, backup_dir: Path | None = None) -> dict:
    """Validate the complete input before backups or data updates; return counts.

    Fields already decryptable with the destination key are left byte-for-byte
    unchanged, making successful reruns and mixed-key inputs idempotent.
    No environment key or normal-runtime fallback is consulted.
    """
    if not legacy_dev_key:
        raise ValueError('Explicit --legacy-dev-key authorization is required')
    db, siem, key_file = (Path(p).absolute() for p in (db, siem, key_file))
    pending = key_file.with_name(key_file.name + '.migration-pending')
    if pending.exists():
        raise RuntimeError('Pending migration: restore BOTH backups before retrying; see marker')
    if not db.is_file() or not siem.is_file() or db.is_symlink() or siem.is_symlink():
        raise ValueError('Explicit existing regular DB and SIEM files are required')
    if len({db.resolve(), siem.resolve(), key_file.resolve(), pending.resolve()}) != 4:
        raise ValueError('DB, SIEM, key, and marker paths must be distinct')
    if apply and backup_dir is None:
        raise ValueError('--apply requires a fresh --backup-dir')
    # An existing destination key is never replaced, even after failed attempts.
    key_exists = key_file.exists() or key_file.is_symlink()
    new_key = _load_key_file(str(key_file)) if key_exists else secrets.token_bytes(32)
    old_key = hashlib.sha256(b'arckon-dev-key-DO-NOT-USE-IN-PROD').digest()
    if new_key == old_key:
        raise ValueError('Destination must not be the legacy development key')

    def convert(value):
        if not isinstance(value, str):
            raise ValueError('Encrypted field must be a string')
        if value.startswith('enc:'):
            try:
                decrypt_field(value, new_key)
                return value
            except Exception:
                # Only this explicit offline mode may try the legacy key.
                plain = decrypt_field(value, old_key)
        else:
            plain = value
        return encrypt_field(plain, new_key)

    original = siem.read_bytes()
    cfg = json.loads(original)
    if not isinstance(cfg, dict):
        raise ValueError('SIEM config must be an object')
    secrets_changed = 0
    for vals in cfg.values():
        if isinstance(vals, dict):
            for field in vals.keys() & _SIEM_SECRET_FIELDS:
                value = convert(vals[field])
                secrets_changed += value != vals[field]
                vals[field] = value
    payload = json.dumps(cfg, indent=2).encode('utf-8')
    conn = sqlite3.connect(db.as_uri() + ('?mode=rw' if apply else '?mode=ro'),
                           uri=True, timeout=0)
    staged = restore = None
    replaced = commit_attempted = committed = marker_written = False
    try:
        conn.execute('BEGIN IMMEDIATE' if apply else 'BEGIN')
        updates = {}
        for table in ('protected_paths', 'protected_paths_audit'):
            updates[table] = []
            for row_id, value in conn.execute(f'SELECT id, path FROM {table}'):
                encrypted = convert(value)
                if encrypted != value:
                    updates[table].append((encrypted, row_id))
        counts = {table: len(rows) for table, rows in updates.items()}
        counts['siem_secrets'] = secrets_changed
        if not apply or not any(counts.values()):
            conn.rollback()
            if apply and not key_exists:
                _private_write(key_file, base64.b64encode(new_key) + b'\n')
            return counts

        # Nothing above this point mutates inputs, creates backups, or keys.
        if not key_exists:
            _private_write(key_file, base64.b64encode(new_key) + b'\n')
        backup_dir = Path(backup_dir).absolute()
        backup_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
        _sync_dir(backup_dir.parent)
        _private_write(backup_dir / 'siem_config.json', original)
        backup_db = backup_dir / 'database.sqlite'
        _private_write(backup_db, b'')
        # A separate reader snapshots the original while our write lock excludes
        # competing DB writers. SQLite backup includes committed WAL content.
        with sqlite3.connect(db.as_uri() + '?mode=ro', uri=True) as source:
            with sqlite3.connect(backup_db) as target:
                source.backup(target)
        with backup_db.open('rb') as stream:
            os.fsync(stream.fileno())
        _sync_dir(backup_dir)
        if siem.read_bytes() != original:
            raise RuntimeError('SIEM config changed; stop all writers and retry')
        if secrets_changed:
            staged = _stage(siem, payload)
            restore = _stage(siem, original)
        manifest = {'database': str(db), 'siem': str(siem),
                    'backup_dir': str(backup_dir),
                    'recovery': 'Restore BOTH stores offline; retain key; then remove this marker.'}
        _private_write(pending, json.dumps(manifest, indent=2).encode('utf-8'))
        marker_written = True
        for table, rows in updates.items():
            conn.executemany(f'UPDATE {table} SET path=? WHERE id=?', rows)
        if staged is not None:
            os.replace(staged, siem)
            replaced = True
            _sync_dir(siem.parent)
        commit_attempted = True
        conn.commit()
        committed = True
        pending.unlink()
        _sync_dir(pending.parent)
        return counts
    except BaseException:
        conn.rollback()
        if replaced and not committed:
            os.replace(restore, siem)
            _sync_dir(siem.parent)
        # A failed/uncertain commit requires operator recovery, not guessing.
        if marker_written and not commit_attempted:
            pending.unlink()
            _sync_dir(pending.parent)
        raise
    finally:
        conn.close()
        for path in (staged, restore):
            if path is not None:
                path.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--check', action='store_true', help='Read-only full validation')
    mode.add_argument('--apply', action='store_true')
    parser.add_argument('--db', type=Path, required=True)
    parser.add_argument('--siem-config', type=Path, required=True)
    parser.add_argument('--new-key-file', type=Path, required=True)
    parser.add_argument('--backup-dir', type=Path)
    parser.add_argument('--legacy-dev-key', action='store_true', required=True,
                        help='Explicitly authorize decrypting with the old public development key')
    args = parser.parse_args()
    try:
        counts = migrate(args.db, args.siem_config, args.new_key_file,
                         apply=args.apply, legacy_dev_key=args.legacy_dev_key,
                         backup_dir=args.backup_dir)
    except Exception:
        # Exception messages may include JSON input, SQL values or secret paths.
        print('Migration failed. Keep writers stopped. No key is replaced. If a '
              '.migration-pending marker exists, restore BOTH backups as documented '
              'in --help before removing it. Otherwise inputs were rolled back; '
              'fix configuration/decryption/permissions and retry with the same key '
              'and a fresh backup directory.', file=sys.stderr)
        return 1
    print(('Applied' if args.apply else 'Check passed') + ': ' + json.dumps(counts))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
