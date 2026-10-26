#!/usr/bin/env python3
"""Prepare operator-owned tenant security files; never migrate or replace keys.

Run as root. Optional outbound-private-origins.json in the tenant secret directory
overrides the operator's ARCKON_OUTBOUND_PRIVATE_ORIGINS environment variable.
runtime.env is consumed by Docker, not mounted into the customer container.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys


CUSTOMER_UID = 999


def private_file(path: Path, owner: int, mode: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner
                or stat.S_IMODE(info.st_mode) != mode or info.st_nlink != 1):
            raise ValueError(f'{path}: expected private regular file, uid {owner}, mode {mode:04o}')
        return stream.read(65537)


def prepare(customer_id: str, data_root: Path, secret_root: Path, *, provision: bool) -> None:
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}', customer_id):
        raise ValueError('Invalid customer ID')
    data_root, secret_root = data_root.absolute(), secret_root.absolute()
    data = data_root / customer_id
    directory = secret_root / customer_id
    # Reject symlinked ancestors and tenant-controlled secret locations. The data
    # root itself may belong to the admin; only root may own the secret subtree.
    if secret_root.resolve().is_relative_to(data.resolve()):
        raise ValueError('Field secrets must be outside customer data')
    if (secret_root.resolve().is_relative_to(data_root.resolve())
            and secret_root.resolve() != data_root.resolve() / '.field-secrets'):
        raise ValueError('Only .field-secrets may hold keys beneath the data root')
    for path in (*data_root.parents, data_root, data, *secret_root.parents, secret_root, directory):
        if path.is_symlink():
            raise ValueError(f'Symlinked security/data path: {path}')
    if not data_root.is_dir():
        raise ValueError('Data root must already exist')
    for path in (secret_root, directory):
        path.mkdir(mode=0o700, exist_ok=True)
        info = path.stat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise ValueError(f'{path}: expected operator-owned directory, mode 0700')
    key = directory / 'master-key'
    pending = directory / 'master-key.migration-pending'
    if pending.exists() or pending.is_symlink():
        raise ValueError('Pending field migration; operator recovery required')
    if not key.exists() and not key.is_symlink():
        # Deliberately conservative: ANY existing tenant files require operator
        # review, including empty databases and configs with unknown provenance.
        if not provision or (data.exists() and any(data.iterdir())):
            raise ValueError('Missing master key; use the explicit offline migration workflow')
        fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(base64.b64encode(secrets.token_bytes(32)) + b'\n')
            stream.flush()
            os.fchown(stream.fileno(), CUSTOMER_UID, CUSTOMER_UID)
            os.fchmod(stream.fileno(), 0o400)
            os.fsync(stream.fileno())
        directory_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    raw = private_file(key, CUSTOMER_UID, 0o400).decode('ascii').rstrip('\r\n')
    decoded = (bytes.fromhex(raw) if re.fullmatch(r'[0-9a-fA-F]{64}', raw)
               else base64.b64decode(raw, validate=True))
    if len(decoded) != 32:
        raise ValueError('Master key must encode exactly 32 bytes')

    policy_file = directory / 'outbound-private-origins.json'
    policy = (private_file(policy_file, os.geteuid(), 0o600).decode('utf-8')
              if policy_file.exists() or policy_file.is_symlink()
              else os.environ.get('ARCKON_OUTBOUND_PRIVATE_ORIGINS', '{}'))
    policy = json.loads(policy)
    if not isinstance(policy, dict):
        raise ValueError('Outbound private origins must be a JSON object')
    # JSON serialization prevents newline/env injection. The server validates
    # exact origins and private CIDRs using its outbound HTTP policy parser.
    payload = 'ARCKON_OUTBOUND_PRIVATE_ORIGINS=' + json.dumps(policy, separators=(',', ':'), ensure_ascii=True) + '\n'
    env_file = directory / 'runtime.env'
    # Never follow or overwrite a tenant-supplied file. The parent is root-only.
    if env_file.exists() or env_file.is_symlink():
        private_file(env_file, os.geteuid(), 0o600)
        env_file.unlink()
    fd = os.open(env_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write(payload)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('customer_id')
    parser.add_argument('--provision', action='store_true')
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise ValueError('Run security preparation as root')
        data_root = Path(os.environ.get('SENTINEL_DATA_ROOT', '/opt/sentinel-data'))
        secret_root = Path(os.environ.get('SENTINEL_FIELD_SECRET_ROOT', str(data_root / '.field-secrets')))
        prepare(args.customer_id, data_root, secret_root, provision=args.provision)
    except (OSError, ValueError) as exc:
        print(f'Security preflight failed: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
