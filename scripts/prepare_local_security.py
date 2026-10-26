#!/usr/bin/env python3
"""Security preflight for same-user POSIX source-tree launchers.

The default key is .field-secrets/master-key beside server.py. Back it up
privately with data; never delete it to fix startup. ARCKON_MASTER_KEY_FILE
may select an existing private key instead. Raw environment keys are not
supported by these launchers. Existing data without a key requires stopped
writers and explicit operator migration; see migrate_field_encryption.py --help.

For LAN browser access, explicitly set PUBLIC_DASHBOARD_URL, for example
PUBLIC_DASHBOARD_URL=http://192.168.1.10:7331 ./launch_arckon.sh
Set PUBLIC_ADMIN_URL too if using a separate admin origin. These are exact
trusted CSRF origins, not values inferred from an untrusted request Host.
This does not configure TLS, authentication, firewall rules, or an admin server.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import os
from pathlib import Path
import secrets
import stat
import sys


def prepare(project: Path, key: Path) -> None:
    project, key = project.resolve(), key.absolute()
    if 'ARCKON_MASTER_KEY' in os.environ:
        raise ValueError('Use ARCKON_MASTER_KEY_FILE, not a raw environment key')
    data = project / 'data'
    for path in (data, *key.parents, key):
        if path.is_symlink():
            raise ValueError('Symlinked data/key paths are not supported')
    pending = key.with_name(key.name + '.migration-pending')
    if pending.exists() or pending.is_symlink():
        raise ValueError('Pending migration; keep writers stopped and recover offline')
    if not key.exists():
        if ((data.exists() and (not data.is_dir() or any(data.iterdir())))
                or (project / 'siem_config.json').exists()):
            raise ValueError('Existing data without a key: explicit offline migration required; '
                             'see scripts/migrate_field_encryption.py --help')
        if key != project / '.field-secrets' / 'master-key':
            raise ValueError('Configured key file must already exist; no replacement is generated')
        key.parent.mkdir(mode=0o700, exist_ok=True)
    info = key.parent.stat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError('Key directory must be owned by the current user with mode 0700')
    if not key.exists():
        fd = os.open(key, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(base64.b64encode(secrets.token_bytes(32)) + b'\n')
            stream.flush()
            os.fchmod(stream.fileno(), 0o600)
            os.fsync(stream.fileno())
        fd = os.open(key.parent, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    fd = os.open(key, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) not in (0o400, 0o600) or info.st_nlink != 1):
            raise ValueError('Key must be a current-user-owned private regular file (0400 or 0600)')
        raw = stream.read(1024).decode('ascii').rstrip('\r\n')
    decoded = (bytes.fromhex(raw) if len(raw) == 64
               and all(c in '0123456789abcdefABCDEF' for c in raw)
               else base64.b64decode(raw, validate=True))
    if len(decoded) != 32:
        raise ValueError('Key must encode exactly 32 bytes')
    if decoded == hashlib.sha256(b'arckon-dev-key-DO-NOT-USE-IN-PROD').digest():
        raise ValueError('Legacy development key requires explicit offline migration')


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--project-dir', type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    configured = os.environ.get('ARCKON_MASTER_KEY_FILE')
    if configured == '':
        print('Security preflight failed: ARCKON_MASTER_KEY_FILE is empty', file=sys.stderr)
        return 1
    key = Path(configured) if configured is not None else args.project_dir / '.field-secrets/master-key'
    try:
        prepare(args.project_dir, key)
    except (OSError, ValueError) as exc:
        # Decoder/OS exceptions can contain input. Never print their contents.
        message = str(exc) if type(exc) is ValueError else 'Invalid key file or filesystem permissions'
        print(f'Security preflight failed: {message}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
