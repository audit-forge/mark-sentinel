#!/usr/bin/env python3
"""Host-only offline upgrade. Run as root after disabling automated restarts.

Never removes/restarts the tenant or changes authentication. On failure keep all
writers stopped, retain the key and paired backups, and follow
scripts/migrate_field_encryption.py --help for pending-marker recovery.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from deploy.gcp.prepare_customer_security import prepare, private_file


def docker(*args: str) -> str:
    # Capture ALL output: inspect contains credentials and errors can echo input.
    result = subprocess.run(['docker', *args], capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError('Docker operation failed; tenant must remain stopped if maintenance began')
    return result.stdout


BACKUP = """
import os, sqlite3
from pathlib import Path
p = Path(__import__('sys').argv[1])
p.mkdir(mode=0o700)
os.umask(0o077)
with sqlite3.connect('file:/app/data/agents.db?mode=ro', uri=True) as source:
    with sqlite3.connect(p / 'database.sqlite') as target:
        source.backup(target)
(p / 'siem_config.json').write_bytes(Path('/app/data/siem_config.json').read_bytes())
for f in p.iterdir():
    with f.open('rb') as stream:
        os.fsync(stream.fileno())
fd = os.open(p, os.O_RDONLY)
os.fsync(fd)
os.close(fd)
"""


def upgrade(customer_id: str, image: str, data_root: Path, secret_root: Path,
            *, maintenance: bool, legacy_dev_key: bool) -> None:
    if os.geteuid() != 0:
        raise ValueError('Run on the Docker host as root')
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}', customer_id):
        raise ValueError('Invalid customer ID')
    if not maintenance or not legacy_dev_key:
        raise ValueError('Require --maintenance and explicit --legacy-dev-key; never infer a legacy key')
    data_root, secret_root = data_root.absolute(), secret_root.absolute()
    data, secrets = data_root / customer_id, secret_root / customer_id
    if not data.is_dir() or not (data / 'agents.db').is_file() or (data / 'agents.db').is_symlink():
        raise ValueError('Existing tenant data/agents.db required')
    if secret_root.resolve().is_relative_to(data_root.resolve()) and secret_root != data_root / '.field-secrets':
        raise ValueError('Secrets must be outside tenant data or in data-root/.field-secrets')
    for path in (data, *data.parents, secrets, *secrets.parents):
        if path.is_symlink():
            raise ValueError('Symlinked data/security paths are forbidden')
    if secrets == data or secrets.is_relative_to(data):
        raise ValueError('Secrets must be outside tenant data')
    for path in (secret_root, secrets):
        path.mkdir(mode=0o700, exist_ok=True)
        info = path.stat()
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError('Secret directories require root ownership and mode 0700')
    key = secrets / 'master-key'
    pending = secrets / 'master-key.migration-pending'
    if pending.exists() or pending.is_symlink():
        raise ValueError('Pending migration: restore BOTH stores per migration tool help before retry')
    if key.exists() or key.is_symlink():
        private_file(key, 0, 0o600)  # Retry only with the SAME migration-owned key.
    container = 'sentinel-' + customer_id
    info = json.loads(docker('inspect', container))[0]
    env = dict(value.split('=', 1) for value in info['Config'].get('Env', []) if '=' in value)
    configured = any(name in env for name in ('ARCKON_MASTER_KEY', 'ARCKON_MASTER_KEY_FILE'))
    print('Configured field-key source present: ' + ('yes' if configured else 'no'))
    if configured:
        raise ValueError('Configured key detected. Do not assume legacy encryption; review that key offline')
    mounts = [m for m in info['Mounts'] if m['Destination'] == '/app/data']
    if len(mounts) != 1 or mounts[0]['Type'] != 'bind' or Path(mounts[0]['Source']) != data or not mounts[0]['RW']:
        raise ValueError('Expected original writable tenant data bind mount; refusing another data source')
    # Validate the new image locally before stopping; never pull an unreviewed tag.
    pinned = json.loads(docker('image', 'inspect', image))[0]['Id']
    docker('run', '--rm', '--network', 'none', '--user', '0:0', '--entrypoint', 'python3',
           pinned, '/app/scripts/migrate_field_encryption.py', '--help')
    print('Entering maintenance: stopping tenant, without removing it')
    docker('stop', container)
    if json.loads(docker('inspect', container))[0]['State']['Running']:
        raise RuntimeError('Tenant is still running')
    # docker cp works on a stopped container and retains its old writable layer.
    work = Path(tempfile.mkdtemp(prefix='upgrade-', dir=secrets))
    old = work / 'old-siem.json'
    # A missing file is distinct from a failed copy. Never restart old code to
    # inspect a stopped tenant, including when retrying a failed upgrade.
    result = subprocess.run(['docker', 'cp', container + ':/app/siem_config.json', str(old)],
                            capture_output=True, text=True)
    if result.returncode:
        # Do not treat arbitrary Docker errors as an absent config.
        if 'Could not find the file' not in result.stderr:
            raise RuntimeError('Unable to preserve old SIEM configuration; keep tenant stopped')
    siem = data / 'siem_config.json'
    if siem.is_symlink() or old.is_symlink():
        raise ValueError('SIEM config must not be a symlink')
    if old.exists() and siem.exists() and old.read_bytes() != siem.read_bytes():
        raise ValueError('Conflicting old and persistent SIEM configs; neither was overwritten')
    if not siem.exists():
        payload = old.read_bytes() if old.exists() else b'{}\n'
        with os.fdopen(os.open(siem, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), 'wb') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    if old.exists():
        old.chmod(0o600)
    base = ('run', '--rm', '--network', 'none', '--read-only', '--tmpfs', '/tmp',
            '--user', '0:0', '--mount', f'type=bind,src={data},dst=/app/data',
            '--mount', f'type=bind,src={secrets},dst=/field-secrets',
            '--entrypoint', 'python3', pinned)
    migration = ('/app/scripts/migrate_field_encryption.py', '--db', '/app/data/agents.db',
                 '--siem-config', '/app/data/siem_config.json', '--new-key-file',
                 '/field-secrets/master-key', '--legacy-dev-key')
    docker(*base, *migration, '--check')
    backup = '/field-secrets/' + work.name
    # Always back up, including empty/already-migrated stores. Never copy SQLite
    # files: committed WAL records must be included in the snapshot.
    docker(*base, '-c', BACKUP, backup + '/before')
    docker(*base, *migration, '--apply', '--backup-dir', backup + '/migration')
    verified = docker(*base, *migration, '--check')
    if any(json.loads(verified.split(': ', 1)[1]).values()):
        raise RuntimeError('Verification still requires changes; key not handed off')
    private_file(key, 0, 0o600)
    os.chown(siem, 999, 999)
    os.chmod(siem, 0o600)
    os.chmod(key, 0o400)
    os.chown(key, 999, 999)
    docker('run', '--rm', '--network', 'none', '--read-only', '--user', '999:999',
           '--mount', f'type=bind,src={key},dst=/run/secrets/arckon_master_key,readonly',
           '-e', 'ARCKON_MASTER_KEY_FILE=/run/secrets/arckon_master_key',
           '--entrypoint', 'python3', pinned, '-c',
           'from crypto import _load_master_key; _load_master_key()')
    prepare(customer_id, data_root, secret_root, provision=False)
    print('Verified; key handed off to uid 999 mode 0400. Tenant remains STOPPED.')
    print('Paired backups: ' + str(work / 'before'))
    print('Recreate using the reviewed image as mark-sentinel:latest, then:')
    print('sudo bash deploy/gcp/restart_customer.sh ' + shlex.quote(customer_id))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('customer_id')
    parser.add_argument('--image', required=True, help='Locally built migration image containing reviewed new code')
    parser.add_argument('--maintenance', action='store_true', help='Authorize stop; all other writers/automation disabled')
    parser.add_argument('--legacy-dev-key', action='store_true', help='Authorize old public development key explicitly')
    args = parser.parse_args()
    root = Path(os.environ.get('SENTINEL_DATA_ROOT', '/opt/sentinel-data'))
    secrets = Path(os.environ.get('SENTINEL_FIELD_SECRET_ROOT', str(root / '.field-secrets')))
    try:
        upgrade(args.customer_id, args.image, root, secrets,
                maintenance=args.maintenance, legacy_dev_key=args.legacy_dev_key)
    except (ValueError, OSError, RuntimeError, KeyError) as exc:
        # Never print Docker/JSON exception details, which may contain secrets.
        reason = (str(exc) if isinstance(exc, (ValueError, RuntimeError))
                  and not isinstance(exc, json.JSONDecodeError) else type(exc).__name__)
        print('Upgrade failed: ' + reason + '. Keep maintenance active; '
              'retain the container, key and backups. Review configured keys, SIEM conflicts, '
              'permissions and pending-marker recovery before retrying.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
