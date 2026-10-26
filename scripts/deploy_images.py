#!/usr/bin/env python3
"""Root-only local-image rollout. No source fetch, builds, pulls, or migrations.

The signed-release poller must verify/import artifacts BEFORE calling this tool.
Only local sha256:<64 hex> image IDs are accepted. --check runs read-only Docker
and tenant-key/decryption preflights (but creates/locks the private state dir).
Stopped labeled containers fail closed unless individually acknowledged with
--skip-stopped ID. Skipped tenants must also be inactive/suspended in the admin
registry, or final smoke coverage fails. Every running customer is included,
with opco first when present.

Exit 0: checked/deployed; 1: failed (see journal rollback status); 2: CLI misuse.
An interrupted journal blocks further deployment pending operator recovery.
Rollback restores images only, never databases, keys, or external side effects.
Lifecycle aliases are promoted after smoke gates and restored on promotion failure.
Both previous lifecycle aliases must exist locally for preflight to succeed.
"""
from __future__ import annotations

import argparse
import base64
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[1]
IMAGE = re.compile(r'sha256:[0-9a-f]{64}')
TENANT = re.compile(r'[a-z0-9][a-z0-9-]{0,62}')
PUBLIC_CHECK = '''
import os
from urllib.parse import urlsplit
for name in ('PUBLIC_ADMIN_URL', 'PUBLIC_DASHBOARD_URL'):
    url = urlsplit(os.environ[name])
    if url.scheme != 'https' or not url.hostname or url.username or url.password:
        raise RuntimeError('Public smoke requires HTTPS origins')
'''
ADMIN_INVENTORY = PUBLIC_CHECK + '''
import json, sqlite3
from pathlib import Path
with sqlite3.connect(Path(os.environ.get('DB_PATH', '/data/sentinel.db')).as_uri() + '?mode=ro', uri=True) as conn:
    print(json.dumps([row[0] for row in conn.execute(
        'SELECT id FROM customers WHERE active=1 AND service_suspended=0 ORDER BY id')]))
'''

# Read-only SQLite access deliberately avoids AgentStore's schema initialization.
# Only authoritative encrypted fields are checked; reports/events are opaque data.
RUNTIME_CHECK = r'''
import json, sqlite3
from pathlib import Path
from crypto import _load_master_key, encrypt_field, decrypt_field
from connectors.siem_connector import _SIEM_SECRET_FIELDS
key = _load_master_key()
assert decrypt_field(encrypt_field('deployment-probe', key), key) == 'deployment-probe'
db = Path('/app/data/agents.db')
assert db.is_file()
with sqlite3.connect(db.as_uri() + '?mode=ro', uri=True) as conn:
    for table in ('protected_paths', 'protected_paths_audit'):
        for (value,) in conn.execute('SELECT path FROM ' + table):
            decrypt_field(value, key)
config = Path('/app/data/siem_config.json')
if config.exists():
    policy = json.loads(config.read_text())
    if not isinstance(policy, dict):
        raise ValueError('SIEM config must be an object')
    for fields in policy.values():
        if isinstance(fields, dict):
            for field in fields.keys() & _SIEM_SECRET_FIELDS:
                if not isinstance(fields[field], str):
                    raise ValueError('SIEM secret must be a string')
                decrypt_field(fields[field], key)
'''


class DeploymentError(RuntimeError):
    pass


def run(argv, *, env=None, input=None):
    """Do not echo command output: Docker/crypto failures may contain secrets."""
    try:
        result = subprocess.run(argv, env=env, input=input, text=True,
                                capture_output=True, timeout=600)
    except (OSError, subprocess.TimeoutExpired):
        raise DeploymentError('Command could not complete: ' + argv[0]) from None
    if result.returncode:
        raise DeploymentError('Command failed: ' + ' '.join(argv[:3]))
    return result.stdout


def save(path, value):
    temporary = path.with_suffix('.tmp')
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    fd = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def host_key_check(tenant):
    spec = importlib.util.spec_from_file_location(
        'customer_security', ROOT / 'deploy/gcp/prepare_customer_security.py')
    security = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(security)
    data_root = Path(os.environ.get('SENTINEL_DATA_ROOT', '/opt/sentinel-data'))
    secret_root = Path(os.environ.get('SENTINEL_FIELD_SECRET_ROOT', str(data_root / '.field-secrets')))
    data, directory = data_root / tenant, secret_root / tenant
    for path in (data, *data.parents, directory, *directory.parents):
        if path.is_symlink():
            raise DeploymentError('Symlinked tenant path: ' + tenant)
    if not data.is_dir() or directory.resolve().is_relative_to(data.resolve()):
        raise DeploymentError('Invalid tenant directories: ' + tenant)
    for path in (secret_root, directory):
        info = path.stat()
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            raise DeploymentError('Insecure tenant secret directory: ' + tenant)
    pending = directory / 'master-key.migration-pending'
    if pending.exists() or pending.is_symlink():
        raise DeploymentError('Pending key migration: ' + tenant)
    raw = security.private_file(directory / 'master-key', 999, 0o400).decode('ascii').strip()
    key = bytes.fromhex(raw) if re.fullmatch(r'[a-fA-F0-9]{64}', raw) else base64.b64decode(raw, validate=True)
    if len(key) != 32:
        raise DeploymentError('Invalid tenant key: ' + tenant)
    security.private_file(directory / 'runtime.env', 0, 0o600)
    if not (data / 'agent_token.txt').read_bytes().strip():
        raise DeploymentError('Missing tenant agent token: ' + tenant)
    return hashlib.sha256(key).hexdigest()


class Engine:
    def __init__(self, args):
        self.args = args
        self.compose = ['docker', 'compose', '-f', str(ROOT / 'deploy/gcp/docker-compose.yml')]

    def inspect(self, name):
        return json.loads(run(['docker', 'inspect', name]))[0]

    def image(self, image):
        if not IMAGE.fullmatch(image):
            raise DeploymentError('Only immutable local sha256 image IDs are accepted')
        actual = json.loads(run(['docker', 'image', 'inspect', image]))[0]['Id']
        if actual != image:
            raise DeploymentError('Local image identity mismatch')

    def runtime(self, name, fingerprint=None):
        code = RUNTIME_CHECK
        if fingerprint:
            code += '\nimport hashlib\nassert hashlib.sha256(key).hexdigest() == ' + repr(fingerprint)
        run(['docker', 'exec', '-i', name, 'python3', '-'], input=code)

    def admin(self, image):
        env = dict(os.environ, ARCKON_ADMIN_IMAGE=image)
        run(self.compose + ['up', '-d', '--no-build', '--pull', 'never', '--no-deps',
                            '--force-recreate', 'user-manager'], env=env)
        if self.inspect('sentinel-admin')['Image'] != image:
            raise DeploymentError('Admin image override was not applied')
        for attempt in range(30):
            try:
                run(['docker', 'exec', 'sentinel-admin', 'python3', '-c',
                     "import urllib.request; assert urllib.request.urlopen('http://localhost:8000/login', timeout=2).status == 200"])
                break
            except DeploymentError:
                if attempt == 29:
                    raise DeploymentError('Admin readiness exhausted') from None
                time.sleep(1)
        # Reload nginx after admin replacement so it resolves the new admin IP.
        run(['docker', 'exec', 'sentinel-nginx', 'nginx', '-t'])
        run(['docker', 'exec', 'sentinel-nginx', 'nginx', '-s', 'reload'])

    def tenant(self, tenant, image):
        run(['bash', str(ROOT / 'deploy/gcp/restart_customer.sh'), tenant],
            env=dict(os.environ, SENTINEL_IMAGE=image))
        info = self.inspect('sentinel-' + tenant)
        if info['Image'] != image or not info['State']['Running']:
            raise DeploymentError('Tenant image/running verification failed: ' + tenant)
        self.runtime('sentinel-' + tenant)

    def smoke(self, tenants):
        code = PUBLIC_CHECK + (ROOT / 'scripts/smoke_live_single_login.py').read_text()
        # The smoke script emits a per-tenant PASS only after every gate succeeds.
        # Match coverage, not just process exit, to prevent empty/subset success.
        output = run(['docker', 'exec', '-i', 'sentinel-admin', 'python3', '-'], input=code)
        passed = {line.split(':', 1)[0] for line in output.splitlines()
                  if line.endswith('passive queue, logout PASS')}
        if passed != set(tenants):
            raise DeploymentError('Public HTTPS smoke did not cover exactly all running tenants')

    def deploy(self):
        args = self.args
        journal_path = args.state_dir / 'transaction.json'
        if journal_path.exists():
            old = json.loads(journal_path.read_text())
            if old['status'] not in ('succeeded', 'rolled_back'):
                raise DeploymentError('Unresolved deployment journal; operator recovery required')
        self.image(args.tenant_image)
        self.image(args.admin_image)
        names = run(['docker', 'ps', '-a', '--filter', 'label=sentinel.customer',
                     '--format', '{{.Names}}']).splitlines()
        tenants = {}
        skipped = []
        acknowledged = set(args.skip_stopped)
        for name in names:
            info = self.inspect(name)
            tenant = info['Config']['Labels'].get('sentinel.customer', '')
            if not TENANT.fullmatch(tenant) or name != 'sentinel-' + tenant or tenant in tenants:
                raise DeploymentError('Invalid or duplicate customer label/container')
            if not info['State']['Running']:
                if tenant not in acknowledged:
                    raise DeploymentError('Stopped labeled customer requires --skip-stopped acknowledgment: ' + tenant)
                skipped.append(tenant)
                continue
            tenants[tenant] = info['Image']
        if acknowledged != set(skipped):
            raise DeploymentError('--skip-stopped must name exactly existing stopped labeled customers')
        if not tenants:
            raise DeploymentError('No running customers; refusing empty deployment')
        admin = self.inspect('sentinel-admin')
        if not admin['State']['Running']:
            raise DeploymentError('Previous compatible admin must be running')
        self.image(admin['Image'])
        for tenant in sorted(tenants):
            self.image(tenants[tenant])
            fingerprint = host_key_check(tenant)
            self.runtime('sentinel-' + tenant, fingerprint)
        env = dict(os.environ, ARCKON_ADMIN_IMAGE=args.admin_image)
        config = json.loads(run(self.compose + ['config', '--format', 'json'], env=env))
        if config['services']['user-manager']['image'] != args.admin_image:
            raise DeploymentError('Compose must use ARCKON_ADMIN_IMAGE for user-manager.image')
        active = json.loads(run(['docker', 'exec', '-i', 'sentinel-admin', 'python3', '-'],
                                input=ADMIN_INVENTORY))
        if set(active) != set(tenants):
            raise DeploymentError('Admin active customers differ from running labeled customers; resolve lifecycle first')
        aliases = {'mark-sentinel:latest': args.tenant_image,
                   'gcp-user-manager:hardened': args.admin_image}
        previous_aliases = {}
        for alias in aliases:
            previous_aliases[alias] = json.loads(run(['docker', 'image', 'inspect', alias]))[0]['Id']
            self.image(previous_aliases[alias])
        # --check does not create transient smoke accounts or recreate workloads.
        print(json.dumps({'tenants': sorted(tenants), 'skipped_stopped': sorted(skipped),
                          'revision': args.revision, 'check': args.check}), flush=True)
        if args.check:
            return
        # Preserve locally available rollback images against ordinary image prune.
        run(['docker', 'image', 'tag', admin['Image'], 'arckon-rollback-admin:' + args.revision])
        for tenant, image in tenants.items():
            run(['docker', 'image', 'tag', image, 'arckon-rollback-' + tenant + ':' + args.revision])
        for index, image in enumerate(previous_aliases.values()):
            run(['docker', 'image', 'tag', image, 'arckon-rollback-alias-' + str(index) + ':' + args.revision])
        journal = {'revision': args.revision, 'tenant_image': args.tenant_image,
                   'admin_image': args.admin_image, 'previous_admin': admin['Image'],
                   'previous_tenants': tenants, 'skipped_stopped': sorted(skipped),
                   'previous_aliases': previous_aliases, 'aliases_changed': [],
                   'changed': [], 'status': 'deploying'}
        save(journal_path, journal)
        admin_changed = False
        try:
            # Journal intent BEFORE a destructive command, including failed recreates.
            admin_changed = True
            journal['admin_changed'] = True
            save(journal_path, journal)
            self.admin(args.admin_image)
            order = sorted(tenants, key=lambda t: (t != 'opco', t))
            for index, tenant in enumerate(order):
                journal['changed'].append(tenant)
                save(journal_path, journal)
                self.tenant(tenant, args.tenant_image)
                if index == 0 and len(order) > 1:
                    self.smoke(tenants)
            self.smoke(tenants)
            # Promote defaults only after all runtime/public gates. Docker cannot
            # atomically update two tags, so journal intent and compensate failures.
            for alias, image in aliases.items():
                journal['aliases_changed'].append(alias)
                save(journal_path, journal)
                run(['docker', 'image', 'tag', image, alias])
                actual = json.loads(run(['docker', 'image', 'inspect', alias]))[0]['Id']
                if actual != image:
                    raise DeploymentError('Lifecycle alias promotion verification failed: ' + alias)
        except BaseException:
            errors = []
            for alias in reversed(journal['aliases_changed']):
                try:
                    run(['docker', 'image', 'tag', previous_aliases[alias], alias])
                    actual = json.loads(run(['docker', 'image', 'inspect', alias]))[0]['Id']
                    if actual != previous_aliases[alias]:
                        raise DeploymentError('Lifecycle alias rollback verification failed')
                except BaseException:
                    errors.append('alias:' + alias)
            # Restore compatible admin first, including its nginx DNS binding.
            if admin_changed:
                try:
                    self.admin(admin['Image'])
                except BaseException:
                    errors.append('admin')
            for tenant in reversed(journal['changed']):
                try:
                    self.tenant(tenant, tenants[tenant])
                except BaseException:
                    errors.append(tenant)
            try:
                self.smoke(tenants)
            except BaseException:
                errors.append('public-smoke')
            journal['status'] = 'rollback_failed' if errors else 'rolled_back'
            journal['rollback_errors'] = errors
            save(journal_path, journal)
            raise DeploymentError('Deployment failed; rollback status: ' + journal['status']) from None
        # Publication errors must not trigger rollback after a success marker may
        # already have been atomically replaced. An unfinished journal fails shut.
        journal['status'] = 'succeeded'
        save(args.state_dir / 'successful.json', journal)
        save(journal_path, journal)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--tenant-image', required=True)
    parser.add_argument('--admin-image', required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--state-dir', type=Path, default=Path('/opt/arckon-deploy'))
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--skip-stopped', action='append', default=[], metavar='ID',
                        help='explicitly acknowledge an intentionally stopped customer (repeatable)')
    args = parser.parse_args(argv)
    if not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', args.revision):
        parser.error('--revision must be a full 40- or 64-character lowercase hash')
    try:
        if os.geteuid() != 0:
            raise DeploymentError('Run as root on the Docker host')
        args.state_dir = args.state_dir.absolute()
        for path in (args.state_dir, *args.state_dir.parents):
            if path.is_symlink():
                raise DeploymentError('Symlinked state directory')
        args.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = args.state_dir.stat()
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            raise DeploymentError('State directory must be root-owned mode 0700')
        fd = os.open(args.state_dir / 'deploy.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            def interrupted(signum, frame):
                raise DeploymentError('Deployment interrupted')
            signal.signal(signal.SIGTERM, interrupted)
            Engine(args).deploy()
    except (DeploymentError, OSError, ValueError, KeyError) as exc:
        # Never print raw filesystem/key-validation exceptions with secret content.
        print(str(exc) if isinstance(exc, DeploymentError) else 'Deployment preflight/state validation failed', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
