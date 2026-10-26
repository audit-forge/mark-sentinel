"""Local-only security preflight and lifecycle tests; Docker is always stubbed."""
import base64
import importlib.util
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import sys

import pytest


REPO = Path(__file__).resolve().parents[1]
GCP = REPO / 'deploy/gcp'
spec = importlib.util.spec_from_file_location('customer_security', GCP / 'prepare_customer_security.py')
security = importlib.util.module_from_spec(spec)
spec.loader.exec_module(security)


@pytest.fixture
def layout(tmp_path, monkeypatch):
    # Exercise real file modes without requiring root on developer machines.
    monkeypatch.setattr(security, 'CUSTOMER_UID', os.geteuid())
    fchown = os.fchown
    monkeypatch.setattr(security.os, 'fchown', lambda fd, uid, gid: fchown(fd, uid, -1))
    monkeypatch.delenv('ARCKON_OUTBOUND_PRIVATE_ORIGINS', raising=False)
    root = tmp_path.resolve() / 'data'
    root.mkdir()
    return root, root / '.field-secrets'


def test_new_tenant_key_is_private_random_and_never_replaced(layout):
    root, secrets = layout
    security.prepare('acme', root, secrets, provision=True)
    key = secrets / 'acme/master-key'
    original = key.read_bytes()
    assert len(base64.b64decode(original)) == 32
    assert stat.S_IMODE(key.stat().st_mode) == 0o400
    assert key.stat().st_uid == os.geteuid()
    assert stat.S_IMODE(key.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(secrets.stat().st_mode) == 0o700
    (root / 'acme').mkdir()
    (root / 'acme/siem_config.json').write_text('{}')
    security.prepare('acme', root, secrets, provision=False)
    security.prepare('acme', root, secrets, provision=True)
    assert key.read_bytes() == original
    security.prepare('other', root, secrets, provision=True)
    assert (secrets / 'other/master-key').read_bytes() != original


@pytest.mark.parametrize('filename', ['agents.db', 'sentinel.db', 'siem_config.json', 'unknown'])
def test_provision_never_generates_key_for_existing_data(layout, filename):
    root, secrets = layout
    (root / 'acme').mkdir()
    (root / 'acme' / filename).touch()
    with pytest.raises(ValueError, match='offline migration'):
        security.prepare('acme', root, secrets, provision=True)
    assert not (secrets / 'acme/master-key').exists()


def test_restart_never_generates_key_even_without_data(layout):
    root, secrets = layout
    with pytest.raises(ValueError, match='offline migration'):
        security.prepare('acme', root, secrets, provision=False)
    assert not (secrets / 'acme/master-key').exists()


@pytest.mark.parametrize('bad_key', ['public', 'writable', 'symlink', 'directory', 'invalid', 'hardlink', 'owner', 'pending'])
def test_invalid_key_fails_closed(layout, bad_key):
    root, secrets = layout
    security.prepare('acme', root, secrets, provision=True)
    key = secrets / 'acme/master-key'
    if bad_key == 'public':
        key.chmod(0o444)
    elif bad_key == 'writable':
        key.chmod(0o600)
    elif bad_key == 'symlink':
        key.rename(key.with_name('original'))
        key.symlink_to('original')
    elif bad_key == 'directory':
        key.unlink()
        key.mkdir()
    elif bad_key == 'invalid':
        key.chmod(0o600)
        key.write_text('not a key')
        key.chmod(0o400)
    elif bad_key == 'hardlink':
        os.link(key, key.with_name('alias'))
    elif bad_key == 'owner':
        security.CUSTOMER_UID = os.geteuid() + 1
    else:
        key.with_name('master-key.migration-pending').touch()
    with pytest.raises((OSError, ValueError)):
        security.prepare('acme', root, secrets, provision=False)


@pytest.mark.parametrize('location', ['tenant-data', 'symlink', 'writable-directory'])
def test_reject_tenant_controlled_secret_locations(layout, location):
    root, secrets = layout
    (root / 'acme').mkdir()
    if location == 'tenant-data':
        secrets = root / 'acme/secrets'
    elif location == 'symlink':
        (root / 'actual').mkdir()
        secrets.symlink_to(root / 'actual', target_is_directory=True)
    else:
        secrets.mkdir(mode=0o777)
        secrets.chmod(0o777)
    with pytest.raises(ValueError):
        security.prepare('acme', root, secrets, provision=True)


@pytest.mark.parametrize('customer', ['../escape', '', 'acme/other', '.field-secrets', 'x\ny'])
def test_invalid_customer_ids_are_rejected(layout, customer):
    with pytest.raises(ValueError, match='customer ID'):
        security.prepare(customer, *layout, provision=True)


def test_operator_policy_is_tenant_scoped_and_cannot_inject_env(layout, monkeypatch):
    root, secrets = layout
    policy = {'https://siem.internal:443': ['10.0.0.1/32']}
    monkeypatch.setenv('ARCKON_OUTBOUND_PRIVATE_ORIGINS', json.dumps(policy))
    security.prepare('acme', root, secrets, provision=True)
    env = secrets / 'acme/runtime.env'
    assert stat.S_IMODE(env.stat().st_mode) == 0o600
    assert json.loads(env.read_text().split('=', 1)[1]) == policy
    override = {'https://other.internal': ['192.168.1.2/32'], 'injection\nARCKON_MASTER_KEY=bad': []}
    policy_file = secrets / 'acme/outbound-private-origins.json'
    policy_file.write_text(json.dumps(override))
    policy_file.chmod(0o600)
    security.prepare('acme', root, secrets, provision=False)
    assert len(env.read_text().splitlines()) == 1
    assert json.loads(env.read_text().split('=', 1)[1]) == override
    security.prepare('other', root, secrets, provision=True)
    assert json.loads((secrets / 'other/runtime.env').read_text().split('=', 1)[1]) == policy
    policy_file.chmod(0o666)
    with pytest.raises(ValueError):
        security.prepare('acme', root, secrets, provision=False)


@pytest.fixture
def shell_env(layout, tmp_path):
    root, secrets = layout
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    # Run the actual helper, changing only the UID for unprivileged local tests.
    wrapper = f'''#!{sys.executable}
import importlib.util, os, pathlib, sys
if sys.argv[1].endswith('prepare_customer_security.py'):
    spec = importlib.util.spec_from_file_location('security', sys.argv[1])
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.CUSTOMER_UID = os.geteuid()
    fchown = os.fchown
    os.fchown = lambda fd, uid, gid: fchown(fd, uid, -1)
    try:
        module.prepare(sys.argv[2], pathlib.Path(os.environ['SENTINEL_DATA_ROOT']),
                       pathlib.Path(os.environ['SENTINEL_FIELD_SECRET_ROOT']),
                       provision='--provision' in sys.argv)
    except (OSError, ValueError) as exc:
        print(exc, file=sys.stderr)
        sys.exit(1)
else:
    os.execv({sys.executable!r}, [{sys.executable!r}, *sys.argv[1:]])
'''
    (bin_dir / 'python3').write_text(wrapper)
    (bin_dir / 'docker').write_text(
        f'#!{sys.executable}\nimport json, os, sys\n'
        "with open(os.environ['DOCKER_LOG'], 'a') as f: f.write(json.dumps(sys.argv[1:]) + '\\n')\n"
        "sys.exit(42 if sys.argv[1] == 'run' else 0)\n")
    for command in ('install', 'chown', 'chmod'):
        (bin_dir / command).write_text('#!/bin/sh\nexit 0\n')
    for command in bin_dir.iterdir():
        command.chmod(0o755)
    nginx = tmp_path / 'nginx'
    nginx.mkdir()
    env = dict(os.environ, PATH=f'{bin_dir}:{os.environ["PATH"]}',
               SENTINEL_DATA_ROOT=str(root), SENTINEL_FIELD_SECRET_ROOT=str(secrets),
               NGINX_PROXY_TOKEN_DIR=str(nginx), DOCKER_LOG=str(tmp_path / 'docker.log'),
               PUBLIC_ADMIN_URL='https://admin.example.test',
               PUBLIC_DASHBOARD_URL='https://dashboard.example.test')
    return env


@pytest.mark.parametrize('bad_key', ['missing', 'public', 'symlink', 'invalid'])
def test_restart_failure_never_calls_docker(layout, shell_env, bad_key):
    root, secrets = layout
    (root / 'acme').mkdir()
    if bad_key != 'missing':
        security.prepare('acme', root, secrets, provision=True)
        key = secrets / 'acme/master-key'
        if bad_key == 'public':
            key.chmod(0o444)
        elif bad_key == 'symlink':
            key.unlink()
            key.symlink_to('missing')
        else:
            key.chmod(0o600)
            key.write_text('invalid')
            key.chmod(0o400)
    result = subprocess.run(['bash', str(GCP / 'restart_customer.sh'), 'acme'],
                            env=shell_env, capture_output=True, text=True)
    assert result.returncode != 0
    assert not Path(shell_env['DOCKER_LOG']).exists()


@pytest.mark.parametrize('script', ['provision_customer.sh', 'restart_customer.sh'])
def test_lifecycle_passes_only_tenant_key_and_security_environment(layout, shell_env, script):
    root, secrets = layout
    if script.startswith('restart'):
        security.prepare('acme', root, secrets, provision=True)
        (root / 'acme').mkdir()
        (root / 'acme/agent_token.txt').write_text('existing-agent-token')
    result = subprocess.run(['bash', str(GCP / script), 'acme', '127.0.0.1'],
                            env=shell_env, capture_output=True, text=True)
    assert result.returncode == 42, result.stderr  # stub stops at docker run
    calls = [json.loads(line) for line in Path(shell_env['DOCKER_LOG']).read_text().splitlines()]
    run = next(call for call in calls if call[0] == 'run')
    args = shlex.join(run)
    assert f'type=bind,src={secrets}/acme/master-key,dst=/run/secrets/arckon_master_key,readonly' in run
    assert 'ARCKON_MASTER_KEY_FILE=/run/secrets/arckon_master_key' in run
    assert 'PUBLIC_ADMIN_URL=https://admin.example.test' in run
    assert 'PUBLIC_DASHBOARD_URL=https://dashboard.example.test' in run
    assert f'{secrets}/acme/runtime.env' in run
    assert 'SENTINEL_ADMIN_LOGOUT_URL=https://admin.example.test/logout' in run
    assert 'SENTINEL_TRUSTED_PROXY_TOKEN_FILE=/run/secrets/proxy_token' in run
    assert f'{secrets}:' not in args
    assert not any(value.startswith('ARCKON_MASTER_KEY=') for value in run)
    assert 'migrate_field_encryption' not in (GCP / script).read_text()
    if script.startswith('restart'):
        assert calls[0] == ['rm', '-f', 'sentinel-acme']


def test_secret_artifacts_are_excluded_from_git_and_docker():
    for filename in ('.gitignore', '.dockerignore'):
        lines = (REPO / filename).read_text().splitlines()
        for pattern in ('.field-secrets/', 'master-key', 'master-key.*',
                        'runtime.env', 'outbound-private-origins.json', 'siem_config.json'):
            assert pattern in lines
