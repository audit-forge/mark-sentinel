"""Standalone preflight and stubbed launcher tests. No real server or deployment."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys

import pytest


REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('local_security', REPO / 'scripts/prepare_local_security.py')
security = importlib.util.module_from_spec(spec)
spec.loader.exec_module(security)


@pytest.fixture
def layout(tmp_path, monkeypatch):
    monkeypatch.delenv('ARCKON_MASTER_KEY', raising=False)
    monkeypatch.delenv('ARCKON_MASTER_KEY_FILE', raising=False)
    project = tmp_path.resolve() / 'project'
    project.mkdir()
    return project, project / '.field-secrets/master-key'


def test_new_key_random_private_persistent_and_runtime_compatible(layout, capsys):
    project, key = layout
    security.prepare(project, key)
    original = key.read_bytes()
    assert len(base64.b64decode(original, validate=False)) == 32
    assert key.stat().st_uid == os.geteuid()
    assert stat.S_IMODE(key.stat().st_mode) == 0o600
    assert stat.S_IMODE(key.parent.stat().st_mode) == 0o700
    (project / 'data').mkdir()
    (project / 'data/agents.db').touch()
    security.prepare(project, key)
    assert key.read_bytes() == original
    from crypto import _load_key_file
    assert _load_key_file(str(key)) == base64.b64decode(original)
    other = project / 'other'
    other.mkdir()
    other_key = other / '.field-secrets/master-key'
    security.prepare(other, other_key)
    assert other_key.read_bytes() != original
    assert capsys.readouterr() == ('', '')


@pytest.mark.parametrize('name', ['data/agents.db', 'data/siem_config.json', 'data/unknown',
                                 'data/customers', 'siem_config.json'])
def test_old_data_requires_explicit_migration(layout, name):
    project, key = layout
    target = project / name
    target.parent.mkdir(exist_ok=True)
    target.touch()
    with pytest.raises(ValueError, match='explicit offline migration'):
        security.prepare(project, key)
    assert not key.exists()


@pytest.mark.parametrize('kind', ['public', 'executable', 'invalid', 'short', 'symlink',
                                 'directory', 'hardlink', 'parent', 'pending', 'legacy', 'owner'])
def test_unsafe_keys_fail_closed_without_replacement(layout, monkeypatch, kind):
    project, key = layout
    security.prepare(project, key)
    if kind == 'public':
        key.chmod(0o644)
    elif kind == 'executable':
        key.chmod(0o700)
    elif kind == 'invalid':
        key.write_text('invalid secret input')
    elif kind == 'short':
        key.write_text(base64.b64encode(b'short').decode())
    elif kind == 'symlink':
        key.rename(key.with_name('original'))
        key.symlink_to('original')
    elif kind == 'directory':
        key.unlink()
        key.mkdir()
    elif kind == 'hardlink':
        os.link(key, key.with_name('alias'))
    elif kind == 'parent':
        key.parent.chmod(0o755)
    elif kind == 'pending':
        key.with_name(key.name + '.migration-pending').touch()
    elif kind == 'legacy':
        key.write_text(hashlib.sha256(b'arckon-dev-key-DO-NOT-USE-IN-PROD').hexdigest())
    else:
        monkeypatch.setattr(security.os, 'geteuid', lambda: key.stat().st_uid + 1)
    before = key.read_bytes() if key.is_file() else None
    with pytest.raises((OSError, ValueError)):
        security.prepare(project, key)
    if before is not None:
        assert key.read_bytes() == before


def test_explicit_key_and_raw_environment(layout, monkeypatch):
    project, default = layout
    external = project / 'private'
    external.mkdir(mode=0o700)
    key = external / 'key'
    with pytest.raises(ValueError, match='already exist'):
        security.prepare(project, key)
    key.write_text(os.urandom(32).hex())
    key.chmod(0o400)
    security.prepare(project, key)
    assert not default.exists()
    monkeypatch.setenv('ARCKON_MASTER_KEY', 'must-not-be-output')
    with pytest.raises(ValueError, match='not a raw'):
        security.prepare(project, key)


@pytest.fixture
def launcher(layout):
    project, key = layout
    (project / 'scripts').mkdir()
    shutil.copy(REPO / 'scripts/prepare_local_security.py', project / 'scripts')
    for name in ('launch_arckon.sh', 'launch_sentinel.sh'):
        shutil.copy(REPO / name, project / name)
    app_launcher = project / 'Sentinel.app/Contents/MacOS/Sentinel'
    app_launcher.parent.mkdir(parents=True)
    shutil.copy(REPO / 'Sentinel.app/Contents/MacOS/Sentinel', app_launcher)
    (project / 'server.py').write_text(
        'import json, os, pathlib\n'
        'pathlib.Path(os.environ["STARTED"]).write_text(json.dumps({k: os.environ.get(k) '
        'for k in ("ARCKON_MASTER_KEY_FILE", "PUBLIC_ADMIN_URL", "PUBLIC_DASHBOARD_URL")}))\n')
    bin_dir = project / 'bin'
    bin_dir.mkdir()
    for name in ('python3.14', 'python3.13', 'python3.12', 'python3.11', 'python3'):
        (bin_dir / name).symlink_to(sys.executable)
    (bin_dir / 'curl').write_text('#!/bin/sh\ntest -f "$STARTED"\n')
    (bin_dir / 'xdg-open').write_text('#!/bin/sh\nexit 0\n')
    (bin_dir / 'open').write_text('#!/bin/sh\nexit 0\n')
    (bin_dir / 'open').chmod(0o755)
    (bin_dir / 'curl').chmod(0o755)
    (bin_dir / 'xdg-open').chmod(0o755)
    env = dict(os.environ, PATH=f'{bin_dir}:{os.environ["PATH"]}', STARTED=str(project / 'started'))
    return project, key, env


@pytest.mark.parametrize('script', ['launch_arckon.sh', 'launch_sentinel.sh',
                                    'Sentinel.app/Contents/MacOS/Sentinel'])
@pytest.mark.parametrize('lan', [False, True])
def test_launcher_prepares_key_and_passes_explicit_origins(launcher, script, lan):
    project, key, env = launcher
    if lan:
        env.update(PUBLIC_ADMIN_URL='http://192.168.1.10:8000',
                   PUBLIC_DASHBOARD_URL='http://192.168.1.10:7331')
    else:
        env.pop('PUBLIC_ADMIN_URL', None)
        env.pop('PUBLIC_DASHBOARD_URL', None)
    result = subprocess.run(['bash', str(project / script)], env=env,
                            capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    started = json.loads(Path(env['STARTED']).read_text())
    assert started['ARCKON_MASTER_KEY_FILE'] == str(key)
    assert started['PUBLIC_DASHBOARD_URL'] == env.get('PUBLIC_DASHBOARD_URL', 'http://localhost:7331')
    assert started['PUBLIC_ADMIN_URL'] == env.get('PUBLIC_ADMIN_URL', 'http://localhost:7331')
    assert key.read_text().strip() not in result.stdout + result.stderr


@pytest.mark.parametrize('script', ['launch_arckon.sh', 'launch_sentinel.sh',
                                    'Sentinel.app/Contents/MacOS/Sentinel'])
@pytest.mark.parametrize('failure', ['old-data', 'invalid-key', 'raw-key', 'empty-file'])
def test_launcher_failure_never_starts_server(launcher, script, failure):
    project, key, env = launcher
    if failure == 'old-data':
        (project / 'data').mkdir()
        (project / 'data/agents.db').touch()
    elif failure == 'invalid-key':
        security.prepare(project, key)
        key.write_text('private invalid key material')
    elif failure == 'raw-key':
        env['ARCKON_MASTER_KEY'] = 'private raw key material'
    else:
        env['ARCKON_MASTER_KEY_FILE'] = ''
    result = subprocess.run(['bash', str(project / script)], env=env,
                            capture_output=True, text=True, timeout=15)
    assert result.returncode != 0
    assert not Path(env['STARTED']).exists()
    assert 'private invalid key material' not in result.stdout + result.stderr
    assert 'private raw key material' not in result.stdout + result.stderr
    assert not list(project.glob('.*.log'))


def test_deploy_preserves_credential_without_source_literal():
    source = (REPO / 'deploy-local.sh').read_text()
    assert '-e ARCKON_AGENT_TOKEN=' not in source
    assert 'docker inspect $CONTAINER' in source
    assert source.index('docker inspect') < source.index('docker stop')
    assert '--env-file' in source
    assert 'os.fchmod(stream.fileno(), 0o600)' in source


@pytest.mark.parametrize('token', ['synthetic-token-not-a-real-credential', '', 'bad\ninjection'])
def test_deploy_remote_token_handoff_is_private_exact_and_cleaned(tmp_path, token):
    source = (REPO / 'deploy-local.sh').read_text()
    # Ask bash to expand the real SSH command, but never call gcloud or Docker.
    ssh = source[source.index('gcloud compute ssh'):source.index('\necho ""')]
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    capture = tmp_path / 'ssh.json'
    gcloud = bin_dir / 'gcloud'
    gcloud.write_text(f'#!{sys.executable}\nimport json, os, pathlib, sys\n'
                      'pathlib.Path(os.environ["CAPTURE"]).write_text(json.dumps(sys.argv))\n')
    gcloud.chmod(0o755)
    sudo = bin_dir / 'sudo'
    sudo.write_text(f'''#!{sys.executable}
import json, os, pathlib, sys, tempfile
args = sys.argv[1:]
if args[0] == 'mktemp':
    fd, name = tempfile.mkstemp(dir=os.environ['TEST_TEMP'])
    os.close(fd)
    pathlib.Path(os.environ['ENV_PATH']).write_text(name)
    print(name)
elif args[:2] == ['docker', 'inspect']:
    print(json.dumps([{{'Config': {{'Env': ['ARCKON_AGENT_TOKEN=' + os.environ['TEST_TOKEN']]}}}}]))
elif args[0] == 'python3':
    os.execv({sys.executable!r}, [{sys.executable!r}, *args[1:]])
elif args[0] == 'rm':
    pathlib.Path(args[-1]).unlink()
else:
    sys.exit('Unexpected command')
''')
    sudo.chmod(0o755)
    env = dict(os.environ, PATH=f'{bin_dir}:{os.environ["PATH"]}', CAPTURE=str(capture),
               TEST_TEMP=str(tmp_path), ENV_PATH=str(tmp_path / 'env-path'), TEST_TOKEN=token)
    expanded = subprocess.run(['bash', '-c', 'VM=test PROJECT=test ZONE=test CONTAINER=test IMAGE=test\n' + ssh],
                              env=env, capture_output=True, text=True)
    assert expanded.returncode == 0, expanded.stderr
    remote = next(arg.split('=', 1)[1] for arg in json.loads(capture.read_text())
                  if arg.startswith('--command='))
    handoff = remote[remote.index('TOKEN_ENV='):remote.index("echo '  -> Stopping old container...'")]
    check = '''python3 -c 'import os, pathlib, stat, sys
p = pathlib.Path(sys.argv[1])
assert stat.S_IMODE(p.stat().st_mode) == 0o600
assert p.read_text() == "ARCKON_AGENT_TOKEN=" + os.environ["TEST_TOKEN"] + "\\n"
' "$TOKEN_ENV"
'''
    result = subprocess.run(['bash', '-c', 'set -e\n' + handoff + check],
                            env=env, capture_output=True, text=True)
    assert (result.returncode == 0) == bool(token and '\n' not in token)
    assert not Path(Path(env['ENV_PATH']).read_text()).exists()
    if token:
        assert token not in result.stdout + result.stderr
