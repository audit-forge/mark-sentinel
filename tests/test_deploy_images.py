"""Process-run Docker simulation only. Never connects to a Docker daemon."""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess

import pytest


REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('deploy_images', REPO / 'scripts/deploy_images.py')
deploy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(deploy)
OLD = 'sha256:' + '1' * 64
OLD_ADMIN = 'sha256:' + '2' * 64
NEW = 'sha256:' + '3' * 64
NEW_ADMIN = 'sha256:' + '4' * 64
REVISION = 'a' * 40
OLD_ALIASES = {'mark-sentinel:latest': 'sha256:' + '5' * 64,
               'gcp-user-manager:hardened': 'sha256:' + '6' * 64}


class Docker:
    def __init__(self):
        self.images = {'sentinel-admin': OLD_ADMIN, 'sentinel-mfd': OLD,
                       'sentinel-opco': OLD, 'sentinel-zeta': OLD}
        self.stopped = set()
        self.calls = []
        self.fail_tenant = None
        self.fail_admin = False
        self.bad_override = False
        self.fail_smoke = False
        self.fail_rollback = False
        self.smoke_tenants = ['mfd', 'opco', 'zeta']
        self.key_failure = None
        self.aliases = dict(OLD_ALIASES)
        self.fail_alias = None
        self.fail_alias_restore = None

    def run(self, argv, *, env=None, input=None, **kwargs):
        self.calls.append((argv, env, input))
        output, rc = '', 0
        if argv[:3] == ['docker', 'image', 'inspect']:
            output = json.dumps([{'Id': self.aliases.get(argv[3], argv[3])}])
        elif argv[:3] == ['docker', 'image', 'tag']:
            image, alias = argv[3:]
            if alias in self.aliases:
                if alias == self.fail_alias_restore and image == OLD_ALIASES[alias]:
                    rc = 1
                else:
                    self.aliases[alias] = image
                    # Simulate failure after mutation to require intent journaling.
                    rc = int(alias == self.fail_alias and image in (NEW, NEW_ADMIN))
        elif argv[:2] == ['docker', 'inspect']:
            name = argv[2]
            output = json.dumps([{'Image': self.images[name],
                                  'State': {'Running': name not in self.stopped},
                                  'Config': {'Labels': {'sentinel.customer': name.removeprefix('sentinel-')}}}])
        elif argv[:2] == ['docker', 'ps']:
            output = '\n'.join(n for n in self.images if n != 'sentinel-admin')
        elif argv[:2] == ['docker', 'compose']:
            image = env['ARCKON_ADMIN_IMAGE']
            if 'config' in argv:
                output = json.dumps({'services': {'user-manager': {
                    'image': 'mutable:latest' if self.bad_override else image}}})
            else:
                self.images['sentinel-admin'] = image
                rc = int(self.fail_admin and image == NEW_ADMIN)
        elif argv[0] == 'bash':
            tenant, image = argv[-1], env['SENTINEL_IMAGE']
            self.images['sentinel-' + tenant] = image
            rc = int((tenant == self.fail_tenant and image == NEW)
                     or (self.fail_rollback and image == OLD))
        elif argv[:3] == ['docker', 'exec', '-i']:
            if argv[3] == 'sentinel-admin':
                if input == deploy.ADMIN_INVENTORY:
                    output = json.dumps([n.removeprefix('sentinel-') for n in self.images
                                         if n != 'sentinel-admin' and n not in self.stopped])
                else:
                    rc = int(self.fail_smoke and self.images['sentinel-admin'] == NEW_ADMIN)
                    output = '\n'.join(t + ': single login, shared cookie, dashboard APIs, enrollment, CSRF, passive queue, logout PASS'
                                       for t in self.smoke_tenants)
            elif self.key_failure == argv[3]:
                rc = 1
        elif argv[:2] != ['docker', 'exec']:
            raise AssertionError(argv)
        return subprocess.CompletedProcess(argv, rc, output, 'SECRET MUST NOT BE PRINTED')

    def mutations(self):
        return [(argv, env) for argv, env, _ in self.calls
                if argv[0] == 'bash' or (argv[:2] == ['docker', 'compose'] and 'up' in argv)]


@pytest.fixture
def setup(tmp_path, monkeypatch):
    docker = Docker()
    monkeypatch.setattr(deploy.subprocess, 'run', docker.run)
    monkeypatch.setattr(deploy, 'host_key_check', lambda tenant: 'f' * 64)
    args = argparse.Namespace(tenant_image=NEW, admin_image=NEW_ADMIN,
                              revision=REVISION, state_dir=tmp_path, check=False,
                              skip_stopped=[])
    return docker, args, deploy.Engine(args)


def test_full_rollout_all_tenants_canary_first_and_success_after_smoke(setup, monkeypatch):
    docker, args, engine = setup
    original = deploy.save
    def verify_publication(path, value):
        if path.name == 'successful.json':
            assert docker.aliases == {'mark-sentinel:latest': NEW, 'gcp-user-manager:hardened': NEW_ADMIN}
            journal = json.loads((args.state_dir / 'transaction.json').read_text())
            assert set(journal['aliases_changed']) == set(OLD_ALIASES)
            assert journal['previous_aliases'] == OLD_ALIASES
        original(path, value)
    monkeypatch.setattr(deploy, 'save', verify_publication)
    engine.deploy()
    changes = docker.mutations()
    assert changes[0][0][-1] == 'user-manager'
    assert [argv[-1] for argv, _ in changes[1:]] == ['opco', 'mfd', 'zeta']
    assert all(env['SENTINEL_IMAGE'] == NEW for _, env in changes[1:])
    assert {'--no-build', '--no-deps', '--force-recreate', '--pull', 'never'} <= set(changes[0][0])
    state = json.loads((args.state_dir / 'successful.json').read_text())
    assert state['revision'] == REVISION
    assert state['previous_admin'] == OLD_ADMIN
    assert state['previous_tenants'] == dict.fromkeys(['mfd', 'opco', 'zeta'], OLD)
    assert state['previous_aliases'] == OLD_ALIASES
    assert docker.aliases == {'mark-sentinel:latest': NEW, 'gcp-user-manager:hardened': NEW_ADMIN}
    smoke = [c for c in docker.calls if c[0][:4] == ['docker', 'exec', '-i', 'sentinel-admin']
             and c[2] != deploy.ADMIN_INVENTORY]
    assert len(smoke) == 2 and 'transient test accounts' in smoke[0][2]
    first_alias = next(i for i, call in enumerate(docker.calls)
                       if call[0][:3] == ['docker', 'image', 'tag'] and call[0][-1] in OLD_ALIASES)
    assert all(index < first_alias for index, call in enumerate(docker.calls)
               if call[0][:4] == ['docker', 'exec', '-i', 'sentinel-admin']
               and call[2] != deploy.ADMIN_INVENTORY)


def test_check_is_read_only_and_checks_every_tenant(setup):
    docker, args, engine = setup
    args.check = True
    engine.deploy()
    assert not docker.mutations()
    assert not any(c[0][:3] == ['docker', 'image', 'tag'] for c in docker.calls)
    assert not (args.state_dir / 'successful.json').exists()
    assert len([c for c in docker.calls if c[2] and 'hashlib.sha256(key)' in c[2]]) == 3
    assert not any(c[0][:4] == ['docker', 'exec', '-i', 'sentinel-admin']
                   and c[2] != deploy.ADMIN_INVENTORY for c in docker.calls)


@pytest.mark.parametrize('image', ['latest', 'repo:latest', 'repo@sha256:' + 'a' * 64, 'sha256:bad'])
def test_rejects_non_local_immutable_id(setup, image):
    docker, args, engine = setup
    args.tenant_image = image
    with pytest.raises(deploy.DeploymentError, match='immutable'):
        engine.deploy()
    assert not docker.mutations()


def test_stopped_customer_is_not_silently_omitted(setup):
    docker, _, engine = setup
    docker.stopped.add('sentinel-zeta')
    with pytest.raises(deploy.DeploymentError, match='Stopped labeled customer'):
        engine.deploy()
    assert not docker.mutations()


def test_explicit_stopped_acknowledgment_is_reported_and_not_restarted(setup):
    docker, args, engine = setup
    docker.stopped.add('sentinel-zeta')
    docker.smoke_tenants.remove('zeta')  # inactive/suspended admin registry entry
    args.skip_stopped = ['zeta']
    engine.deploy()
    assert docker.images['sentinel-zeta'] == OLD
    state = json.loads((args.state_dir / 'successful.json').read_text())
    assert state['skipped_stopped'] == ['zeta']
    assert set(state['previous_tenants']) == {'mfd', 'opco'}


def test_cannot_skip_running_or_nonexistent_customer(setup):
    docker, args, engine = setup
    args.skip_stopped = ['mfd']
    with pytest.raises(deploy.DeploymentError, match='exactly existing stopped'):
        engine.deploy()
    assert not docker.mutations()


def test_success_publication_failure_does_not_rollback_a_published_revision(setup, monkeypatch):
    docker, args, engine = setup
    original = deploy.save
    def fail_final_journal(path, value):
        if path.name == 'transaction.json' and value['status'] == 'succeeded':
            raise OSError('simulated fsync failure')
        original(path, value)
    monkeypatch.setattr(deploy, 'save', fail_final_journal)
    with pytest.raises(OSError):
        engine.deploy()
    assert docker.images['sentinel-admin'] == NEW_ADMIN
    assert docker.aliases == {'mark-sentinel:latest': NEW, 'gcp-user-manager:hardened': NEW_ADMIN}
    assert json.loads((args.state_dir / 'successful.json').read_text())['revision'] == REVISION
    with pytest.raises(deploy.DeploymentError, match='operator recovery'):
        engine.deploy()


@pytest.mark.parametrize('failure', ['host', 'runtime', 'compose'])
def test_all_preflight_failures_precede_any_mutation(setup, monkeypatch, failure):
    docker, _, engine = setup
    if failure == 'host':
        def invalid(tenant):
            if tenant == 'zeta':
                raise deploy.DeploymentError('bad key')
        monkeypatch.setattr(deploy, 'host_key_check', invalid)
    elif failure == 'runtime':
        docker.key_failure = 'sentinel-zeta'
    else:
        docker.bad_override = True
    with pytest.raises(deploy.DeploymentError):
        engine.deploy()
    assert not docker.mutations()


@pytest.mark.parametrize('failure', ['admin', 'opco', 'mfd', 'smoke'])
def test_rollback_proof_restores_failed_recreate_and_previous_admin(setup, failure):
    docker, args, engine = setup
    docker.fail_admin = failure == 'admin'
    docker.fail_tenant = failure if failure in ('opco', 'mfd') else None
    docker.fail_smoke = failure == 'smoke'
    with pytest.raises(deploy.DeploymentError, match='rolled_back'):
        engine.deploy()
    assert docker.images['sentinel-admin'] == OLD_ADMIN
    assert all(v == OLD for k, v in docker.images.items() if k != 'sentinel-admin')
    state = json.loads((args.state_dir / 'transaction.json').read_text())
    assert state['status'] == 'rolled_back'
    assert state['failure']['stage'] == {'admin': 'admin.recreate', 'opco': 'opco.restart',
                                         'mfd': 'mfd.restart', 'smoke': 'public-smoke.canary'}[failure]
    assert state['failure']['message'] == 'Command failed (exit 1)'
    assert not (args.state_dir / 'successful.json').exists()
    # Rollback only recreates images; no DB/key restore or Docker copy occurs.
    assert not any('cp' in c[0] or 'build' in c[0] or 'pull' in c[0] for c in docker.calls)
    assert docker.aliases == OLD_ALIASES


@pytest.mark.parametrize('alias', list(OLD_ALIASES))
def test_alias_publication_failure_restores_aliases_and_containers(setup, monkeypatch, alias):
    docker, args, engine = setup
    previous_success = {'revision': 'b' * 40}
    deploy.save(args.state_dir / 'successful.json', previous_success)
    docker.fail_alias = alias
    original = docker.run
    def journal_checked(argv, **kwargs):
        if argv[:3] == ['docker', 'image', 'tag'] and argv[-1] in OLD_ALIASES:
            journal = json.loads((args.state_dir / 'transaction.json').read_text())
            assert journal['previous_aliases'] == OLD_ALIASES
            assert argv[-1] in journal['aliases_changed']
            assert json.loads((args.state_dir / 'successful.json').read_text()) == previous_success
        return original(argv, **kwargs)
    monkeypatch.setattr(deploy.subprocess, 'run', journal_checked)
    with pytest.raises(deploy.DeploymentError, match='rolled_back'):
        engine.deploy()
    assert docker.aliases == OLD_ALIASES
    assert docker.images['sentinel-admin'] == OLD_ADMIN
    assert all(image == OLD for name, image in docker.images.items() if name != 'sentinel-admin')
    assert json.loads((args.state_dir / 'successful.json').read_text()) == previous_success
    assert json.loads((args.state_dir / 'transaction.json').read_text())['status'] == 'rolled_back'
    assert json.loads((args.state_dir / 'transaction.json').read_text())['failure'] == {
        'stage': 'alias.promote:' + alias, 'message': 'Command failed (exit 1)'}


def test_alias_restore_failure_blocks_next_deployment_without_publishing_success(setup):
    docker, args, engine = setup
    docker.fail_alias = 'gcp-user-manager:hardened'
    docker.fail_alias_restore = 'mark-sentinel:latest'
    with pytest.raises(deploy.DeploymentError, match='rollback_failed'):
        engine.deploy()
    journal = json.loads((args.state_dir / 'transaction.json').read_text())
    assert journal['rollback_errors'] == ['alias:mark-sentinel:latest']
    assert docker.aliases['mark-sentinel:latest'] == NEW
    assert docker.aliases['gcp-user-manager:hardened'] == OLD_ALIASES['gcp-user-manager:hardened']
    assert docker.images['sentinel-admin'] == OLD_ADMIN
    assert not (args.state_dir / 'successful.json').exists()
    docker.calls.clear()
    with pytest.raises(deploy.DeploymentError, match='operator recovery'):
        engine.deploy()
    assert not docker.calls


def test_rollback_failure_blocks_next_deployment_and_preserves_success(setup):
    docker, args, engine = setup
    previous = {'revision': 'b' * 40}
    deploy.save(args.state_dir / 'successful.json', previous)
    docker.fail_tenant, docker.fail_rollback = 'mfd', True
    with pytest.raises(deploy.DeploymentError, match='rollback_failed'):
        engine.deploy()
    assert json.loads((args.state_dir / 'successful.json').read_text()) == previous
    docker.calls.clear()
    with pytest.raises(deploy.DeploymentError, match='operator recovery'):
        engine.deploy()
    assert not docker.calls


def test_smoke_subset_does_not_publish_success(setup):
    docker, args, engine = setup
    docker.smoke_tenants = ['mfd']
    with pytest.raises(deploy.DeploymentError, match='rollback_failed'):
        engine.deploy()
    assert not (args.state_dir / 'successful.json').exists()


def test_command_failure_does_not_leak_output(setup):
    docker, _, _ = setup
    docker.fail_tenant = 'opco'
    with pytest.raises(deploy.DeploymentError) as error:
        deploy.run(['bash', 'restart', 'opco'], env={'SENTINEL_IMAGE': NEW})
    assert 'SECRET' not in str(error.value)


@pytest.mark.parametrize('stage', ['zeta.restart', 'zeta.verify', 'zeta.runtime',
                                   'public-smoke.canary', 'public-smoke.final'])
def test_failure_diagnosis_is_saved_before_rollback(setup, monkeypatch, capsys, stage):
    docker, args, engine = setup
    original = docker.run
    failed = False
    smoke_count = 0
    message = 'Command failed (exit 1)'

    def fail_at_stage(argv, **kwargs):
        nonlocal failed, smoke_count, message
        if failed:
            # The first rollback command must see the original failure on disk.
            journal = json.loads((args.state_dir / 'transaction.json').read_text())
            assert journal['failure'] == {'stage': stage, 'message': message}
        result = original(argv, **kwargs)
        if failed:
            return result
        is_smoke = (argv[:4] == ['docker', 'exec', '-i', 'sentinel-admin']
                    and kwargs.get('input') != deploy.ADMIN_INVENTORY)
        if is_smoke:
            smoke_count += 1
        if ((stage == 'zeta.restart' and argv[0] == 'bash' and argv[-1] == 'zeta')
                or (stage == 'zeta.runtime' and argv[:4] == ['docker', 'exec', '-i', 'sentinel-zeta']
                    and docker.images['sentinel-zeta'] == NEW)
                or (stage == 'public-smoke.canary' and is_smoke and smoke_count == 1)
                or (stage == 'public-smoke.final' and is_smoke and smoke_count == 2)):
            failed = True
            return subprocess.CompletedProcess(argv, 1, 'SECRET stdout', 'SECRET stderr')
        if (stage == 'zeta.verify' and argv == ['docker', 'inspect', 'sentinel-zeta']
                and docker.images['sentinel-zeta'] == NEW):
            failed = True
            message = 'Tenant image/running verification failed: zeta'
            info = json.loads(result.stdout)
            info[0]['State']['Running'] = False
            return subprocess.CompletedProcess(argv, 0, json.dumps(info), '')
        return result

    monkeypatch.setattr(deploy.subprocess, 'run', fail_at_stage)
    with pytest.raises(deploy.DeploymentError) as error:
        engine.deploy()
    assert failed
    assert stage in str(error.value) and message in str(error.value)
    journal = json.loads((args.state_dir / 'transaction.json').read_text())
    assert journal['status'] == 'rolled_back'
    assert journal['failure'] == {'stage': stage, 'message': message}
    assert docker.images['sentinel-admin'] == OLD_ADMIN
    assert docker.aliases == OLD_ALIASES
    assert all(image == OLD for name, image in docker.images.items() if name != 'sentinel-admin')
    assert not (args.state_dir / 'successful.json').exists()
    captured = capsys.readouterr()
    assert 'SECRET' not in str(error.value) + json.dumps(journal) + captured.out + captured.err


def test_unexpected_exception_is_not_persisted_or_printed(setup, monkeypatch):
    _, args, engine = setup
    original = engine.smoke
    failed = False

    def fail_once(tenants):
        nonlocal failed
        if not failed:
            failed = True
            raise ValueError('SECRET raw exception')
        original(tenants)

    monkeypatch.setattr(engine, 'smoke', fail_once)
    with pytest.raises(deploy.DeploymentError) as error:
        engine.deploy()
    journal = json.loads((args.state_dir / 'transaction.json').read_text())
    assert journal['failure'] == {'stage': 'public-smoke.canary',
                                  'message': 'Unexpected deployment failure'}
    assert journal['status'] == 'rolled_back'
    assert 'SECRET' not in str(error.value) + json.dumps(journal)


def test_diagnostic_write_failure_does_not_prevent_rollback(setup, monkeypatch):
    docker, args, engine = setup
    docker.fail_tenant = 'mfd'
    original = deploy.save
    failed = False

    def fail_diagnostic_write(path, value):
        nonlocal failed
        if 'failure' in value and not failed:
            failed = True
            raise OSError('SECRET filesystem error')
        original(path, value)

    monkeypatch.setattr(deploy, 'save', fail_diagnostic_write)
    with pytest.raises(deploy.DeploymentError, match='rolled_back'):
        engine.deploy()
    assert failed
    journal = json.loads((args.state_dir / 'transaction.json').read_text())
    assert journal['failure'] == {'stage': 'mfd.restart', 'message': 'Command failed (exit 1)'}
    assert journal['status'] == 'rolled_back'
    assert docker.images['sentinel-admin'] == OLD_ADMIN
    assert all(image == OLD for name, image in docker.images.items() if name != 'sentinel-admin')


@pytest.mark.parametrize('failure', ['exit', 'timeout', 'oserror'])
def test_command_diagnostics_exclude_arguments_output_and_exception_text(monkeypatch, failure):
    def fail(argv, **kwargs):
        if failure == 'timeout':
            raise subprocess.TimeoutExpired(argv, 600, output='SECRET stdout', stderr='SECRET stderr')
        if failure == 'oserror':
            raise OSError('SECRET exception')
        return subprocess.CompletedProcess(argv, 7, 'SECRET stdout', 'SECRET stderr')

    monkeypatch.setattr(deploy.subprocess, 'run', fail)
    with pytest.raises(deploy.DeploymentError) as error:
        deploy.run(['SECRET executable', 'SECRET argument'], input='SECRET input')
    assert str(error.value) == ('Command failed (exit 7)' if failure == 'exit'
                                else 'Command could not complete')


def test_main_takes_exclusive_flock_before_engine(tmp_path, monkeypatch):
    events = []
    monkeypatch.setattr(deploy.os, 'geteuid', lambda: 0)
    monkeypatch.setattr(deploy.fcntl, 'flock', lambda fd, mode: events.append(('lock', mode)))
    monkeypatch.setattr(deploy.signal, 'signal', lambda *args: None)
    monkeypatch.setattr(deploy.Engine, 'deploy', lambda self: events.append(('deploy', None)))
    # macOS test runners need not be root; only emulate ownership of this dir.
    original = Path.stat
    def root_stat(path, *args, **kwargs):
        result = original(path, *args, **kwargs)
        if path == tmp_path:
            values = list(result)
            values[4] = 0
            return type(result)(values)
        return result
    monkeypatch.setattr(Path, 'stat', root_stat)
    assert deploy.main(['--tenant-image', NEW, '--admin-image', NEW_ADMIN,
                        '--revision', REVISION, '--state-dir', str(tmp_path), '--check']) == 0
    assert events == [('lock', deploy.fcntl.LOCK_EX), ('deploy', None)]


def test_restart_strict_readiness_logic():
    source = (REPO / 'deploy/gcp/restart_customer.sh').read_text()
    snippet = source.split('"import urllib.request, urllib.error, sys\n', 1)[1].split('" \\\n', 1)[0]
    code = 'import urllib.request, urllib.error, sys\n' + snippet
    import urllib.error
    from unittest.mock import patch
    class Response:
        status = 200
    for health, status, expected in [(200, 401, 0), (401, 401, 1),
                                      (500, 401, 1), (200, 200, 1), (200, 503, 1)]:
        def urlopen(url, **kwargs):
            value = health if url.endswith('/health') else status
            if value != 200:
                raise urllib.error.HTTPError(url, value, '', {}, None)
            return Response()
        with patch('urllib.request.urlopen', urlopen), pytest.raises(SystemExit) as exit_info:
            exec(code, {})
        assert exit_info.value.code == expected
    assert 'if [ "$READY" != true ]; then' in source
    assert '"$SENTINEL_IMAGE"' in source


def test_runtime_decrypts_persisted_database_and_json_without_schema_changes(tmp_path, monkeypatch):
    import sqlite3
    import crypto
    monkeypatch.delenv('ARCKON_MASTER_KEY_FILE', raising=False)
    monkeypatch.setenv('ARCKON_MASTER_KEY', 'ab' * 32)
    ciphertext = crypto.encrypt_field('private customer value')
    db = tmp_path / 'agents.db'
    with sqlite3.connect(db) as conn:
        conn.execute('CREATE TABLE protected_paths(path TEXT)')
        conn.execute('CREATE TABLE protected_paths_audit(path TEXT)')
        conn.execute('INSERT INTO protected_paths VALUES(?)', (ciphertext,))
        conn.execute('INSERT INTO protected_paths_audit VALUES(?)', (ciphertext,))
    config = tmp_path / 'siem_config.json'
    config.write_text(json.dumps({'integration': {'hec_token': ciphertext}}))
    code = deploy.RUNTIME_CHECK.replace('/app/data', str(tmp_path))
    exec(code, {})
    with sqlite3.connect(db) as conn:
        assert conn.execute('SELECT path FROM protected_paths').fetchone()[0] == ciphertext
        assert conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall() == [
            ('protected_paths',), ('protected_paths_audit',)]
    monkeypatch.setenv('ARCKON_MASTER_KEY', 'cd' * 32)
    with pytest.raises(Exception):
        exec(code, {})


@pytest.fixture
def runtime_data(tmp_path, monkeypatch):
    import sqlite3
    monkeypatch.delenv('ARCKON_MASTER_KEY_FILE', raising=False)
    monkeypatch.setenv('ARCKON_MASTER_KEY', 'ab' * 32)
    db = tmp_path / 'agents.db'
    with sqlite3.connect(db) as conn:
        conn.execute('CREATE TABLE protected_paths(path TEXT, description TEXT)')
        conn.execute('CREATE TABLE protected_paths_audit(path TEXT, actor TEXT)')
        conn.execute('CREATE TABLE reports(body TEXT)')
        conn.execute('CREATE TABLE access_events(path TEXT, detail TEXT)')
        conn.execute("INSERT INTO protected_paths VALUES('/policy', 'enc:literal description')")
        conn.execute("INSERT INTO protected_paths_audit VALUES('/policy', 'enc:literal actor')")
        conn.execute("INSERT INTO reports VALUES('enc:literal report')")
        conn.execute("INSERT INTO reports VALUES('{malformed unrelated JSON')")
        conn.execute("INSERT INTO access_events VALUES('enc:literal event path', 'enc:literal detail')")
    (tmp_path / 'report.json').write_text('{malformed unrelated JSON')
    (tmp_path / 'events.json').write_text('{"path":"enc:literal event"}')
    (tmp_path / 'siem_config.json').write_text(json.dumps({
        'splunk': {'hec_token': '', 'description': 'enc:literal description',
                   'metadata': {'password': 'enc:not an authoritative secret field'}}}))
    return tmp_path, deploy.RUNTIME_CHECK.replace('/app/data', str(tmp_path))


def test_runtime_ignores_unrelated_enc_literals_and_malformed_json(runtime_data):
    _, code = runtime_data
    exec(code, {})


@pytest.mark.parametrize('table', ['protected_paths', 'protected_paths_audit'])
def test_runtime_rejects_corrupt_protected_policy(runtime_data, table):
    import sqlite3
    root, code = runtime_data
    with sqlite3.connect(root / 'agents.db') as conn:
        conn.execute('UPDATE ' + table + ' SET path=?', ('enc:corrupt policy',))
    with pytest.raises(Exception):
        exec(code, {})


@pytest.mark.parametrize('field', ['hec_token', 'shared_key', 'api_key', 'vsa_api_key',
                                  'bms_api_key', 'itglue_api_key', 'password'])
def test_runtime_rejects_corrupt_authoritative_siem_secrets(runtime_data, field):
    root, code = runtime_data
    (root / 'siem_config.json').write_text(json.dumps({'integration': {field: 'enc:corrupt secret'}}))
    with pytest.raises(Exception):
        exec(code, {})
