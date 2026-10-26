import shutil
import subprocess
import sys
import threading
from pathlib import Path

import pytest
import yaml

import agent
from monitors.base import EventQueue
from scripts import package_release


ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize('dockerfile', ['Dockerfile.build', 'Dockerfile.build-audit'])
def test_docker_audit_sources_include_secure_connector_dependencies(tmp_path, dockerfile):
    text = (ROOT / 'scripts' / dockerfile).read_text()
    # Stage precisely the sources available before audit compilation, not the checkout.
    before_compile = text.split('RUN python -m nuitka', 1)[0]
    for line in before_compile.splitlines():
        if not line.startswith('COPY '):
            continue
        *sources, destination = line.split()[1:]
        for source in sources:
            path = ROOT / source
            if path.is_dir():
                shutil.copytree(path, tmp_path / destination)
            else:
                shutil.copy2(path, tmp_path / path.name)

    for module in ('arckon_version', 'outbound_http', 'crypto'):
        assert (tmp_path / f'{module}.py').is_file()
        assert f'--include-module={module}' in text
    for package in ('checks', 'connectors', 'output'):
        assert f'--include-package={package}' in text

    # Exercise the lazy crypto import via encrypted SIEM config without a key file
    # or network access. Isolated mode prevents the checkout masking missing files.
    subprocess.run(
        [sys.executable, '-I', '-c', '''
import os
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import outbound_http
from connectors import api_connector, hash_connector, psa_connector
from connectors.siem_connector import load_siem_config, save_siem_config
os.environ.pop('ARCKON_MASTER_KEY_FILE', None)
os.environ['ARCKON_MASTER_KEY'] = 'ab' * 32
path = Path('siem.json')
config = {'splunk': {'hec_token': 'release-smoke-secret'}}
save_siem_config(config, path)
assert 'release-smoke-secret' not in path.read_text()
assert load_siem_config(path) == config
''', str(tmp_path)],
        cwd=tmp_path, check=True, capture_output=True, text=True, timeout=30,
    )


def test_linux_agent_build_includes_access_monitor_runtime():
    text = (ROOT / 'scripts' / 'Dockerfile.build').read_text()
    before_agent = text.split('# Compile agent binary', 1)[0]
    assert 'COPY monitors/ ./monitors/' in before_agent
    command = text.split('# Compile agent binary', 1)[1]
    assert '--include-package=monitors' in command
    assert '--include-package=psutil' in command


@pytest.mark.parametrize('platform', ['linux', 'macos', 'windows'])
@pytest.mark.parametrize('entry', ['agent', 'audit'])
def test_native_build_includes_secure_runtime(tmp_path, monkeypatch, platform, entry):
    (tmp_path / f'{entry}.py').write_text('pass\n')
    monkeypatch.setattr(package_release, '_ensure_nuitka', lambda: None)
    commands = []
    monkeypatch.setattr(package_release.subprocess, 'run', lambda cmd, **kw: commands.append(cmd))

    package_release._build_nuitka_binary(tmp_path, f'{entry}.py', entry, platform)

    command, = commands
    for flag in (
        '--follow-imports', '--include-module=outbound_http', '--include-module=crypto',
        '--include-package=connectors', '--include-package=monitors', '--include-package=psutil',
    ):
        assert flag in command
    assert any(flag.startswith('--include-data-file=') and 'certifi/cacert.pem' in flag
               for flag in command)


def test_access_reporter_posts_without_waiting_for_scan(monkeypatch):
    queue = EventQueue(max_size=10)
    event = {'path': '/protected/release-smoke', 'action': 'read'}
    queue.push(event)
    posted = threading.Event()
    calls = []
    config = {'server': 'https://example.invalid', 'token': 'test'}

    def post(events, cfg):
        calls.append((events, cfg))
        posted.set()
        return True

    monkeypatch.setattr(agent, 'post_access_events', post)
    reporter = agent._start_access_event_reporter(queue, config)
    try:
        assert posted.wait(2), 'reporter waited for the main scan cycle'
        assert calls == [([event], config)]
        assert len(queue) == 0
    finally:
        agent._stop_access_event_reporter(reporter)
        reporter.join(timeout=2)
    assert not reporter.is_alive()


@pytest.mark.parametrize('platform', ['linux', 'macos', 'windows'])
def test_release_workflow_checks_signed_and_extracted_runtime(platform):
    workflow = yaml.safe_load((ROOT / '.github' / 'workflows' / 'release.yml').read_text())
    steps = workflow['jobs'][f'release-{platform}']['steps']
    commands = '\n'.join(step.get('run', '') for step in steps)
    assert 'scripts/create_release.py' in commands
    assert '_validate_update_manifest' in commands
    assert "manifest['size']" in commands
    assert "manifest['sha256']" in commands
    assert f"manifest['platform'] == '{platform}'" in commands
    assert '--help' in commands  # Neither current entry point implements --version.
    assert 'scripts/smoke_test_agent_session_runtime.py' in commands
    if platform == 'linux':
        assert './audit --help && ./agent --help' in commands
    else:
        assert "cwd=root, check=True, timeout=30" in commands
        extension = '.exe' if platform == 'windows' else ''
        assert f"for name in ('audit{extension}', 'agent{extension}')" in commands
        python = commands.split("python - <<'PY'\n", 1)[1].split('\nPY', 1)[0]
        compile(python, '<release-workflow>', 'exec')


def test_release_validation_runs_full_suite_on_exact_tag_sha():
    workflow = yaml.safe_load((ROOT / '.github' / 'workflows' / 'release.yml').read_text())
    validation = workflow['jobs']['validate-release']
    assert validation['if'] == "github.ref_type == 'tag'"
    assert validation['permissions'] == {'contents': 'read'}
    assert validation['env']['SECRET_KEY'] == 'release-validation-synthetic-key-not-for-production'
    assert not validation.get('continue-on-error', False)
    steps = validation['steps']
    assert steps[0]['uses'] == 'actions/checkout@v4'
    assert steps[0]['with']['ref'] == '${{ github.sha }}'
    assert any(step.get('with', {}).get('python-version') == '3.12' for step in steps)
    commands = '\n'.join(step.get('run', '') for step in steps)
    assert 'test "$(git rev-parse HEAD)" = "$GITHUB_SHA"' in commands
    assert '[[ "$TAG" =~ ^v' in commands
    assert 'test "${TAG#v}"' in commands
    assert 'from arckon_version import VERSION; print(VERSION)' in commands
    assert any(step.get('env', {}).get('TAG') == '${{ github.ref_name }}' for step in steps)
    assert 'python -m pip install -r requirements.txt -r admin/requirements.txt pytest httpx' in commands
    assert steps[-1]['run'] == 'python -m pytest -q'
    assert all(not step.get('continue-on-error', False) for step in steps)


@pytest.mark.parametrize('platform', ['linux', 'macos', 'windows'])
def test_release_builds_and_publication_cannot_bypass_validation(platform):
    workflow = yaml.safe_load((ROOT / '.github' / 'workflows' / 'release.yml').read_text())
    job = workflow['jobs'][f'release-{platform}']
    assert job['needs'] == 'validate-release'
    assert job['if'] == "github.ref_type == 'tag'"
    assert not job.get('continue-on-error', False)
    assert job['steps'][0]['uses'] == 'actions/checkout@v4'
    assert job['steps'][0]['with']['ref'] == '${{ github.sha }}'
    publish = workflow['jobs']['publish-github-release']
    assert set(publish['needs']) == {'release-linux', 'release-macos', 'release-windows'}
    assert 'if' not in publish  # Default success() propagates failures through the DAG.
