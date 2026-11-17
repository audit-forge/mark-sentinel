import importlib.util
from pathlib import Path


_SCRIPT = Path(__file__).parents[1] / 'scripts' / 'gworkspace_drive_forwarder.py'
_SPEC = importlib.util.spec_from_file_location('gworkspace_drive_forwarder', _SCRIPT)
forwarder = importlib.util.module_from_spec(_SPEC)
assert _SPEC.loader is not None
_SPEC.loader.exec_module(forwarder)


def test_state_file_is_persisted_at_configured_location(tmp_path):
    state_file = tmp_path / 'nested' / 'forwarder.state'

    assert forwarder._load_state(state_file) == ''
    forwarder._save_state('2026-10-13T19:00:00Z', state_file)

    assert forwarder._load_state(state_file) == '2026-10-13T19:00:00Z'


def test_splits_drive_activity_into_uniquely_identified_events():
    payloads = forwarder._event_payloads({
        'id': {'time': '2026-10-13T19:00:00Z', 'uniqQualifier': 'event-1'},
        'actor': {'email': 'user@example.com'},
        'events': [{'name': 'view'}, {'name': 'access_item_content'}],
    }, 'example.com')

    assert [payload['arckonEventId'] for payload in payloads] == [
        '2026-10-13T19:00:00Z:event-1:0',
        '2026-10-13T19:00:00Z:event-1:1',
    ]
    assert all(len(payload['events']) == 1 for payload in payloads)
    assert all(payload['actor'] == {'email': 'user@example.com'} for payload in payloads)


def test_each_domain_is_tagged_in_payload():
    """Multiple domains can forward to the same tenant; each event carries its source domain."""
    payloads_a = forwarder._event_payloads({
        'id': {'time': '2026-10-13T19:00:00Z', 'uniqQualifier': 'q'},
        'actor': {'email': 'user@a.com'},
        'events': [{'name': 'view'}],
    }, 'a.com')
    payloads_b = forwarder._event_payloads({
        'id': {'time': '2026-10-13T19:00:00Z', 'uniqQualifier': 'q'},
        'actor': {'email': 'user@b.com'},
        'events': [{'name': 'view'}],
    }, 'b.com')

    assert payloads_a[0]['arckonDomain'] == 'a.com'
    assert payloads_b[0]['arckonDomain'] == 'b.com'


def test_add_workspace_domain_script_exists_and_is_executable():
    """The multi-domain helper script must exist and be executable."""
    script = Path(__file__).parents[1] / 'deploy' / 'gcp' / 'add_workspace_domain.sh'
    assert script.is_file()
    assert script.stat().st_mode & 0o100, 'script should be executable'


def test_service_template_uses_arckon_url_env_var():
    """The systemd template must read ARCKON_URL from the env file, not construct it."""
    template = (Path(__file__).parents[1] / 'deploy' / 'gcp'
                 / 'arckon-gworkspace-drive-forwarder@.service').read_text()
    assert '${ARCKON_URL}' in template
    assert 'sentinel-%i:7331' not in template, 'must not hardcode URL from instance name'
