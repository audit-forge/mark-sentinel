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
