#!/usr/bin/env python3
"""Tests for Protected Files monitoring: crypto, storage, base collector.

FedRAMP-aligned test coverage:
  SC-13: AES-256-GCM encryption roundtrip + tamper detection
  AU-2:  SHA-256 hash chain integrity + tamper detection
  AC-3:  Protected-path policy add/remove/audit
  SI-4:  AI process matching + event filtering
"""
import base64
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

os.environ['ARCKON_MASTER_KEY'] = base64.b64encode(os.urandom(32)).decode()


class TestCrypto(unittest.TestCase):
    def test_encrypt_decrypt_roundtrip(self):
        import crypto
        for pt in ['/etc/passwd', '/Users/keith/secrets.pem', '', 'a' * 500]:
            if not pt:
                continue
            ct = crypto.encrypt_field(pt)
            self.assertTrue(ct.startswith('enc:'))
            self.assertNotEqual(ct, pt)
            self.assertEqual(crypto.decrypt_field(ct), pt)

    def test_empty_string_passthrough(self):
        import crypto
        self.assertEqual(crypto.encrypt_field(''), '')
        self.assertEqual(crypto.decrypt_field(''), '')

    def test_plaintext_passthrough(self):
        import crypto
        self.assertEqual(crypto.decrypt_field('not-encrypted'), 'not-encrypted')

    def test_tamper_detection(self):
        import crypto
        ct = crypto.encrypt_field('/secret/path')
        # Flip a byte in the ciphertext
        import base64 as b64
        blob = b64.b64decode(ct[4:])
        tampered = b'enc:' + b64.b64encode(bytes([blob[0] ^ 1]) + blob[1:])
        with self.assertRaises(Exception):
            crypto.decrypt_field(tampered)

    def test_hash_chain(self):
        import crypto
        data1 = {'device': 'd1', 'path': '/x', 'process': 'claude', 'action': 'read'}
        h1 = crypto.compute_event_hash('', data1)
        data2 = {'device': 'd1', 'path': '/y', 'process': 'cursor', 'action': 'write'}
        h2 = crypto.compute_event_hash(h1, data2)
        chain = [dict(data1, event_hash=h1, prev_hash=''),
                 dict(data2, event_hash=h2, prev_hash=h1)]
        self.assertTrue(crypto.verify_hash_chain(chain))

    def test_hash_chain_tamper_detected(self):
        import crypto
        data1 = {'device': 'd1', 'path': '/x', 'process': 'claude', 'action': 'read'}
        h1 = crypto.compute_event_hash('', data1)
        data2 = {'device': 'd1', 'path': '/y', 'process': 'cursor', 'action': 'write'}
        h2 = crypto.compute_event_hash(h1, data2)
        chain = [dict(data1, event_hash=h1, prev_hash=''),
                 dict(data2, event_hash=h2, prev_hash=h1)]
        chain[1]['path'] = '/tampered'
        self.assertFalse(crypto.verify_hash_chain(chain))

    def test_path_hash(self):
        import crypto
        h = crypto.hash_path('/etc/passwd')
        self.assertEqual(len(h), 64)  # SHA-256 hex
        self.assertEqual(crypto.hash_path('/etc/passwd'), h)  # deterministic


class TestStorage(unittest.TestCase):
    def setUp(self):
        self.db = Path(tempfile.mktemp(suffix='.db'))
        import storage
        self.store = storage.AgentStore(self.db)

    def tearDown(self):
        self.store._conn().close()
        try:
            self.db.unlink()
        except Exception:
            pass

    def test_protected_path_add_get_remove(self):
        pid = self.store.add_protected_path('dev1', '/tmp/secrets', created_by='test')
        self.assertIsInstance(pid, int)
        paths = self.store.get_protected_paths()
        self.assertEqual(len(paths), 1)
        # Path is canonicalized (realpath)
        self.assertEqual(paths[0]['path'], os.path.realpath('/tmp/secrets'))
        self.assertTrue(paths[0]['recursive'])
        self.assertEqual(paths[0]['created_by'], 'test')
        # Remove
        self.assertTrue(self.store.remove_protected_path(pid, changed_by='test'))
        self.assertEqual(len(self.store.get_protected_paths()), 0)

    def test_protected_path_wildcard(self):
        self.store.add_protected_path('*', '/etc/global', created_by='test')
        # Should return for any device
        paths = self.store.get_protected_paths('dev1')
        self.assertEqual(len(paths), 1)

    def test_protected_paths_audit_log(self):
        pid = self.store.add_protected_path('dev1', '/tmp/secret1', created_by='test')
        self.store.remove_protected_path(pid, changed_by='test')
        audit = self.store.get_protected_paths_audit_log()
        self.assertEqual(len(audit), 2)  # add + remove
        actions = {a['action'] for a in audit}
        self.assertIn('upsert', actions)
        self.assertIn('remove', actions)

    def test_access_events_ingest_and_chain(self):
        events = [
            {'ts': 1700000000, 'device_id': 'd1', 'process': 'claude', 'pid': 1234,
             'path': '/etc/passwd', 'action': 'read', 'hostname': 'h1', 'platform': 'macos'},
            {'ts': 1700000001, 'device_id': 'd1', 'process': 'cursor', 'pid': 1235,
             'path': '/etc/shadow', 'action': 'write', 'hostname': 'h1', 'platform': 'macos'},
        ]
        n = self.store.ingest_access_events(events)
        self.assertEqual(n, 2)
        self.assertTrue(self.store.verify_access_event_chain())

    def test_access_events_review(self):
        events = [
            {'ts': 1700000000, 'device_id': 'd1', 'process': 'claude', 'pid': 1234,
             'path': '/etc/passwd', 'action': 'read'},
        ]
        self.store.ingest_access_events(events)
        self.assertEqual(self.store.count_unreviewed_access_events(), 1)
        evts = self.store.get_access_events()
        self.store.mark_access_event_reviewed(evts[0]['id'])
        self.assertEqual(self.store.count_unreviewed_access_events(), 0)

    def test_access_events_invalid_rejected(self):
        events = [{'ts': 1700000000}]  # missing required fields
        n = self.store.ingest_access_events(events)
        self.assertEqual(n, 0)


class TestBaseCollector(unittest.TestCase):
    def test_ai_process_matching(self):
        from monitors.base import is_ai_process
        for name in ['claude', 'Claude', 'claude.exe', 'Claude Helper',
                      'cursor', 'Cursor', 'ollama', 'GitHub Copilot',
                      'aider', 'ChatGPT', 'ChatGPT.exe']:
            self.assertTrue(is_ai_process(name), f'{name} should match')
        for name in ['chrome', 'Safari', 'sshd', 'Finder', 'bash', 'python3']:
            self.assertFalse(is_ai_process(name), f'{name} should NOT match')

    def test_path_matching_recursive(self):
        from monitors.base import path_matches_protected
        pp = [{'path': '/etc/secrets', 'recursive': True, 'actions': 'read,write'}]
        self.assertIsNotNone(path_matches_protected('/etc/secrets', pp))
        self.assertIsNotNone(path_matches_protected('/etc/secrets/key.pem', pp))
        self.assertIsNone(path_matches_protected('/etc/passwd', pp))

    def test_path_matching_non_recursive(self):
        from monitors.base import path_matches_protected
        pp = [{'path': '/etc/secrets', 'recursive': False, 'actions': 'read,write'}]
        self.assertIsNotNone(path_matches_protected('/etc/secrets', pp))
        self.assertIsNone(path_matches_protected('/etc/secrets/sub/key.pem', pp))

    def test_event_format_no_file_contents(self):
        from monitors.base import format_event
        evt = format_event(1700000000, 'd1', 'h1', 'macos', 'claude', 1234,
                           '/etc/secrets', 'read', 'esf')
        self.assertEqual(evt['process'], 'claude')
        self.assertEqual(evt['action'], 'read')
        self.assertNotIn('contents', evt)
        self.assertNotIn('file_data', evt)

    def test_event_queue(self):
        from monitors.base import EventQueue
        q = EventQueue(max_size=5)
        for i in range(3):
            q.push({'i': i})
        self.assertEqual(len(q), 3)
        drained = q.drain()
        self.assertEqual(len(drained), 3)
        self.assertEqual(len(q), 0)

    def test_event_queue_drop_oldest(self):
        from monitors.base import EventQueue
        q = EventQueue(max_size=3)
        for i in range(5):
            q.push({'i': i})
        drained = q.drain()
        self.assertEqual(len(drained), 3)  # only 3 kept
        self.assertEqual(drained[0]['i'], 2)  # oldest two dropped


class TestAlerts(unittest.TestCase):
    def test_access_alert_trigger_default(self):
        from alerts import _DEFAULT_TRIGGERS
        self.assertIn('ai_accessed_protected_file', _DEFAULT_TRIGGERS)
        self.assertTrue(_DEFAULT_TRIGGERS['ai_accessed_protected_file'])

    def test_fire_access_alert_importable(self):
        from alerts import fire_access_alert
        self.assertTrue(callable(fire_access_alert))


if __name__ == '__main__':
    unittest.main()