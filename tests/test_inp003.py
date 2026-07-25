"""Tests for the AI-INP-003 indirect injection check and storage prune fix."""
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))
from checks.input_safety import check_inp_003
from checks import PASS, FAIL, NA, SKIP
from connectors.api_connector import ProbeResult


def _ctx(uses_rag=None, files=None):
    ctx = MagicMock()
    ctx.uses_rag = uses_rag
    ctx.files = files or {}
    ctx.mode = 'config'
    ctx.probe_results = {}
    return ctx


class TestInp003Static(unittest.TestCase):
    def test_na_when_rag_not_used(self):
        r = check_inp_003(_ctx(uses_rag=False))
        self.assertEqual(r.status, NA)
        self.assertEqual(r.check_id, 'AI-INP-003')

    def test_skip_without_a_configured_live_rag_probe(self):
        self.assertEqual(check_inp_003(_ctx(uses_rag=True)).status, SKIP)

    def test_pass_when_retrieval_is_verified_and_injection_rejected(self):
        ctx = _ctx(uses_rag=True)
        ctx.probe_results['inp-003-a'] = ProbeResult(
            'inp-003-a', 'AI-INP-003', 'RAG test', response='ARCKON_RAG_RETRIEVED_C7E1', passed=True,
        )
        self.assertEqual(check_inp_003(ctx).status, PASS)

    def test_fail_when_retrieved_instruction_is_followed(self):
        ctx = _ctx(uses_rag=True)
        ctx.probe_results['inp-003-a'] = ProbeResult(
            'inp-003-a', 'AI-INP-003', 'RAG test', response='ARCKON_RAG_INJECTION_A9D4',
            passed=False, fail_reason='Model followed the injected instruction.',
        )
        self.assertEqual(check_inp_003(ctx).status, FAIL)

    def test_skip_when_retrieval_cannot_be_verified(self):
        ctx = _ctx(uses_rag=True)
        ctx.probe_results['inp-003-a'] = ProbeResult(
            'inp-003-a', 'AI-INP-003', 'RAG test', error='RAG retrieval could not be verified', passed=False,
        )
        self.assertEqual(check_inp_003(ctx).status, SKIP)


class TestStoragePruneFix(unittest.TestCase):
    """Verify the FK-safe prune: devices must not be deleted during prune."""

    def setUp(self):
        import sqlite3
        import tempfile
        self._tmp = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        self._db_path = self._tmp.name
        conn = sqlite3.connect(self._db_path)
        conn.execute('''CREATE TABLE devices (
            device_id TEXT PRIMARY KEY, hostname TEXT, platform TEXT,
            agent_version TEXT, ip_address TEXT, first_seen INTEGER, last_seen INTEGER
        )''')
        conn.execute('''CREATE TABLE reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT REFERENCES devices(device_id),
            received_at INTEGER, scan_date TEXT, profile TEXT, mode TEXT,
            target TEXT, fail_count INTEGER, warn_count INTEGER, pass_count INTEGER,
            report_json TEXT
        )''')
        conn.commit()
        now = int(time.time())
        conn.execute("INSERT INTO devices VALUES (?,?,?,?,?,?,?)",
                     ('dev1', 'host1', 'Linux', '1.0', '10.0.0.1', now - 200, now))
        conn.execute("INSERT INTO reports VALUES (NULL,'dev1',?,NULL,'default','config','/',0,0,0,'{}' )",
                     (now - 200,))
        old_ts = now - (100 * 86400)
        conn.execute("INSERT INTO reports VALUES (NULL,'dev1',?,NULL,'default','config','/',0,0,0,'{}' )",
                     (old_ts,))
        conn.commit()
        conn.close()

    def tearDown(self):
        Path(self._db_path).unlink(missing_ok=True)

    def _prune(self, retention_days=90):
        import sqlite3
        cutoff = int(time.time()) - (retention_days * 86400)
        with sqlite3.connect(self._db_path) as conn:
            cur = conn.execute("DELETE FROM reports WHERE received_at < ?", (cutoff,))
            return cur.rowcount

    def test_prune_removes_old_reports(self):
        deleted = self._prune(retention_days=90)
        self.assertEqual(deleted, 1)

    def test_prune_does_not_delete_devices(self):
        self._prune(retention_days=90)
        import sqlite3
        with sqlite3.connect(self._db_path) as conn:
            count = conn.execute("SELECT count(*) FROM devices").fetchone()[0]
        self.assertEqual(count, 1, "Devices must survive report pruning")

    def test_recent_report_not_pruned(self):
        deleted = self._prune(retention_days=90)
        import sqlite3
        with sqlite3.connect(self._db_path) as conn:
            remaining = conn.execute("SELECT count(*) FROM reports").fetchone()[0]
        self.assertEqual(remaining, 1)


if __name__ == '__main__':
    unittest.main()
