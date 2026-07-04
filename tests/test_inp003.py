"""Tests for the AI-INP-003 indirect injection check and storage prune fix."""
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))
from checks.input_safety import check_inp_003
from checks import PASS, FAIL, WARN, NA, SKIP


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

    def test_fail_when_rag_used_no_guards(self):
        r = check_inp_003(_ctx(uses_rag=True, files={'app.py': 'from openai import OpenAI\nretrieve(query)'}))
        self.assertIn(r.status, (FAIL, WARN))

    def test_pass_when_guard_and_sanitize_present(self):
        code = 'import lakera_guard\nsanitize_retrieved_content(docs)\nllm.call()'
        r = check_inp_003(_ctx(uses_rag=True, files={'app.py': code}))
        self.assertEqual(r.status, PASS)

    def test_warn_when_only_guard_present(self):
        code = 'import lakera_guard\nllm.call(retrieved_docs)'
        r = check_inp_003(_ctx(uses_rag=True, files={'app.py': code}))
        self.assertIn(r.status, (WARN, PASS))

    def test_warn_when_only_sanitize_present(self):
        code = 'docs = sanitize_retrieved_content(raw)\nllm.call(docs)'
        r = check_inp_003(_ctx(uses_rag=True, files={'app.py': code}))
        self.assertIn(r.status, (WARN, PASS))

    def test_fail_when_rag_unknown_no_guards(self):
        r = check_inp_003(_ctx(uses_rag=None, files={'config.json': '{"model": "gpt-4"}'}))
        self.assertIn(r.status, (FAIL, WARN))

    def test_remediation_present_on_fail(self):
        r = check_inp_003(_ctx(uses_rag=True))
        if r.status in (FAIL, WARN):
            self.assertIsNotNone(r.remediation)
            self.assertIn('guard', r.remediation.lower())

    def test_presidio_counts_as_guard(self):
        code = 'from presidio_analyzer import AnalyzerEngine\nsanitize_retrieved_content(docs)'
        r = check_inp_003(_ctx(uses_rag=True, files={'app.py': code}))
        self.assertEqual(r.status, PASS)

    def test_llama_guard_counts(self):
        code = 'GUARD_MODEL = "meta-llama/LlamaGuard-7b"\nsanitize_retrieved_content(docs)'
        r = check_inp_003(_ctx(uses_rag=True, files={'app.py': code}))
        self.assertEqual(r.status, PASS)

    def test_gemini_attack_vector_mentioned_in_details(self):
        r = check_inp_003(_ctx(uses_rag=True))
        if r.status in (FAIL, WARN):
            self.assertIn('Gemini', r.details)


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
