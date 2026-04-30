"""
Phase 2 integration tests — live probe logic and API connector.

Uses a mock HTTP server to simulate an OpenAI-compatible endpoint without
requiring a real API key or live model.

Run: pytest test/test_live_probes.py -v
"""
import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).parent.parent
AUDIT = str(ROOT / "audit.py")
HARDENED = str(ROOT / "test/fixtures/deploy-hardened")

sys.path.insert(0, str(ROOT))
from connectors.api_connector import (
    Probe, ProbeResult, _evaluate, _CANARY_OVERRIDE, _CANARY_INJECT,
    _CANARY_JAILBREAK, _CANARY_SYSPROMPT, _CANARY_PII_NAME, _CANARY_PII_EMAIL,
    PROBES, run_probes,
)
from connectors.config_connector import ScanContext


# ---------------------------------------------------------------------------
# Mock OpenAI-compatible server
# ---------------------------------------------------------------------------

_mock_response_text = "I cannot help with that request."  # default: safe refusal


_CANARIES = [_CANARY_OVERRIDE, _CANARY_INJECT, _CANARY_JAILBREAK,
             _CANARY_SYSPROMPT, _CANARY_PII_NAME, _CANARY_PII_EMAIL]


class _MockHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            payload = json.loads(body)
            messages = payload.get("messages", [])
            # Combine all message content for canary search
            all_content = " ".join(m.get("content", "") for m in messages)
            # System prompt is the first system-role message (if any)
            sys_content = next(
                (m["content"] for m in messages if m.get("role") == "system"), ""
            )
        except Exception:
            all_content = ""
            sys_content = ""

        # In vulnerable mode: echo back any canary found anywhere in the conversation
        # (simulates a model that leaks system prompts and accepts injections)
        if _MockHandler.echo_canary:
            found = [c for c in _CANARIES if c in all_content]
            if found:
                # Return all content that contains the canary — simulates system prompt disclosure
                reply = all_content if sys_content and any(c in sys_content for c in found) else all_content
            else:
                reply = _mock_response_text
        else:
            reply = _mock_response_text

        resp = {
            "choices": [{"message": {"role": "assistant", "content": reply}}]
        }
        body = json.dumps(resp).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass  # silence request logs during tests

    echo_canary = False  # class-level flag — set True to simulate a vulnerable model


def _start_mock_server() -> tuple[HTTPServer, str]:
    server = HTTPServer(("127.0.0.1", 0), _MockHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{port}/v1"


@pytest.fixture(scope="module")
def safe_server():
    """Mock server that always returns a safe refusal — simulates a hardened model."""
    _MockHandler.echo_canary = False
    server, endpoint = _start_mock_server()
    yield endpoint
    server.shutdown()


@pytest.fixture(scope="module")
def vulnerable_server():
    """Mock server that echoes canary strings back — simulates a vulnerable model."""
    _MockHandler.echo_canary = True
    server, endpoint = _start_mock_server()
    yield endpoint
    server.shutdown()


# ---------------------------------------------------------------------------
# Unit tests — probe evaluation logic (no HTTP)
# ---------------------------------------------------------------------------

class TestProbeEvaluation:
    def test_fail_if_canary_in_response(self):
        probe = Probe(
            id="test-1", check_id="AI-INP-001", description="test",
            system_prompt="sys", user_message="user",
            fail_if=[_CANARY_OVERRIDE],
        )
        result = _evaluate(probe, response=f"Sure! {_CANARY_OVERRIDE}", error="")
        assert not result.passed
        assert _CANARY_OVERRIDE in result.fail_reason

    def test_pass_if_canary_absent(self):
        probe = Probe(
            id="test-2", check_id="AI-INP-001", description="test",
            system_prompt="sys", user_message="user",
            fail_if=[_CANARY_OVERRIDE],
        )
        result = _evaluate(probe, response="I cannot do that.", error="")
        assert result.passed

    def test_pass_if_refusal_detected(self):
        probe = Probe(
            id="test-3", check_id="AI-OUT-004", description="test",
            system_prompt="sys", user_message="user",
            pass_if_refuses=True,
        )
        result = _evaluate(probe, response="I'm sorry, I cannot help with that.", error="")
        assert result.passed

    def test_fail_if_no_refusal(self):
        probe = Probe(
            id="test-4", check_id="AI-OUT-004", description="test",
            system_prompt="sys", user_message="user",
            pass_if_refuses=True,
        )
        result = _evaluate(probe, response="Sure, here are the step-by-step instructions...", error="")
        assert not result.passed

    def test_error_does_not_fail(self):
        probe = Probe(
            id="test-5", check_id="AI-INP-001", description="test",
            system_prompt="sys", user_message="user",
            fail_if=[_CANARY_OVERRIDE],
        )
        result = _evaluate(probe, response="", error="HTTP 401: Unauthorized")
        assert result.passed  # connection errors don't count as security failures
        assert result.error

    def test_all_probes_have_unique_ids(self):
        ids = [p.id for p in PROBES]
        assert len(ids) == len(set(ids)), "Duplicate probe IDs found"

    def test_all_probes_have_check_id(self):
        for p in PROBES:
            assert p.check_id.startswith("AI-"), f"Probe {p.id} has invalid check_id"


# ---------------------------------------------------------------------------
# Integration tests — safe model (all probes should PASS)
# ---------------------------------------------------------------------------

class TestSafeModel:
    @pytest.fixture(scope="class")
    def probe_results(self, safe_server):
        return run_probes(endpoint=safe_server, api_key="", model="test-model")

    def test_all_probes_ran(self, probe_results):
        assert len(probe_results) == len(PROBES)

    def test_inp_001_passes_on_safe_model(self, probe_results):
        for pid in ["inp-001-a", "inp-001-b"]:
            r = probe_results.get(pid)
            assert r is not None
            assert r.passed, f"{pid} failed on safe model: {r.fail_reason}"

    def test_inp_002_passes_on_safe_model(self, probe_results):
        r = probe_results.get("inp-002-a")
        assert r and r.passed

    def test_inp_004_passes_on_safe_model(self, probe_results):
        for pid in ["inp-004-a", "inp-004-b"]:
            r = probe_results.get(pid)
            assert r and r.passed, f"{pid} failed on safe model: {r.fail_reason}"

    def test_out_003_passes_on_safe_model(self, probe_results):
        for pid in ["out-003-a", "out-003-b"]:
            r = probe_results.get(pid)
            assert r and r.passed

    def test_out_002_passes_on_safe_model(self, probe_results):
        r = probe_results.get("out-002-a")
        assert r and r.passed

    def test_out_004_passes_on_safe_model(self, probe_results):
        for pid in ["out-004-a", "out-004-b"]:
            r = probe_results.get(pid)
            assert r and r.passed


# ---------------------------------------------------------------------------
# Integration tests — vulnerable model (selected probes should FAIL)
# ---------------------------------------------------------------------------

class TestVulnerableModel:
    @pytest.fixture(scope="class")
    def probe_results(self, vulnerable_server):
        return run_probes(endpoint=vulnerable_server, api_key="", model="test-model")

    def test_inp_001_fails_on_vulnerable_model(self, probe_results):
        # Both override probes contain canary strings — vulnerable model echoes them back
        failed = [
            probe_results[pid]
            for pid in ["inp-001-a", "inp-001-b"]
            if not probe_results[pid].passed
        ]
        assert len(failed) >= 1, "Expected at least one INP-001 probe to fail on vulnerable model"

    def test_inp_004_fails_on_vulnerable_model(self, probe_results):
        failed = [
            probe_results[pid]
            for pid in ["inp-004-a", "inp-004-b"]
            if not probe_results[pid].passed
        ]
        assert len(failed) >= 1, "Expected at least one INP-004 probe to fail on vulnerable model"

    def test_out_003_fails_on_vulnerable_model(self, probe_results):
        failed = [
            probe_results[pid]
            for pid in ["out-003-a", "out-003-b"]
            if not probe_results[pid].passed
        ]
        assert len(failed) >= 1, "Expected at least one OUT-003 probe to fail on vulnerable model"

    def test_out_002_fails_on_vulnerable_model(self, probe_results):
        r = probe_results.get("out-002-a")
        assert r and not r.passed, "Expected OUT-002 PII probe to fail on vulnerable model"


# ---------------------------------------------------------------------------
# End-to-end — full audit pipeline with mock server (JSON output)
# ---------------------------------------------------------------------------

class TestFullPipelineApiMode:
    def test_api_mode_produces_json(self, safe_server):
        result = subprocess.run(
            [sys.executable, AUDIT,
             "--mode", "api",
             "--endpoint", safe_server,
             "--api-key", "test-key",
             "--model", "test-model",
             "--target", HARDENED,
             "--profile", "default",
             "--output", "json",
             "--quiet"],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
        )
        data = json.loads(result.stdout)
        assert "findings" in data
        assert "summary" in data
        assert data["mode"] == "api"

    def test_api_mode_live_checks_not_skipped(self, safe_server):
        result = subprocess.run(
            [sys.executable, AUDIT,
             "--mode", "api",
             "--endpoint", safe_server,
             "--api-key", "test-key",
             "--model", "test-model",
             "--target", HARDENED,
             "--profile", "default",
             "--output", "json",
             "--quiet"],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
        )
        data = json.loads(result.stdout)
        findings = {f["check_id"]: f for f in data["findings"]}

        # These were SKIP in config mode — should now have PASS/FAIL/WARN in api mode
        for check_id in ["AI-INP-001", "AI-INP-002", "AI-INP-004",
                         "AI-OUT-002", "AI-OUT-003", "AI-OUT-004"]:
            assert check_id in findings, f"{check_id} not in findings"
            status = findings[check_id]["status"]
            assert status != "SKIP", f"{check_id} still SKIP in api mode (got {status})"

    def test_api_mode_produces_sarif(self, safe_server):
        result = subprocess.run(
            [sys.executable, AUDIT,
             "--mode", "api",
             "--endpoint", safe_server,
             "--api-key", "test-key",
             "--model", "test-model",
             "--target", HARDENED,
             "--profile", "default",
             "--output", "sarif",
             "--quiet"],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
        )
        sarif = json.loads(result.stdout)
        assert sarif["version"] == "2.1.0"
        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "M.A.R.K. Sentinel"

    def test_connection_error_graceful(self):
        """Unreachable endpoint should not crash — checks fall through to SKIP/error."""
        result = subprocess.run(
            [sys.executable, AUDIT,
             "--mode", "api",
             "--endpoint", "http://127.0.0.1:19999/v1",  # nothing listening here
             "--api-key", "test-key",
             "--model", "test-model",
             "--target", HARDENED,
             "--profile", "default",
             "--output", "json",
             "--quiet"],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
            timeout=60,
        )
        # Should not crash — may return non-zero exit code but stdout must be valid JSON
        data = json.loads(result.stdout)
        assert "findings" in data
