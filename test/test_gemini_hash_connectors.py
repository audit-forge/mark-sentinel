"""
Tests for Gemini and hash connectors.

Uses local mock HTTP servers — no real API keys or running hash instance needed.

Run: pytest test/test_gemini_hash_connectors.py -v
"""
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from connectors.api_connector import (  # noqa: E402
    _CANARY_OVERRIDE, _CANARY_INJECT, _CANARY_JAILBREAK,
    _CANARY_SYSPROMPT, _CANARY_PII_NAME, _CANARY_PII_EMAIL,
)
from connectors.hash_connector import (  # noqa: E402
    _chat_request as hash_request, run_probes as hash_run_probes,
    _SYSTEM_PROMPT_PROBES,
)

HARDENED = str(ROOT / "test/fixtures/deploy-hardened")
_ALL_CANARIES = [
    _CANARY_OVERRIDE, _CANARY_INJECT, _CANARY_JAILBREAK,
    _CANARY_SYSPROMPT, _CANARY_PII_NAME, _CANARY_PII_EMAIL,
]


# ---------------------------------------------------------------------------
# Mock Gemini server
# ---------------------------------------------------------------------------

class _GeminiHandler(BaseHTTPRequestHandler):
    echo_canary: bool = False

    def log_message(self, *args):
        pass  # silence request logs

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            payload = json.loads(body)
            parts = payload.get("contents", [{}])
            user_text = parts[0].get("parts", [{}])[0].get("text", "") if parts else ""
            sys_instr = payload.get("systemInstruction", {})
            sys_text = (sys_instr.get("parts") or [{}])[0].get("text", "") if sys_instr else ""
            all_text = user_text + " " + sys_text
        except Exception:
            all_text = ""

        if self.echo_canary:
            found = [c for c in _ALL_CANARIES if c in all_text]
            reply = all_text if found else "I cannot help with that request."
        else:
            reply = "I cannot help with that request."

        resp = {"candidates": [{"content": {"parts": [{"text": reply}], "role": "model"}}]}
        data = json.dumps(resp).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def _start_mock_gemini(echo: bool = False) -> tuple[HTTPServer, str]:
    _GeminiHandler.echo_canary = echo
    server = HTTPServer(("127.0.0.1", 0), _GeminiHandler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever)
    t.daemon = True
    t.start()
    return server, f"http://127.0.0.1:{port}"


# ---------------------------------------------------------------------------
# Mock hash server
# ---------------------------------------------------------------------------

class _HashHandler(BaseHTTPRequestHandler):
    echo_canary: bool = False

    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            payload = json.loads(body)
            message = payload.get("message", "")
        except Exception:
            message = ""

        if self.echo_canary:
            found = [c for c in _ALL_CANARIES if c in message]
            reply = message if found else "I cannot help with that request."
        else:
            reply = "I cannot help with that request."

        resp = {"response": reply}
        data = json.dumps(resp).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def _start_mock_hash(echo: bool = False) -> tuple[HTTPServer, str]:
    _HashHandler.echo_canary = echo
    server = HTTPServer(("127.0.0.1", 0), _HashHandler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever)
    t.daemon = True
    t.start()
    return server, f"http://127.0.0.1:{port}"


# ===========================================================================
# Gemini connector tests
# ===========================================================================

class TestGeminiChatRequest:
    def test_safe_response_returned(self):
        server, base = _start_mock_gemini(echo=False)
        try:
            # Patch the base URL so it points at our mock
            import connectors.gemini_connector as gc
            orig = gc._GEMINI_API_BASE
            gc._GEMINI_API_BASE = base
            text, err = gc._chat_request("fake-key", "gemini-1.5-flash", "You are a helper.", "Hello")
            gc._GEMINI_API_BASE = orig
        finally:
            server.shutdown()
        assert err == ""
        assert "cannot help" in text.lower()

    def test_connection_error_returns_error_string(self):
        import connectors.gemini_connector as gc
        orig = gc._GEMINI_API_BASE
        gc._GEMINI_API_BASE = "http://127.0.0.1:19999"  # nothing listening
        text, err = gc._chat_request("fake-key", "gemini-1.5-flash", "", "hello")
        gc._GEMINI_API_BASE = orig
        assert text == ""
        assert err != ""


class TestGeminiRunProbes:
    def test_safe_server_all_probes_pass(self):
        server, base = _start_mock_gemini(echo=False)
        import connectors.gemini_connector as gc
        orig = gc._GEMINI_API_BASE
        gc._GEMINI_API_BASE = base
        try:
            results = gc.run_probes("fake-key", "gemini-1.5-flash")
        finally:
            gc._GEMINI_API_BASE = orig
            server.shutdown()
        assert len(results) == 11
        assert all(r.passed for r in results.values())

    def test_vulnerable_server_canary_probes_fail(self):
        server, base = _start_mock_gemini(echo=True)
        import connectors.gemini_connector as gc
        orig = gc._GEMINI_API_BASE
        gc._GEMINI_API_BASE = base
        try:
            results = gc.run_probes("fake-key", "gemini-1.5-flash")
        finally:
            gc._GEMINI_API_BASE = orig
            server.shutdown()
        canary_probes = [pid for pid, r in results.items() if not r.passed]
        assert len(canary_probes) > 0

    def test_all_11_probes_executed(self):
        server, base = _start_mock_gemini(echo=False)
        import connectors.gemini_connector as gc
        orig = gc._GEMINI_API_BASE
        gc._GEMINI_API_BASE = base
        try:
            results = gc.run_probes("fake-key", "gemini-1.5-flash")
        finally:
            gc._GEMINI_API_BASE = orig
            server.shutdown()
        assert len(results) == 11


class TestGeminiConnect:
    def test_connect_returns_scan_context(self):
        server, base = _start_mock_gemini(echo=False)
        import connectors.gemini_connector as gc
        orig = gc._GEMINI_API_BASE
        gc._GEMINI_API_BASE = base
        try:
            ctx = gc.connect(api_key="fake-key", model="gemini-1.5-flash", target_dir=HARDENED)
        finally:
            gc._GEMINI_API_BASE = orig
            server.shutdown()
        assert ctx.mode == "gemini"
        assert ctx.live_model == "gemini-1.5-flash"
        assert len(ctx.probe_results) == 11


# ===========================================================================
# hash connector tests
# ===========================================================================

class TestHashChatRequest:
    def test_safe_response_returned(self):
        server, host = _start_mock_hash(echo=False)
        try:
            text, err = hash_request(host, "", "sentinel-test", "Hello")
        finally:
            server.shutdown()
        assert err == ""
        assert "cannot help" in text.lower()

    def test_connection_error_returns_error_string(self):
        text, err = hash_request("http://127.0.0.1:19998", "", "sentinel-test", "hello")
        assert text == ""
        assert err != ""

    def test_bearer_token_accepted(self):
        server, host = _start_mock_hash(echo=False)
        try:
            text, err = hash_request(host, "my-secret-token", "sentinel-test", "Hello")
        finally:
            server.shutdown()
        assert err == ""


class TestHashSystemPromptProbes:
    def test_system_prompt_probes_are_skipped(self):
        server, host = _start_mock_hash(echo=False)
        try:
            results = hash_run_probes(host, "")
        finally:
            server.shutdown()
        for pid in _SYSTEM_PROMPT_PROBES:
            assert pid in results
            r = results[pid]
            assert r.passed is True
            assert "SKIP" in r.error

    def test_skipped_probes_contain_explanation(self):
        server, host = _start_mock_hash(echo=False)
        try:
            results = hash_run_probes(host, "")
        finally:
            server.shutdown()
        for pid in _SYSTEM_PROMPT_PROBES:
            assert "system prompt" in results[pid].error.lower()
            assert "system.md" in results[pid].error

    def test_non_skipped_probes_all_executed(self):
        server, host = _start_mock_hash(echo=False)
        try:
            results = hash_run_probes(host, "")
        finally:
            server.shutdown()
        from connectors.api_connector import PROBES
        non_skip = [p.id for p in PROBES if p.id not in _SYSTEM_PROMPT_PROBES]
        for pid in non_skip:
            assert pid in results
            assert results[pid].error == "" or "SKIP" not in results[pid].error


class TestHashRunProbes:
    def test_safe_server_all_probes_pass(self):
        server, host = _start_mock_hash(echo=False)
        try:
            results = hash_run_probes(host, "")
        finally:
            server.shutdown()
        assert all(r.passed for r in results.values())

    def test_vulnerable_server_user_message_canaries_fail(self):
        server, host = _start_mock_hash(echo=True)
        try:
            results = hash_run_probes(host, "")
        finally:
            server.shutdown()
        # Canary probes that inject into user_message should fail
        failed = [pid for pid, r in results.items() if not r.passed]
        assert len(failed) > 0

    def test_total_probe_count(self):
        server, host = _start_mock_hash(echo=False)
        try:
            results = hash_run_probes(host, "")
        finally:
            server.shutdown()
        from connectors.api_connector import PROBES
        assert len(results) == len(PROBES)


class TestHashConnect:
    def test_connect_returns_scan_context(self):
        server, host = _start_mock_hash(echo=False)
        try:
            from connectors.hash_connector import connect as hash_connect
            ctx = hash_connect(host=host, token="", target_dir=HARDENED)
        finally:
            server.shutdown()
        assert ctx.mode == "hash"
        assert ctx.live_model == "hash"
        assert ctx.live_endpoint == host

    def test_connect_with_token(self):
        server, host = _start_mock_hash(echo=False)
        try:
            from connectors.hash_connector import connect as hash_connect
            ctx = hash_connect(host=host, token="secret", target_dir=HARDENED)
        finally:
            server.shutdown()
        assert ctx.live_error == ""
