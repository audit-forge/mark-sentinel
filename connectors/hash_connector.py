"""
M.A.R.K. Sentinel — Hash Connector
Connects to a local Hash-AI runtime via its /chat endpoint.

hash manages its own system prompt (set in system.md / hash.json) — probes that
require per-request system_prompt injection are automatically skipped with a clear
explanation in the report. All user-message-only probes run normally.

Default endpoint: http://127.0.0.1:8400
"""
import json
import os
import time
import urllib.request
import urllib.error

from connectors.config_connector import scan_directory, ScanContext
from connectors.api_connector import PROBES, _evaluate, ProbeResult

# Allow probe timeout to be overridden via env var for faster demos or constrained CI
PROBE_TIMEOUT = int(os.environ.get('HASH_PROBE_TIMEOUT', '60'))
DEFAULT_HOST = "http://127.0.0.1:8400"
_SESSION_TYPE = "main"

# Probes that inject canaries into system_prompt — hash controls its own, so these
# cannot be executed. They are surfaced as SKIP (not FAIL) in the report.
_SYSTEM_PROMPT_PROBES = frozenset({"out-003-a", "out-003-b", "out-002-a"})

_SKIP_REASON = (
    "SKIP: hash manages its own system prompt via system.md / hash.json. "
    "Per-request system_prompt injection is not supported by the /chat API. "
    "Audit system.md manually to verify confidentiality of sensitive data in the prompt."
)


def _chat_request(host: str, token: str, session_id: str, message: str) -> tuple[str, str]:
    """Returns (response_text, error_string)."""
    url = f"{host.rstrip('/')}/chat"
    payload = json.dumps({
        "message": message,
        "session_id": session_id,
        "session_type": _SESSION_TYPE,
    }).encode()
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=PROBE_TIMEOUT) as resp:
            body = json.loads(resp.read().decode())
            text = body.get("response", "")
            return text, ""
    except urllib.error.HTTPError as e:
        return "", f"HTTP {e.code}: {e.reason}"
    except urllib.error.URLError as e:
        return "", f"Connection error: {e.reason}"
    except (json.JSONDecodeError, KeyError) as e:
        return "", f"Response parse error: {e}"
    except Exception as e:
        return "", f"Error: {e}"


def run_probes(host: str, token: str) -> dict:
    """Run all applicable probes against hash. Returns dict of probe_id -> ProbeResult.

    Prints per-probe progress to stdout so long-running or timed-out probes are visible
    during demo runs. Probe timeout is governed by PROBE_TIMEOUT (env HASH_PROBE_TIMEOUT).
    """
    results = {}
    total = len(PROBES)
    for idx, probe in enumerate(PROBES, start=1):
        if probe.id in _SYSTEM_PROMPT_PROBES:
            print(f"  Probe {idx}/{total} {probe.id}: SKIP (system-prompt probe)")
            results[probe.id] = ProbeResult(
                probe_id=probe.id,
                check_id=probe.check_id,
                description=probe.description,
                response="",
                error=_SKIP_REASON,
                passed=True,
            )
            continue

        print(f"  Probe {idx}/{total} {probe.id}: running...", end='', flush=True)
        start = time.time()
        response, error = _chat_request(host, token, f"sentinel-{probe.id}", probe.user_message)
        res = _evaluate(probe, response, error)
        elapsed = time.time() - start
        status = 'PASS' if res.passed and not res.error else ('ERROR' if res.error else 'FAIL')
        extra = f" - {res.error}" if res.error else ''
        print(f" {status} ({elapsed:.1f}s){extra}")
        results[probe.id] = res
    return results


def connect(host: str = DEFAULT_HOST, token: str = "", target_dir: str = ".") -> ScanContext:
    """
    Scan target_dir for config issues and run live adversarial probes against hash.
    Optionally pass a bearer token if hash.json has auth enabled.
    """
    ctx = scan_directory(target_dir, mode="hash")
    ctx.live_endpoint = host
    ctx.live_model = "hash"
    try:
        ctx.probe_results = run_probes(host, token)
    except Exception as e:
        ctx.live_error = str(e)
    return ctx
