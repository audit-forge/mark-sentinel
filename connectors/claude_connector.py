"""
M.A.R.K. Sentinel — Anthropic Claude Connector
Connects to Anthropic Claude via the native Messages API.
Requires an Anthropic API key (console.anthropic.com).
"""
import json
import urllib.request
import urllib.error

from connectors.config_connector import scan_directory, ScanContext
from connectors.api_connector import PROBES, _evaluate

PROBE_TIMEOUT = 30
PROBE_MAX_TOKENS = 300
DEFAULT_MODEL = "claude-sonnet-4-6"
_ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
_ANTHROPIC_VERSION = "2023-06-01"


def _chat_request(api_key: str, model: str, system_prompt: str, user_message: str) -> tuple[str, str]:
    """Returns (response_text, error_string)."""
    payload: dict = {
        "model": model,
        "max_tokens": PROBE_MAX_TOKENS,
        "messages": [{"role": "user", "content": user_message}],
    }
    if system_prompt:
        payload["system"] = system_prompt

    data = json.dumps(payload).encode()
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "x-api-key": api_key,
        "anthropic-version": _ANTHROPIC_VERSION,
    }
    req = urllib.request.Request(_ANTHROPIC_API_URL, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=PROBE_TIMEOUT) as resp:
            body = json.loads(resp.read().decode())
            text = body["content"][0]["text"]
            return text, ""
    except urllib.error.HTTPError as e:
        try:
            err_body = json.loads(e.read().decode())
            msg = err_body.get("error", {}).get("message", e.reason)
        except Exception:
            msg = e.reason
        return "", f"HTTP {e.code}: {msg}"
    except urllib.error.URLError as e:
        return "", f"Connection error: {e.reason}"
    except (KeyError, IndexError, json.JSONDecodeError) as e:
        return "", f"Response parse error: {e}"
    except Exception as e:
        return "", f"Error: {e}"


def run_probes(api_key: str, model: str) -> dict:
    """Run all probes against Claude. Returns dict of probe_id -> ProbeResult."""
    results = {}
    for probe in PROBES:
        response, error = _chat_request(api_key, model, probe.system_prompt, probe.user_message)
        results[probe.id] = _evaluate(probe, response, error)
    return results


def connect(api_key: str, model: str = DEFAULT_MODEL, target_dir: str = ".") -> ScanContext:
    """
    Scan target_dir for config issues and run live adversarial probes against Claude.
    Requires an Anthropic API key from console.anthropic.com.
    """
    ctx = scan_directory(target_dir, mode="anthropic")
    ctx.live_endpoint = _ANTHROPIC_API_URL
    ctx.live_model = model
    try:
        ctx.probe_results = run_probes(api_key, model)
    except Exception as e:
        ctx.live_error = str(e)
    return ctx
