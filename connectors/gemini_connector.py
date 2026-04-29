"""
M.A.R.K. Sentinel — Gemini Connector
Connects to Google Gemini via the native generateContent API.
Supports all probes — Gemini's systemInstruction field accepts per-request system prompts.
"""
import json
import urllib.request
import urllib.error

from connectors.config_connector import scan_directory, ScanContext
from connectors.api_connector import PROBES, _evaluate

PROBE_TIMEOUT = 30
PROBE_MAX_TOKENS = 300
DEFAULT_MODEL = "gemini-1.5-flash"
_GEMINI_API_BASE = "https://generativelanguage.googleapis.com/v1beta/models"


def _chat_request(api_key: str, model: str, system_prompt: str, user_message: str) -> tuple[str, str]:
    """Returns (response_text, error_string)."""
    url = f"{_GEMINI_API_BASE}/{model}:generateContent?key={api_key}"
    payload: dict = {
        "contents": [
            {"role": "user", "parts": [{"text": user_message}]}
        ],
        "generationConfig": {
            "maxOutputTokens": PROBE_MAX_TOKENS,
            "temperature": 0,
        },
    }
    if system_prompt:
        payload["systemInstruction"] = {"parts": [{"text": system_prompt}]}

    data = json.dumps(payload).encode()
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=PROBE_TIMEOUT) as resp:
            body = json.loads(resp.read().decode())
            text = body["candidates"][0]["content"]["parts"][0]["text"]
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
    """Run all probes against Gemini. Returns dict of probe_id -> ProbeResult."""
    results = {}
    for probe in PROBES:
        response, error = _chat_request(api_key, model, probe.system_prompt, probe.user_message)
        results[probe.id] = _evaluate(probe, response, error)
    return results


def connect(api_key: str, model: str = DEFAULT_MODEL, target_dir: str = ".") -> ScanContext:
    """
    Scan target_dir for config issues and run live adversarial probes against Gemini.
    Requires a Google AI API key (console.cloud.google.com or aistudio.google.com).
    """
    ctx = scan_directory(target_dir, mode="gemini")
    ctx.live_endpoint = _GEMINI_API_BASE
    ctx.live_model = model
    try:
        ctx.probe_results = run_probes(api_key, model)
    except Exception as e:
        ctx.live_error = str(e)
    return ctx
