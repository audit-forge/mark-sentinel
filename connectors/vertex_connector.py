"""
M.A.R.K. Sentinel — Google Cloud Vertex AI Connector
Connects to Gemini via Vertex AI using a service account JSON key.

Setup:
  1. Go to console.cloud.google.com → create or select a project
  2. Enable the Vertex AI API (APIs & Services → Enable APIs → search "Vertex AI")
  3. IAM & Admin → Service Accounts → Create service account
     - Role: Vertex AI User (roles/aiplatform.user)
  4. Click the service account → Keys → Add Key → JSON → download the file
  5. Set VERTEX_SA_KEY_FILE=/path/to/key.json (or --vertex-key-file)
     Set VERTEX_PROJECT=your-project-id (or --vertex-project)
"""
import json
import urllib.request
import urllib.error

from connectors.config_connector import scan_directory, ScanContext
from connectors.api_connector import PROBES, _evaluate

PROBE_TIMEOUT = 45
PROBE_MAX_TOKENS = 300
DEFAULT_MODEL = "gemini-1.5-flash"
DEFAULT_REGION = "us-central1"

_VERTEX_URL_TMPL = (
    "https://{region}-aiplatform.googleapis.com/v1/projects/{project}"
    "/locations/{region}/publishers/google/models/{model}:generateContent"
)
_TOKEN_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]


def _get_access_token(key_file_path: str) -> str:
    from google.oauth2 import service_account
    creds = service_account.Credentials.from_service_account_file(
        key_file_path,
        scopes=_TOKEN_SCOPES,
    )
    import google.auth.transport.requests
    creds.refresh(google.auth.transport.requests.Request())
    return creds.token


def _chat_request(
    token: str, project: str, model: str, region: str,
    system_prompt: str, user_message: str,
) -> tuple[str, str]:
    """Returns (response_text, error_string)."""
    url = _VERTEX_URL_TMPL.format(region=region, project=project, model=model)
    payload: dict = {
        "contents": [{"role": "user", "parts": [{"text": user_message}]}],
        "generationConfig": {
            "maxOutputTokens": PROBE_MAX_TOKENS,
            "temperature": 0,
        },
    }
    if system_prompt:
        payload["systemInstruction"] = {"parts": [{"text": system_prompt}]}

    data = json.dumps(payload).encode()
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Bearer {token}",
    }
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


def run_probes(token: str, project: str, model: str, region: str) -> dict:
    """Run all probes against Vertex AI Gemini. Returns dict of probe_id -> ProbeResult."""
    results = {}
    for probe in PROBES:
        response, error = _chat_request(
            token, project, model, region, probe.system_prompt, probe.user_message
        )
        results[probe.id] = _evaluate(probe, response, error)
    return results


def connect(
    key_file: str,
    project: str,
    model: str = DEFAULT_MODEL,
    region: str = DEFAULT_REGION,
    target_dir: str = ".",
) -> ScanContext:
    """
    Scan target_dir for config issues and run live adversarial probes against Vertex AI Gemini.
    Requires a service account JSON key file and GCP project ID.
    """
    ctx = scan_directory(target_dir, mode="vertex")
    ctx.live_endpoint = _VERTEX_URL_TMPL.format(region=region, project=project, model=model)
    ctx.live_model = model

    try:
        token = _get_access_token(key_file)
        ctx.probe_results = run_probes(token, project, model, region)
    except Exception as e:
        ctx.live_error = str(e)

    return ctx
