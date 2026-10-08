import os
import json
import re
import subprocess
from hmac import compare_digest
from http.server import HTTPServer, BaseHTTPRequestHandler

STATE_DIR = "/run/deployer"
LOCK = f"{STATE_DIR}/deploy.lock"
LOG = f"{STATE_DIR}/deploy.log"
TOKEN_FILE = os.environ.get("DEPLOY_TOKEN_FILE", "/run/secrets/deploy_token")
LIFECYCLE_DIR = os.environ.get("LIFECYCLE_DIR", "/opt/sentinel/deploy/gcp")
LICENSES_DIR = os.environ.get("LICENSES_DIR", "/opt/licenses")
PUBLIC_IP = os.environ.get("PUBLIC_IP", "")
CUSTOMER_UID = int(os.environ.get("CUSTOMER_UID", "999"))
_CUSTOMER_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\Z")
_TIERS = {"standard", "plus"}
_PROFILES = {
    "default", "iso42001", "atlas", "financial", "fedramp", "fedramp_20x",
    "cmmc", "biotech", "healthcare", "lifesciences", "owasp_agentic",
    "eu_ai_act", "professional_services",
}


def _read_token() -> str:
    try:
        with open(TOKEN_FILE, encoding="utf-8") as token_file:
            return token_file.read().strip()
    except OSError:
        return ""


def _write_license(payload: dict) -> None:
    customer_id = payload["customer_id"]
    customer_dir = os.path.join(LICENSES_DIR, customer_id)
    os.makedirs(customer_dir, mode=0o750, exist_ok=True)
    os.chown(customer_dir, CUSTOMER_UID, CUSTOMER_UID)
    os.chmod(customer_dir, 0o700)
    license_path = os.path.join(customer_dir, "license.json")
    document = {
        "customer_id": customer_id,
        "licensed_to": payload["customer_name"],
        "max_agents": payload["max_seats"],
        "grace_pct": 10,
        "expires_at": payload["expires"],
        "issued_at": payload["issued_at"],
        "issued_by": "RiskRaven AI",
        "plan": payload["tier"],
        "telemetry_url": "http://sentinel-admin:8000/api/telemetry",
        "telemetry_interval_h": 1,
    }
    temporary_path = f"{license_path}.tmp"
    with open(temporary_path, "w", encoding="utf-8") as license_file:
        json.dump(document, license_file)
        license_file.write("\n")
    os.chown(temporary_path, CUSTOMER_UID, CUSTOMER_UID)
    os.chmod(temporary_path, 0o400)
    os.replace(temporary_path, license_path)


def _validate_payload(payload: object, operation: str) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("invalid lifecycle request")
    customer_id = str(payload.get("customer_id", "")).strip()
    if not _CUSTOMER_ID.fullmatch(customer_id):
        raise ValueError("invalid customer ID")
    if operation == "remove":
        return {"customer_id": customer_id}

    customer_name = str(payload.get("customer_name", "")).strip()
    tier = str(payload.get("tier", "")).strip()
    expires = str(payload.get("expires", "")).strip()
    issued_at = str(payload.get("issued_at", "")).strip()
    agent_token = str(payload.get("agent_token", "")).strip()
    baseline_profile = str(payload.get("baseline_profile", "default")).strip()
    try:
        max_seats = int(payload.get("max_seats", 0))
        port = int(payload.get("port", 0))
    except (TypeError, ValueError) as exc:
        raise ValueError("invalid lifecycle numeric value") from exc
    if not customer_name or len(customer_name) > 200 or tier not in _TIERS:
        raise ValueError("invalid customer lifecycle request")
    if max_seats < 1 or max_seats > 1_000_000 or port != 80:
        raise ValueError("invalid customer lifecycle request")
    if not expires or not issued_at or baseline_profile not in _PROFILES:
        raise ValueError("invalid customer lifecycle request")
    if operation == "provision" and not agent_token:
        raise ValueError("missing agent token")
    return {
        "customer_id": customer_id,
        "customer_name": customer_name,
        "tier": tier,
        "expires": expires,
        "issued_at": issued_at,
        "max_seats": max_seats,
        "port": port,
        "agent_token": agent_token,
        "baseline_profile": baseline_profile,
    }


def _run_lifecycle(operation: str, payload: object) -> None:
    request = _validate_payload(payload, operation)
    scripts = {
        "provision": "provision_customer.sh",
        "restart": "restart_customer.sh",
        "remove": "remove_customer.sh",
    }
    script = os.path.join(LIFECYCLE_DIR, scripts[operation])
    if not os.path.isfile(script):
        raise RuntimeError("lifecycle script is unavailable")

    if operation == "remove":
        arguments = [request["customer_id"]]
    elif operation == "restart":
        _write_license(request)
        arguments = [request["customer_id"]]
    else:
        _write_license(request)
        arguments = [
            request["customer_id"], PUBLIC_IP, request["tier"], request["expires"],
            str(request["max_seats"]), request["customer_name"], str(request["port"]),
            request["agent_token"], request["baseline_profile"],
        ]
    subprocess.run(["bash", script, *arguments], check=True, timeout=90,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _agent_count(customer_id: str) -> int:
    if not _CUSTOMER_ID.fullmatch(customer_id):
        raise ValueError("invalid customer ID")
    result = subprocess.run(
        ["docker", "exec", f"sentinel-{customer_id}", "python3", "-c",
         "import sqlite3; conn=sqlite3.connect('/app/data/agents.db'); "
         "print(conn.execute('SELECT COUNT(*) FROM devices').fetchone()[0])"],
        capture_output=True, text=True, timeout=10, check=True,
    )
    return int(result.stdout.strip())


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        expected_token = _read_token()
        provided_token = self.headers.get("X-Arckon-Deploy-Token", "")
        if not expected_token or not compare_digest(provided_token, expected_token):
            self.send_response(403)
            self.end_headers()
            return
        if self.path.startswith("/lifecycle/"):
            operation = self.path.removeprefix("/lifecycle/")
            if operation not in {"provision", "restart", "remove"}:
                self.send_response(404)
                self.end_headers()
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length < 1 or length > 16_384:
                    raise ValueError("invalid request length")
                _run_lifecycle(operation, json.loads(self.rfile.read(length)))
            except (OSError, ValueError, subprocess.SubprocessError):
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"Lifecycle operation failed")
                return
            self.send_response(204)
            self.end_headers()
            return
        if self.path != "/deploy":
            self.send_response(404)
            self.end_headers()
            return
        os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
        try:
            lock_fd = os.open(LOCK, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(lock_fd)
        except FileExistsError:
            self.send_response(409)
            self.end_headers()
            self.wfile.write(b"Deploy already in progress")
            return
        try:
            log_fd = os.open(LOG, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(log_fd, "w") as log_file:
                subprocess.Popen(["/deploy.sh"], stdout=log_file, stderr=subprocess.STDOUT)
        except OSError:
            os.unlink(LOCK)
            self.send_response(500)
            self.end_headers()
            return
        self.send_response(202)
        self.end_headers()
        self.wfile.write(b"Deploy started")

    def do_GET(self):
        expected_token = _read_token()
        provided_token = self.headers.get("X-Arckon-Deploy-Token", "")
        if not expected_token or not compare_digest(provided_token, expected_token):
            self.send_response(403)
            self.end_headers()
            return
        if self.path == "/status":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"busy" if os.path.exists(LOCK) else b"idle")
        elif self.path.startswith("/usage/"):
            try:
                count = _agent_count(self.path.removeprefix("/usage/"))
            except (OSError, ValueError, subprocess.SubprocessError):
                self.send_response(404)
                self.end_headers()
                return
            body = json.dumps({"current_agents": count}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/log":
            try:
                body = open(LOG, "rb").read()[-8192:]
            except FileNotFoundError:
                body = b"No deploy log yet."
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()


if __name__ == "__main__":
    HTTPServer(("0.0.0.0", 9000), Handler).serve_forever()
