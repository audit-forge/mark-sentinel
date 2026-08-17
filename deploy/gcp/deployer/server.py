import os
import subprocess
from hmac import compare_digest
from http.server import HTTPServer, BaseHTTPRequestHandler

STATE_DIR = "/run/deployer"
LOCK = f"{STATE_DIR}/deploy.lock"
LOG = f"{STATE_DIR}/deploy.log"
TOKEN_FILE = os.environ.get("DEPLOY_TOKEN_FILE", "/run/secrets/deploy_token")


def _read_token() -> str:
    try:
        with open(TOKEN_FILE, encoding="utf-8") as token_file:
            return token_file.read().strip()
    except OSError:
        return ""


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


HTTPServer(("0.0.0.0", 9000), Handler).serve_forever()
