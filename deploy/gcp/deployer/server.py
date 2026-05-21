import os
import subprocess
from http.server import HTTPServer, BaseHTTPRequestHandler

LOCK = "/tmp/deploying"
LOG  = "/tmp/deploy.log"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        if self.path != "/deploy":
            self.send_response(404)
            self.end_headers()
            return
        if os.path.exists(LOCK):
            self.send_response(409)
            self.end_headers()
            self.wfile.write(b"Deploy already in progress")
            return
        open(LOCK, "w").close()
        subprocess.Popen(["/deploy.sh"],
                         stdout=open(LOG, "w"),
                         stderr=subprocess.STDOUT)
        self.send_response(202)
        self.end_headers()
        self.wfile.write(b"Deploy started")

    def do_GET(self):
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
