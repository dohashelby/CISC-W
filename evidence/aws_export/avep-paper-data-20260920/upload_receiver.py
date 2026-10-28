from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


TARGET = Path(
    "/home/ubuntu/avep/avep-tenant-short-followup-deploy-20260918.tgz"
)


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        TARGET.write_bytes(self.rfile.read(length))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK\n")

    def log_message(self, format, *args):
        pass


HTTPServer(("127.0.0.1", 8767), Handler).handle_request()
