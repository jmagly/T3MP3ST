"""Narrow host-facing gateway into the internal-only SSRF lab."""
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener

UPSTREAM = os.environ.get("UPSTREAM", "http://ssrf-metadata:8080")
ALLOWED_PATHS = {"", "/", "/health", "/fetch"}
_OPENER = build_opener(ProxyHandler({}))


class ProxyHandler(BaseHTTPRequestHandler):
    def bounded_content_length(self) -> int:
        try:
            return max(0, min(int(self.headers.get("Content-Length", "0")), 2048))
        except ValueError:
            return 0

    def relay(self, method: str) -> None:
        path, _, _query = self.path.partition("?")
        if path not in ALLOWED_PATHS:
            self.send_error(404)
            return
        length = self.bounded_content_length()
        body = self.rfile.read(length) if length else None
        request = Request(UPSTREAM + path, data=body, method=method)
        if body is not None:
            request.add_header("Content-Type", "application/x-www-form-urlencoded")
        try:
            response = _OPENER.open(request, timeout=3)
        except HTTPError as error:
            response = error
        except URLError:
            self.send_error(502)
            return
        payload = response.read(8192)
        self.send_response(response.status)
        self.send_header("Content-Type", response.headers.get("Content-Type", "application/json"))
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        self.relay("GET")

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        self.relay("POST")

    def log_message(self, _format: str, *_args: object) -> None:
        return


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), ProxyHandler).serve_forever()
