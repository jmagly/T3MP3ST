"""Dependency-free HTTP delivery for the isolated SSRF challenge."""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

from challenge import fetch_url


class Handler(BaseHTTPRequestHandler):
    def bounded_content_length(self) -> int:
        try:
            return max(0, min(int(self.headers.get("Content-Length", "0")), 2048))
        except ValueError:
            return 0

    def send_json(self, status: int, payload: dict[str, object]) -> None:
        body = json.dumps(payload, sort_keys=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        if self.path == "/health":
            self.send_json(200, {"status": "ok"})
        elif self.path in {"", "/"}:
            self.send_json(200, {
                "service": "t3mp3st-ctf-ssrf-metadata",
                "usage": "POST /fetch with a form-encoded url",
            })
        else:
            self.send_json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        if self.path != "/fetch":
            self.send_json(404, {"error": "not found"})
            return
        fields = parse_qs(self.rfile.read(self.bounded_content_length()).decode(errors="replace"))
        target = fields.get("url", [""])[0]
        try:
            status, content_type, body = fetch_url(target)
        except ValueError as error:
            self.send_json(400, {"error": str(error)})
            return
        self.send_json(200, {"upstream_status": status, "content_type": content_type, "body": body})

    def log_message(self, _format: str, *_args: object) -> None:
        return


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", "8080"))), Handler).serve_forever()
