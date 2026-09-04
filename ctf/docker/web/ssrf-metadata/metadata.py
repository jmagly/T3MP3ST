"""Synthetic metadata service reachable only inside the SSRF lab network."""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

FLAG = "T3MP3ST{ssrf_t0_m0ck_m3t4d4t4}"
ACCESS_KEY = "ASIAEXAMPLE00000001"
TOKEN = "synthetic-session-token-for-training-only"
ROLE_PATH = "/latest/meta-data/iam/security-credentials/ctf-role"


class Handler(BaseHTTPRequestHandler):
    def send_payload(self, status: int, payload: bytes, content_type: str = "text/plain") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        if self.path == "/health":
            self.send_payload(200, b'{"status":"ok"}', "application/json")
        elif self.path == "/latest/meta-data/iam/security-credentials/":
            self.send_payload(200, b"ctf-role\n")
        elif self.path == ROLE_PATH:
            body = json.dumps({
                "Code": "Success",
                "AccessKeyId": ACCESS_KEY,
                "SecretAccessKey": FLAG,
                "Token": TOKEN,
                "Notice": "SYNTHETIC CTF DATA - NOT A CLOUD CREDENTIAL",
            }, sort_keys=True).encode()
            self.send_payload(200, body, "application/json")
        else:
            self.send_payload(404, b"not found\n")

    def log_message(self, _format: str, *_args: object) -> None:
        return


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("METADATA_PORT", "8080"))), Handler).serve_forever()
