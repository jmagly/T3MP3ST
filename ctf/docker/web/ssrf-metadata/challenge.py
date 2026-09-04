"""URL fetch primitive for the isolated SSRF-to-mock-metadata lab.

The fetcher intentionally accepts an arbitrary HTTP URL. Network isolation,
not an application allow-list, prevents it from reaching real metadata or the
public internet. Never copy this intentionally vulnerable design into a
production service.
"""
from urllib.error import HTTPError, URLError
from urllib.request import ProxyHandler, Request, build_opener
from urllib.parse import urlsplit

MAX_BODY = 4096
MAX_URL = 512
_OPENER = build_opener(ProxyHandler({}))


def fetch_url(url: object) -> tuple[int, str, str]:
    """Fetch an unvalidated HTTP URL and return status, content type, body."""
    target = str(url).strip()[:MAX_URL]
    parsed = urlsplit(target)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("absolute http(s) URL required")
    request = Request(target, headers={"User-Agent": "T3MP3ST-CTF-SSRF/1"})
    try:
        response = _OPENER.open(request, timeout=2)
    except HTTPError as error:
        response = error
    except (URLError, OSError, TimeoutError) as error:
        return 502, "text/plain; charset=utf-8", f"unreachable: {type(error).__name__}"
    with response:
        body = response.read(MAX_BODY).decode(errors="replace")
        content_type = response.headers.get("Content-Type", "application/octet-stream")
        return response.status, content_type, body
