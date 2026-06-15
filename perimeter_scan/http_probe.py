"""HTTP(S) probing for security headers and basic service fingerprinting.

A single unauthenticated GET to a host's own web service — standard browser
behaviour. We record the status, server banner, the response body snippet
(used by the takeover heuristic), and which security headers are present.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import httpx

# (header, severity-if-missing, human title). Lower-cased keys.
SECURITY_HEADERS: list[tuple[str, str, str]] = [
    ("strict-transport-security", "medium", "HSTS (Strict-Transport-Security) not set"),
    ("content-security-policy", "medium", "Content-Security-Policy not set"),
    ("x-frame-options", "low", "X-Frame-Options not set (clickjacking)"),
    ("x-content-type-options", "low", "X-Content-Type-Options not set (MIME sniffing)"),
    ("referrer-policy", "info", "Referrer-Policy not set"),
    ("permissions-policy", "info", "Permissions-Policy not set"),
]

_BODY_SNIPPET_LEN = 2048


@dataclass(slots=True)
class HttpInfo:
    host: str
    url: str | None = None
    reachable: bool = False
    status_code: int | None = None
    scheme: str | None = None
    server: str | None = None
    title: str | None = None
    body_snippet: str = ""
    present_headers: set[str] = field(default_factory=set)
    missing_headers: list[tuple[str, str, str]] = field(default_factory=list)
    error: str | None = None
    redirected_to: str | None = None


async def probe_http(host: str, client: httpx.AsyncClient) -> HttpInfo:
    info = HttpInfo(host=host)
    # Prefer HTTPS; fall back to HTTP so we still fingerprint takeover-able hosts.
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}/"
        try:
            resp = await client.get(url, follow_redirects=True)
        except httpx.HTTPError as exc:
            info.error = str(exc)
            continue

        info.reachable = True
        info.scheme = scheme
        info.url = url
        info.status_code = resp.status_code
        info.server = resp.headers.get("server")
        if str(resp.url) != url:
            info.redirected_to = str(resp.url)

        body = resp.text[:_BODY_SNIPPET_LEN] if resp.content else ""
        info.body_snippet = body
        lowered = {k.lower() for k in resp.headers}
        for header, severity, title in SECURITY_HEADERS:
            if header in lowered:
                info.present_headers.add(header)
            else:
                info.missing_headers.append((header, severity, title))
        info.error = None
        break

    return info
