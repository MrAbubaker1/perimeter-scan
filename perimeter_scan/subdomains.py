"""Passive subdomain discovery via Certificate Transparency logs.

CT logs are public record — this is the cleanest possible recon source and
involves zero contact with the target's infrastructure.

Primary source is crt.sh, which is notoriously flaky under load (502s and
timeouts are common). To keep the headline feature working, we retry crt.sh
with backoff and, if it's still unreachable, fall back to the Certspotter
public API before giving up. Only when *both* CT front-ends fail do we report
a degraded scan.
"""

from __future__ import annotations

import asyncio
import re

import httpx

_CRTSH_URL = "https://crt.sh/"
_CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"
# RFC 1123-ish hostname label validation, lenient enough for real-world certs.
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$")

# CT front-ends (crt.sh especially) are slow; give the lookup its own generous
# timeout regardless of the scan-wide per-request timeout.
_CT_TIMEOUT = 20.0
_CRTSH_RETRIES = 3


def _clean_names(raw_names: list[str], domain: str) -> set[str]:
    domain = domain.lower().strip(".")
    suffix = "." + domain
    out: set[str] = set()
    for raw in raw_names:
        for name in raw.replace("*.", "").splitlines():
            name = name.strip().lower().rstrip(".")
            if not name:
                continue
            if name != domain and not name.endswith(suffix):
                continue
            if not _HOSTNAME_RE.match(name):
                continue
            out.add(name)
    out.add(domain)
    return out


async def _fetch_crtsh(domain: str, client: httpx.AsyncClient) -> set[str]:
    """Query crt.sh with retry + backoff. Raises on final failure."""
    last_exc: Exception | None = None
    for attempt in range(_CRTSH_RETRIES):
        try:
            resp = await client.get(
                _CRTSH_URL,
                params={"q": f"%.{domain}", "output": "json"},
                headers={"Accept": "application/json"},
                timeout=_CT_TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json()
            raw = [row.get("name_value", "") for row in data if isinstance(row, dict)]
            return _clean_names(raw, domain)
        except (httpx.HTTPError, ValueError) as exc:
            last_exc = exc
            if attempt < _CRTSH_RETRIES - 1:
                await asyncio.sleep(0.8 * (attempt + 1))  # 0.8s, 1.6s
    raise last_exc if last_exc else RuntimeError("crt.sh unreachable")


async def _fetch_certspotter(domain: str, client: httpx.AsyncClient) -> set[str]:
    """Fallback CT source: Certspotter's keyless public issuances API."""
    resp = await client.get(
        _CERTSPOTTER_URL,
        params={
            "domain": domain,
            "include_subdomains": "true",
            "expand": "dns_names",
        },
        headers={"Accept": "application/json"},
        timeout=_CT_TIMEOUT,
    )
    resp.raise_for_status()
    data = resp.json()
    raw: list[str] = []
    for row in data:
        if isinstance(row, dict):
            raw.extend(n for n in row.get("dns_names", []) if isinstance(n, str))
    return _clean_names(raw, domain)


async def discover_subdomains(
    domain: str,
    client: httpx.AsyncClient,
    *,
    limit: int,
) -> tuple[list[str], list[str]]:
    """Return (sorted_subdomains, errors). Always includes apex + www."""
    errors: list[str] = []
    apex = domain.lower().strip(".")
    names: set[str] = {apex, f"www.{apex}"}

    try:
        names |= await _fetch_crtsh(domain, client)
    except (httpx.HTTPError, ValueError, RuntimeError) as crt_exc:
        # crt.sh exhausted its retries — try the fallback CT source.
        try:
            names |= await _fetch_certspotter(domain, client)
        except (httpx.HTTPError, ValueError) as cs_exc:
            crt_detail = str(crt_exc).strip() or type(crt_exc).__name__
            cs_detail = str(cs_exc).strip() or type(cs_exc).__name__
            errors.append(
                "subdomain discovery degraded — both CT sources unreachable "
                f"(crt.sh: {crt_detail}; certspotter: {cs_detail}); "
                "scanned apex + www only"
            )

    # Apex first, then shortest names (most likely to be live infra), capped.
    ordered = sorted(names, key=lambda n: (n != apex, n.count("."), len(n), n))
    return ordered[:limit], errors
