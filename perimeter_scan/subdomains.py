"""Passive subdomain discovery via Certificate Transparency logs (crt.sh).

CT logs are public record — this is the cleanest possible recon source and
involves zero contact with the target's infrastructure.
"""

from __future__ import annotations

import re

import httpx

_CRTSH_URL = "https://crt.sh/"
# RFC 1123-ish hostname label validation, lenient enough for real-world certs.
_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$")


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


async def discover_subdomains(
    domain: str,
    client: httpx.AsyncClient,
    *,
    limit: int,
) -> tuple[list[str], list[str]]:
    """Return (sorted_subdomains, errors). Always includes apex + www."""
    errors: list[str] = []
    names: set[str] = {domain.lower().strip("."), f"www.{domain.lower().strip('.')}"}
    try:
        resp = await client.get(
            _CRTSH_URL,
            params={"q": f"%.{domain}", "output": "json"},
            headers={"Accept": "application/json"},
        )
        resp.raise_for_status()
        data = resp.json()
        raw = [row.get("name_value", "") for row in data if isinstance(row, dict)]
        names |= _clean_names(raw, domain)
    except (httpx.HTTPError, ValueError) as exc:
        detail = str(exc).strip() or type(exc).__name__
        errors.append(f"crt.sh lookup failed ({detail}) — scanned apex + www only")

    # Apex first, then shortest names (most likely to be live infra), capped.
    ordered = sorted(names, key=lambda n: (n != domain, n.count("."), len(n), n))
    return ordered[:limit], errors
