"""DNS resolution for discovered hosts.

We only query public resolvers about public records — no contact with the
target's own services here.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import dns.asyncresolver
import dns.resolver


@dataclass(slots=True)
class DnsInfo:
    host: str
    resolves: bool = False
    a: list[str] = field(default_factory=list)
    aaaa: list[str] = field(default_factory=list)
    cname: str | None = None
    mx: list[str] = field(default_factory=list)
    ns: list[str] = field(default_factory=list)
    txt: list[str] = field(default_factory=list)
    nxdomain: bool = False


def _resolver(timeout: float) -> dns.asyncresolver.Resolver:
    r = dns.asyncresolver.Resolver()
    r.timeout = timeout
    r.lifetime = timeout
    return r


async def _query(resolver: dns.asyncresolver.Resolver, host: str, rtype: str) -> list[str]:
    try:
        answer = await resolver.resolve(host, rtype)
        return [r.to_text().strip('"') for r in answer]
    except (
        dns.resolver.NoAnswer,
        dns.resolver.NXDOMAIN,
        dns.resolver.NoNameservers,
        dns.resolver.LifetimeTimeout,
        Exception,
    ):
        return []


async def resolve_host(host: str, *, timeout: float) -> DnsInfo:
    resolver = _resolver(timeout)
    info = DnsInfo(host=host)

    # CNAME first — it drives the takeover heuristic.
    try:
        cname_ans = await resolver.resolve(host, "CNAME")
        info.cname = str(cname_ans[0].target).rstrip(".") if cname_ans else None
    except dns.resolver.NXDOMAIN:
        info.nxdomain = True
    except Exception:
        info.cname = None

    info.a = await _query(resolver, host, "A")
    info.aaaa = await _query(resolver, host, "AAAA")
    info.mx = await _query(resolver, host, "MX")
    info.ns = await _query(resolver, host, "NS")
    info.txt = await _query(resolver, host, "TXT")

    info.resolves = bool(info.a or info.aaaa or info.cname)
    return info
