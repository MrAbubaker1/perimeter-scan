"""Passive scan orchestrator.

Pipeline for a single domain:

  1. Discover subdomains via Certificate Transparency (crt.sh)   [passive]
  2. Resolve DNS for each host                                   [passive]
  3. For hosts that resolve: inspect TLS + probe HTTP headers    [light]
  4. Run the subdomain-takeover heuristic over DNS + HTTP        [analysis]
  5. Aggregate assets + severity-ranked findings into ScanResult

Everything is bounded by a concurrency semaphore and per-request timeouts so a
single scan can't hammer a target or run away with resources.

Only scan domains you own or are authorized to assess.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import httpx

from perimeter_scan.config import ScanConfig
from perimeter_scan.dns_recon import DnsInfo, resolve_host
from perimeter_scan.http_probe import probe_http
from perimeter_scan.models import Asset, AssetKind, Finding, ScanResult
from perimeter_scan.subdomains import discover_subdomains
from perimeter_scan.takeover import assess_takeover
from perimeter_scan.tls import inspect_tls
from perimeter_scan.severity import Severity

# A cert inside this window should be renewed; past zero it is already expired.
_EXPIRY_WARN_DAYS = 21


async def _scan_host(
    host: str,
    apex: str,
    client: httpx.AsyncClient,
    config: ScanConfig,
    sem: asyncio.Semaphore,
) -> tuple[Asset, list[Finding]]:
    async with sem:
        findings: list[Finding] = []
        dns_info: DnsInfo = await resolve_host(host, timeout=config.dns_timeout)

        asset = Asset(
            kind=AssetKind.SUBDOMAIN,
            value=host,
            metadata={
                "resolves": dns_info.resolves,
                "cname": dns_info.cname,
                "a": dns_info.a,
                "is_apex": host == apex,
            },
        )

        if not dns_info.resolves and not dns_info.cname:
            return asset, findings

        http_info = await probe_http(host, client)

        # --- Subdomain takeover -------------------------------------------------
        verdict = assess_takeover(
            host=host,
            cname=dns_info.cname,
            target_nxdomain=dns_info.nxdomain,
            body_snippet=http_info.body_snippet,
        )
        if verdict is not None:
            sev = Severity.CRITICAL if verdict.confidence == "high" else Severity.HIGH
            findings.append(
                Finding(
                    rule_id="takeover.dangling_cname",
                    title=f"Potential subdomain takeover ({verdict.service})",
                    severity=sev,
                    asset=host,
                    detail={
                        "service": verdict.service,
                        "cname": verdict.cname,
                        "reason": verdict.reason,
                        "confidence": verdict.confidence,
                    },
                    remediation=(
                        "Remove the dangling DNS record or re-claim the resource on "
                        f"{verdict.service}. Verify manually before acting."
                    ),
                )
            )

        # --- TLS ----------------------------------------------------------------
        if dns_info.resolves:
            tls = await inspect_tls(host, timeout=config.http_timeout)
            if tls.ok and tls.days_to_expiry is not None:
                if tls.days_to_expiry < 0:
                    findings.append(
                        Finding(
                            rule_id="tls.expired",
                            title="TLS certificate is expired",
                            severity=Severity.HIGH,
                            asset=host,
                            detail={"not_after": tls.not_after.isoformat() if tls.not_after else None},
                            remediation="Renew/replace the certificate immediately.",
                        )
                    )
                elif tls.days_to_expiry <= _EXPIRY_WARN_DAYS:
                    findings.append(
                        Finding(
                            rule_id="tls.expiring_soon",
                            title=f"TLS certificate expires in {tls.days_to_expiry} days",
                            severity=Severity.MEDIUM,
                            asset=host,
                            detail={"days_to_expiry": tls.days_to_expiry},
                            remediation="Schedule renewal; automate it if possible.",
                        )
                    )
                if tls.self_signed:
                    findings.append(
                        Finding(
                            rule_id="tls.self_signed",
                            title="TLS certificate is self-signed",
                            severity=Severity.MEDIUM,
                            asset=host,
                            detail={"issuer": tls.issuer},
                            remediation="Use a publicly trusted CA for internet-facing hosts.",
                        )
                    )

        # --- Security headers ---------------------------------------------------
        if http_info.reachable and http_info.scheme == "https":
            for header, severity, title in http_info.missing_headers:
                findings.append(
                    Finding(
                        rule_id=f"http.header.{header}",
                        title=title,
                        severity=Severity(severity),
                        asset=host,
                        detail={"url": http_info.url},
                        remediation=f"Add the `{header}` response header.",
                    )
                )
        elif http_info.reachable and http_info.scheme == "http":
            findings.append(
                Finding(
                    rule_id="http.no_https",
                    title="Service reachable over HTTP but not HTTPS",
                    severity=Severity.MEDIUM,
                    asset=host,
                    detail={"url": http_info.url},
                    remediation="Serve HTTPS and redirect HTTP -> HTTPS.",
                )
            )

        asset.metadata["http_status"] = http_info.status_code
        asset.metadata["server"] = http_info.server
        return asset, findings


async def passive_scan(domain: str, *, config: ScanConfig | None = None) -> ScanResult:
    """Run a passive attack-surface scan of ``domain``. Returns a ScanResult."""
    config = config or ScanConfig()
    domain = domain.lower().strip().strip(".")
    result = ScanResult(domain=domain, started_at=datetime.now(timezone.utc))

    timeout = httpx.Timeout(config.http_timeout)
    limits = httpx.Limits(max_connections=config.concurrency * 2)
    headers = {"User-Agent": config.user_agent}
    sem = asyncio.Semaphore(config.concurrency)

    async with httpx.AsyncClient(
        timeout=timeout, limits=limits, headers=headers, verify=False
    ) as client:
        hosts, errors = await discover_subdomains(domain, client, limit=config.max_subdomains)
        result.errors.extend(errors)

        tasks = [_scan_host(h, domain, client, config, sem) for h in hosts]
        for coro in asyncio.as_completed(tasks):
            try:
                asset, findings = await coro
            except Exception as exc:  # one host failing must not kill the scan
                result.errors.append(f"host scan error: {exc!s}")
                continue
            result.add_asset(asset)
            for f in findings:
                result.add_finding(f)

    return result.finish()
