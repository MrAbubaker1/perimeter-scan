"""Command-line interface: ``perimeter-scan <domain>``."""

from __future__ import annotations

import argparse
import asyncio
import re
import sys

from perimeter_scan import __version__
from perimeter_scan.config import DEFAULT_USER_AGENT, ScanConfig
from perimeter_scan.report import DEFAULT_FUNNEL_URL, render_json, render_text
from perimeter_scan.scanner import passive_scan
from perimeter_scan.severity import Severity, parse_severity

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})+$")
_SEV_CHOICES = [s.value for s in Severity]


def normalize_domain(raw: str) -> str | None:
    """Strip scheme/path/port/userinfo; return a bare hostname or None."""
    if not raw:
        return None
    value = re.sub(r"^https?://", "", raw.strip().lower())
    value = value.split("/")[0].split("@")[-1].split(":")[0].strip().strip(".")
    return value if value and _DOMAIN_RE.match(value) else None


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="perimeter-scan",
        description="Passive external attack-surface scanner. Only scan domains you "
        "own or are authorized to assess.",
        epilog="Continuous monitoring with alerts on new exposures: " + DEFAULT_FUNNEL_URL,
    )
    p.add_argument("domain", help="domain to scan, e.g. example.com")
    p.add_argument("--json", action="store_true", help="output machine-readable JSON")
    p.add_argument(
        "--min-severity", default="info", choices=_SEV_CHOICES,
        help="hide findings below this severity (default: info)",
    )
    p.add_argument(
        "--fail-on", default="none", choices=["none", *_SEV_CHOICES],
        help="exit 1 if any finding is at or above this severity (for CI; default: none)",
    )
    p.add_argument("--max-subdomains", type=int, default=25, help="cap hosts scanned (default: 25)")
    p.add_argument("--timeout", type=float, default=8.0, help="per-request timeout seconds (default: 8)")
    p.add_argument("--concurrency", type=int, default=12, help="parallel host scans (default: 12)")
    p.add_argument("--user-agent", default=DEFAULT_USER_AGENT, help="HTTP User-Agent to identify the scanner")
    p.add_argument("--no-color", action="store_true", help="disable ANSI color")
    p.add_argument("--quiet", action="store_true", help="findings only — no banner, summary, or footer")
    p.add_argument("--version", action="version", version=f"perimeter-scan {__version__}")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    domain = normalize_domain(args.domain)
    if domain is None:
        print(f"error: '{args.domain}' is not a valid domain", file=sys.stderr)
        return 2

    config = ScanConfig(
        max_subdomains=max(1, args.max_subdomains),
        http_timeout=args.timeout,
        dns_timeout=min(args.timeout, 4.0),
        concurrency=max(1, args.concurrency),
        user_agent=args.user_agent,
    )

    try:
        result = asyncio.run(passive_scan(domain, config=config))
    except KeyboardInterrupt:  # pragma: no cover
        print("aborted", file=sys.stderr)
        return 130
    except Exception as exc:  # pragma: no cover - network/runtime failures
        print(f"error: scan failed: {exc!s}", file=sys.stderr)
        return 2

    if args.json:
        print(render_json(result))
    else:
        use_color = (not args.no_color) and sys.stdout.isatty()
        print(render_text(
            result,
            min_severity=parse_severity(args.min_severity),
            color=use_color,
            quiet=args.quiet,
        ))

    if args.fail_on != "none":
        threshold = parse_severity(args.fail_on)
        if any(f.severity.rank >= threshold.rank for f in result.findings):
            return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
