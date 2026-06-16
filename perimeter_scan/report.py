"""Render a ScanResult as colored terminal text or JSON."""

from __future__ import annotations

import json

from perimeter_scan.models import ScanResult
from perimeter_scan.severity import Severity

DEFAULT_FUNNEL_URL = "https://perimeter-hq.com"

_SEV_ANSI = {
    Severity.INFO: "\033[90m",       # grey
    Severity.LOW: "\033[36m",        # cyan
    Severity.MEDIUM: "\033[33m",     # yellow
    Severity.HIGH: "\033[31m",       # red
    Severity.CRITICAL: "\033[1;31m", # bold red
}
_RESET = "\033[0m"
_BOLD = "\033[1m"
_DIM = "\033[2m"


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2)


def render_text(
    result: ScanResult,
    *,
    min_severity: Severity = Severity.INFO,
    color: bool = True,
    quiet: bool = False,
    funnel_url: str = DEFAULT_FUNNEL_URL,
) -> str:
    reset = _RESET if color else ""
    bold = _BOLD if color else ""
    dim = _DIM if color else ""
    sev_c = _SEV_ANSI if color else {s: "" for s in Severity}

    findings = [f for f in result.findings if f.severity.rank >= min_severity.rank]
    out: list[str] = []

    if not quiet:
        out += [
            "",
            f"  {bold}⬡ perimeter-scan{reset}   {bold}{result.domain}{reset}",
            "",
            f"  {result.subdomain_count} hosts discovered · risk score {result.risk_score}",
            "",
        ]

    if findings:
        for f in findings:
            label = f.severity.value.upper().ljust(8)
            out.append(f"  {sev_c[f.severity]}{label}{reset}  {f.asset}")
            out.append(f"            {dim}{f.title}{reset}")
    else:
        out.append(f"  No findings at or above {min_severity.value} severity.")

    if not quiet:
        counts = result.counts_by_severity()
        summary = " · ".join(
            f"{sev_c[Severity(k)]}{k}{reset} {v}" for k, v in counts.items()
        )
        out += ["", f"  {summary}"]
        if result.errors:
            out += ["", f"  {dim}note: {'; '.join(result.errors[:3])}{reset}"]
        out += [
            "",
            f"  {dim}{'─' * 54}{reset}",
            f"  {dim}Passive scan (CT logs, DNS, standard web requests). Only scan{reset}",
            f"  {dim}domains you own or are authorized to assess.{reset}",
            "",
            f"  ▶ Monitor {result.domain} continuously, with alerts on new exposures:",
            f"    {bold}{funnel_url}{reset}",
            "",
        ]

    return "\n".join(out)
