"""Scan configuration — a plain dataclass, no framework dependency."""

from __future__ import annotations

from dataclasses import dataclass

DEFAULT_USER_AGENT = "perimeter-scan/0.1 (+https://github.com/MrAbubaker1/perimeter-scan)"


@dataclass(slots=True)
class ScanConfig:
    """Tunables for a passive scan. Sensible defaults; override via the CLI."""

    max_subdomains: int = 25
    http_timeout: float = 8.0
    dns_timeout: float = 4.0
    concurrency: int = 12
    user_agent: str = DEFAULT_USER_AGENT
