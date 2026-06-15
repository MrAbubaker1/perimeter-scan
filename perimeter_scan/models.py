"""Dataclasses produced by the scanner — persistence-agnostic."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from perimeter_scan.severity import Severity, score_weight


class AssetKind(str, Enum):
    SUBDOMAIN = "subdomain"
    DNS_RECORD = "dns_record"
    TLS_CERT = "tls_cert"
    HTTP_SERVICE = "http_service"


@dataclass(slots=True)
class Asset:
    kind: AssetKind
    value: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def key(self) -> tuple[str, str]:
        return (self.kind.value, self.value)


@dataclass(slots=True)
class Finding:
    rule_id: str
    title: str
    severity: Severity
    asset: str
    detail: dict[str, Any] = field(default_factory=dict)
    remediation: str = ""

    def key(self) -> tuple[str, str]:
        """Identity used for de-dup / change-detection between scans."""
        return (self.rule_id, self.asset)


@dataclass(slots=True)
class ScanResult:
    domain: str
    started_at: datetime
    finished_at: datetime | None = None
    assets: list[Asset] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def add_asset(self, asset: Asset) -> None:
        self.assets.append(asset)

    def finish(self) -> "ScanResult":
        self.finished_at = datetime.now(timezone.utc)
        # Deterministic ordering: worst findings first, then by asset.
        self.findings.sort(key=lambda f: (-f.severity.rank, f.asset, f.rule_id))
        return self

    @property
    def risk_score(self) -> int:
        """0+ integer; higher is worse."""
        return sum(score_weight(f.severity) for f in self.findings)

    def counts_by_severity(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out

    @property
    def subdomain_count(self) -> int:
        return sum(1 for a in self.assets if a.kind is AssetKind.SUBDOMAIN)

    def to_dict(self) -> dict[str, Any]:
        """JSON-serializable view (used by ``--json``)."""
        return {
            "domain": self.domain,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "subdomain_count": self.subdomain_count,
            "risk_score": self.risk_score,
            "counts": self.counts_by_severity(),
            "findings": [
                {
                    "severity": f.severity.value,
                    "rule_id": f.rule_id,
                    "title": f.title,
                    "asset": f.asset,
                    "remediation": f.remediation,
                    "detail": f.detail,
                }
                for f in self.findings
            ],
            "errors": self.errors,
        }
