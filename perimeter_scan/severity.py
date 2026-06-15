"""Severity model."""

from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _RANK[self]

    def __lt__(self, other: "Severity") -> bool:  # enables sorting
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank


_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

# Points contributed to a domain's risk score by one finding of each severity.
_SCORE_WEIGHT: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 2,
    Severity.MEDIUM: 5,
    Severity.HIGH: 12,
    Severity.CRITICAL: 25,
}


def score_weight(severity: Severity) -> int:
    return _SCORE_WEIGHT[severity]


def parse_severity(value: str) -> Severity:
    return Severity(value.lower().strip())
