"""perimeter-scan — passive external attack-surface scanner.

Public API:
    from perimeter_scan import passive_scan, ScanConfig, ScanResult, Severity
"""

from perimeter_scan.config import ScanConfig
from perimeter_scan.models import Asset, AssetKind, Finding, ScanResult
from perimeter_scan.scanner import passive_scan
from perimeter_scan.severity import Severity

__version__ = "0.1.0"

__all__ = [
    "passive_scan",
    "ScanConfig",
    "ScanResult",
    "Finding",
    "Asset",
    "AssetKind",
    "Severity",
    "__version__",
]
