import json
from datetime import datetime, timezone

import pytest

import perimeter_scan.cli as cli
from perimeter_scan.cli import normalize_domain
from perimeter_scan.models import Finding, ScanResult
from perimeter_scan.severity import Severity


@pytest.mark.parametrize("raw,expected", [
    ("example.com", "example.com"),
    ("https://example.com/path?q=1", "example.com"),
    ("http://sub.example.com:8443/x", "sub.example.com"),
    ("user@example.com", "example.com"),
    ("  Example.COM. ", "example.com"),
])
def test_normalize_valid(raw, expected):
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize("raw", ["", "not a domain", "localhost", "http://"])
def test_normalize_invalid(raw):
    assert normalize_domain(raw) is None


def _fake_result(domain, severities):
    r = ScanResult(domain=domain, started_at=datetime.now(timezone.utc))
    for i, sev in enumerate(severities):
        r.add_finding(Finding(f"r{i}", "t", sev, domain))
    return r.finish()


@pytest.fixture
def patch_scan(monkeypatch):
    def _set(severities):
        async def fake(domain, *, config=None):
            return _fake_result(domain, severities)
        monkeypatch.setattr(cli, "passive_scan", fake)
    return _set


def test_invalid_domain_returns_2(capsys):
    assert cli.main(["not a domain"]) == 2
    assert "not a valid domain" in capsys.readouterr().err


def test_json_output(patch_scan, capsys):
    patch_scan([Severity.MEDIUM])
    assert cli.main(["example.com", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["domain"] == "example.com"


def test_fail_on_triggers_exit_1(patch_scan):
    patch_scan([Severity.HIGH])
    assert cli.main(["example.com", "--fail-on", "high", "--json"]) == 1


def test_fail_on_below_threshold_exit_0(patch_scan):
    patch_scan([Severity.LOW])
    assert cli.main(["example.com", "--fail-on", "high", "--json"]) == 0


def test_no_fail_on_by_default(patch_scan):
    patch_scan([Severity.CRITICAL])
    assert cli.main(["example.com", "--json"]) == 0
