"""Tests for the extracted scanner primitives (pure, no network)."""

from perimeter_scan.severity import Severity, parse_severity, score_weight
from perimeter_scan.subdomains import _clean_names
from perimeter_scan.takeover import assess_takeover


def test_severity_ordering_and_parse():
    assert Severity.INFO < Severity.MEDIUM < Severity.CRITICAL
    assert parse_severity("HIGH") is Severity.HIGH
    assert score_weight(Severity.CRITICAL) > score_weight(Severity.LOW)


def test_clean_names_filters_other_domains():
    out = _clean_names(["*.example.com", "api.example.com", "evil.com", "bad name"], "example.com")
    assert "api.example.com" in out
    assert "example.com" in out
    assert "evil.com" not in out
    assert all(" " not in n for n in out)


def test_takeover_high_confidence_on_nxdomain():
    v = assess_takeover(host="b.example.com", cname="x.herokudns.com", target_nxdomain=True, body_snippet="")
    assert v is not None and v.service == "Heroku" and v.confidence == "high"


def test_takeover_none_without_cname():
    assert assess_takeover(host="x.com", cname=None, target_nxdomain=True, body_snippet="") is None
