import json
from datetime import datetime, timezone

from perimeter_scan.models import Asset, AssetKind, Finding, ScanResult
from perimeter_scan.report import render_json, render_text
from perimeter_scan.severity import Severity


def make_result() -> ScanResult:
    r = ScanResult(domain="example.com", started_at=datetime.now(timezone.utc))
    r.add_asset(Asset(AssetKind.SUBDOMAIN, "example.com"))
    r.add_finding(Finding("takeover.dangling_cname", "Potential subdomain takeover (Heroku)", Severity.CRITICAL, "blog.example.com"))
    r.add_finding(Finding("http.header.hsts", "HSTS not set", Severity.MEDIUM, "example.com"))
    r.add_finding(Finding("http.header.rp", "Referrer-Policy not set", Severity.INFO, "example.com"))
    return r.finish()


def test_text_contains_findings_and_funnel():
    out = render_text(make_result(), color=False)
    assert "perimeter-scan" in out
    assert "CRITICAL" in out
    assert "Potential subdomain takeover (Heroku)" in out
    assert "blog.example.com" in out
    assert "perimeter.example" in out  # the funnel CTA


def test_min_severity_filters():
    out = render_text(make_result(), color=False, min_severity=Severity.HIGH)
    assert "CRITICAL" in out
    assert "HSTS not set" not in out


def test_no_color_has_no_ansi():
    assert "\033[" not in render_text(make_result(), color=False)


def test_color_has_ansi():
    assert "\033[" in render_text(make_result(), color=True)


def test_quiet_suppresses_banner_keeps_findings():
    out = render_text(make_result(), color=False, quiet=True)
    assert "perimeter-scan" not in out
    assert "risk score" not in out
    assert "blog.example.com" in out


def test_json_shape():
    d = json.loads(render_json(make_result()))
    assert d["domain"] == "example.com"
    assert d["counts"]["critical"] == 1
    assert d["risk_score"] >= 25
    assert any(f["asset"] == "blog.example.com" for f in d["findings"])
