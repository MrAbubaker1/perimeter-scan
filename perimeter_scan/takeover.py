"""Dangling-DNS / subdomain-takeover heuristic.

A subdomain is *potentially* takeover-able when it has a CNAME pointing at a
third-party service, but that target is unclaimed — signalled either by an
NXDOMAIN on the apex host or by a known "this resource does not exist"
fingerprint in the HTTP response body.

This is intentionally conservative and labelled "potential": confirming a
takeover requires manual review. We never attempt the takeover itself.

Fingerprints adapted from the well-known community ``can-i-take-over-xyz``
research. This is a representative subset, not exhaustive.
"""

from __future__ import annotations

from dataclasses import dataclass

# service label -> (cname substring, body fingerprint or None)
_SIGNATURES: list[tuple[str, str, str | None]] = [
    ("GitHub Pages", "github.io", "There isn't a GitHub Pages site here"),
    ("Amazon S3", "s3.amazonaws.com", "NoSuchBucket"),
    ("Amazon S3", "s3-website", "NoSuchBucket"),
    ("Heroku", "herokudns.com", "No such app"),
    ("Heroku", "herokuapp.com", "No such app"),
    ("Heroku", "herokussl.com", "No such app"),
    ("AWS CloudFront", "cloudfront.net", "The request could not be satisfied"),
    ("Azure", "azurewebsites.net", "404 Web Site not found"),
    ("Azure", "cloudapp.azure.com", None),
    ("Azure", "trafficmanager.net", None),
    ("Fastly", "fastly.net", "Fastly error: unknown domain"),
    ("Shopify", "myshopify.com", "Sorry, this shop is currently unavailable"),
    ("Ghost", "ghost.io", "The thing you were looking for is no longer here"),
    ("Tumblr", "domains.tumblr.com", "Whatever you were looking for doesn't currently exist"),
    ("Surge.sh", "surge.sh", "project not found"),
    ("Bitbucket", "bitbucket.io", "Repository not found"),
    ("Pantheon", "pantheonsite.io", "The gods are wise"),
    ("Zendesk", "zendesk.com", "Help Center Closed"),
    ("Readme.io", "readme.io", "Project doesnt exist"),
    ("Netlify", "netlify.app", "Not Found"),
]


@dataclass(slots=True)
class TakeoverVerdict:
    host: str
    service: str
    cname: str
    reason: str
    confidence: str  # "high" | "medium"


def _matches_cname(cname: str, needle: str) -> bool:
    return needle.lower() in cname.lower()


def assess_takeover(
    *,
    host: str,
    cname: str | None,
    target_nxdomain: bool,
    body_snippet: str,
) -> TakeoverVerdict | None:
    """Return a verdict if this host looks potentially takeover-able."""
    if not cname:
        return None

    body = (body_snippet or "").lower()
    for service, needle, fingerprint in _SIGNATURES:
        if not _matches_cname(cname, needle):
            continue
        # Strongest signal: CNAME to a known service whose apex is unregistered.
        if target_nxdomain:
            return TakeoverVerdict(
                host=host,
                service=service,
                cname=cname,
                reason=f"CNAME -> {service} target resolves to NXDOMAIN (unclaimed)",
                confidence="high",
            )
        # Next: the service's own "doesn't exist" page is being served.
        if fingerprint and fingerprint.lower() in body:
            return TakeoverVerdict(
                host=host,
                service=service,
                cname=cname,
                reason=f"CNAME -> {service} and response shows unclaimed-resource fingerprint",
                confidence="medium",
            )
    return None
