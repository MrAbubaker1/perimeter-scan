"""TLS certificate inspection.

A single TLS handshake to the host's own advertised HTTPS port — the same
thing any browser does when you visit the site. We read whatever certificate
is presented (including expired / self-signed ones) and flag hygiene problems.

We deliberately do NOT verify the chain during the handshake: the goal is to
*inspect* the cert, not to reject bad ones. ``getpeercert(binary_form=True)``
returns the DER even under ``CERT_NONE``, which we then parse with
``cryptography``.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID


@dataclass(slots=True)
class TlsInfo:
    host: str
    ok: bool = False
    error: str | None = None
    not_after: datetime | None = None
    not_before: datetime | None = None
    issuer: str | None = None
    subject: str | None = None
    self_signed: bool = False
    days_to_expiry: int | None = None


def _common_name(name: x509.Name) -> str:
    try:
        attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
        if attrs:
            return str(attrs[0].value)
        org = name.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        if org:
            return str(org[0].value)
    except Exception:  # pragma: no cover - defensive
        pass
    return name.rfc4514_string()


def _utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _blocking_fetch(host: str, port: int, timeout: float) -> TlsInfo:
    info = TlsInfo(host=host)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError) as exc:
        info.error = str(exc)
        return info

    if not der:
        info.error = "no certificate presented"
        return info

    try:
        cert = x509.load_der_x509_certificate(der, default_backend())
    except Exception as exc:  # pragma: no cover - malformed cert
        info.error = f"could not parse certificate: {exc!s}"
        return info

    info.ok = True
    info.not_after = _utc(cert.not_valid_after_utc)
    info.not_before = _utc(cert.not_valid_before_utc)
    info.days_to_expiry = (info.not_after - datetime.now(timezone.utc)).days
    info.issuer = _common_name(cert.issuer)
    info.subject = _common_name(cert.subject)
    info.self_signed = cert.issuer == cert.subject
    return info


async def inspect_tls(host: str, *, port: int = 443, timeout: float = 8.0) -> TlsInfo:
    return await asyncio.to_thread(_blocking_fetch, host, port, timeout)
