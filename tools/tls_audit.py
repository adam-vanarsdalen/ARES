"""Conservative TLS posture audit for ARES."""

from __future__ import annotations

import socket
import ssl
import urllib.parse
from datetime import datetime, timezone

from utils.config import TLS_TIMEOUT
from utils.scope_validator import ScopeValidator


PROTOCOLS = ("TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3")
WEAK_CIPHER_MARKERS = ("RC4", "3DES", "DES", "NULL", "EXPORT", "MD5")


def _target(host_or_url: str) -> tuple[str, int, str]:
    value = (host_or_url or "").strip()
    parsed = urllib.parse.urlparse(value if "://" in value else f"//{value}")
    host = parsed.hostname or value.split("/", 1)[0].split(":", 1)[0]
    port = parsed.port or 443
    return host.rstrip("."), port, value


def _context_for_protocol(protocol: str | None = None) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if protocol and hasattr(ssl, "TLSVersion"):
        versions = {
            "TLSv1.0": getattr(ssl.TLSVersion, "TLSv1", None),
            "TLSv1.1": getattr(ssl.TLSVersion, "TLSv1_1", None),
            "TLSv1.2": getattr(ssl.TLSVersion, "TLSv1_2", None),
            "TLSv1.3": getattr(ssl.TLSVersion, "TLSv1_3", None),
        }
        version = versions.get(protocol)
        if version:
            ctx.minimum_version = version
            ctx.maximum_version = version
    return ctx


def _handshake(host: str, port: int, protocol: str | None = None, timeout: float = TLS_TIMEOUT):
    ctx = _context_for_protocol(protocol)
    raw = socket.create_connection((host, port), timeout=timeout)
    return ctx.wrap_socket(raw, server_hostname=host)


def _name_from_x509_tuple(value) -> str:
    parts = []
    for group in value or []:
        for key, val in group:
            parts.append(f"{key}={val}")
    return ", ".join(parts)


def _cert_time(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromtimestamp(ssl.cert_time_to_seconds(value), tz=timezone.utc)
    except Exception:
        return None


def _sans(cert: dict) -> list[str]:
    out = []
    for kind, value in cert.get("subjectAltName", []) or []:
        if kind.lower() == "dns":
            out.append(value)
    return sorted(dict.fromkeys(out))


def _hostname_match(cert: dict, host: str) -> bool | None:
    try:
        ssl.match_hostname(cert, host)
        return True
    except Exception:
        return False if cert else None


def _finding(title: str, severity: str, description: str, evidence: dict) -> dict:
    return {
        "title": title,
        "severity": severity,
        "risk": severity.lower(),
        "description": description,
        "evidence": evidence,
        "evidence_refs": ["tls_audit"],
    }


def _certificate_summary(cert: dict, host: str) -> dict:
    not_before_dt = _cert_time(cert.get("notBefore", ""))
    not_after_dt = _cert_time(cert.get("notAfter", ""))
    now = datetime.now(timezone.utc)
    days_until_expiry = None
    if not_after_dt:
        days_until_expiry = int((not_after_dt - now).total_seconds() // 86400)
    subject = _name_from_x509_tuple(cert.get("subject", ()))
    issuer = _name_from_x509_tuple(cert.get("issuer", ()))
    return {
        "subject": subject,
        "issuer": issuer,
        "not_before": not_before_dt.isoformat() if not_before_dt else "",
        "not_after": not_after_dt.isoformat() if not_after_dt else "",
        "days_until_expiry": days_until_expiry,
        "expired": bool(days_until_expiry is not None and days_until_expiry < 0),
        "self_signed_possible": bool(subject and issuer and subject == issuer),
        "sans": _sans(cert),
        "hostname_match": _hostname_match(cert, host),
    }


def _protocol_support(host: str, port: int) -> dict:
    results = {}
    for protocol in PROTOCOLS:
        try:
            sock = _handshake(host, port, protocol=protocol)
            try:
                sock.close()
            except Exception:
                pass
            results[protocol] = "accepted"
        except ssl.SSLError as exc:
            results[protocol] = "refused"
            if "unsupported" in str(exc).lower():
                results[protocol] = "error"
        except Exception:
            results[protocol] = "error"
    return results


def tls_audit(host_or_url: str, scope: ScopeValidator) -> dict:
    scope.assert_in_scope(host_or_url)
    host, port, original = _target(host_or_url)
    result = {
        "target": host,
        "port": port,
        "certificate": {},
        "protocols": {},
        "selected_tls_version": "",
        "selected_cipher": "",
        "findings": [],
        "coverage": {},
    }

    try:
        sock = _handshake(host, port)
        cert = sock.getpeercert() or {}
        cipher = sock.cipher() or ()
        result["selected_tls_version"] = sock.version() or ""
        result["selected_cipher"] = cipher[0] if cipher else ""
        try:
            sock.close()
        except Exception:
            pass
        result["certificate"] = _certificate_summary(cert, host)
        result["coverage"]["certificate"] = "success"
    except Exception as exc:
        result["coverage"]["certificate"] = "failed"
        result["coverage"]["error"] = type(exc).__name__
        cert = {}

    result["protocols"] = _protocol_support(host, port)
    result["coverage"]["protocols"] = "success"

    cert_summary = result["certificate"]
    if cert_summary.get("expired"):
        result["findings"].append(_finding("Expired TLS certificate", "HIGH", "The certificate is expired.", cert_summary))
    days = cert_summary.get("days_until_expiry")
    if days is not None and 0 <= days < 30:
        result["findings"].append(_finding("TLS certificate expiring soon", "MEDIUM", "The certificate expires in less than 30 days.", cert_summary))
    if cert_summary.get("self_signed_possible"):
        result["findings"].append(_finding("Self-signed TLS certificate possible", "MEDIUM", "The certificate subject and issuer match.", cert_summary))
    if cert_summary.get("hostname_match") is False:
        result["findings"].append(_finding("TLS hostname mismatch", "HIGH", "The certificate does not match the requested hostname.", cert_summary))
    if result["protocols"].get("TLSv1.0") == "accepted":
        result["findings"].append(_finding("TLS 1.0 accepted", "HIGH", "The server accepted TLS 1.0.", {"protocol": "TLSv1.0"}))
    if result["protocols"].get("TLSv1.1") == "accepted":
        result["findings"].append(_finding("TLS 1.1 accepted", "MEDIUM", "The server accepted TLS 1.1.", {"protocol": "TLSv1.1"}))
    cipher_name = result.get("selected_cipher", "")
    if any(marker in cipher_name.upper() for marker in WEAK_CIPHER_MARKERS):
        result["findings"].append(_finding("Weak TLS cipher selected", "HIGH", "A weak cipher was negotiated.", {"cipher": cipher_name}))
    result["coverage"]["target"] = original
    return result
