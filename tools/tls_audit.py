"""Conservative TLS posture audit for ARES."""

from __future__ import annotations

import ipaddress
import socket
import ssl
import urllib.parse
from datetime import datetime, timezone

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

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


def _validated_handshake(host: str, port: int, timeout: float = TLS_TIMEOUT) -> dict:
    ctx = ssl.create_default_context()
    raw = socket.create_connection((host, port), timeout=timeout)
    try:
        sock = ctx.wrap_socket(raw, server_hostname=host)
        sock.close()
        return {"trusted": True, "hostname_validated": True, "error": ""}
    except ssl.SSLCertVerificationError as exc:
        message = str(exc)
        return {
            "trusted": False,
            "hostname_validated": "hostname" not in message.lower(),
            "error": message,
            "verify_code": getattr(exc, "verify_code", None),
            "verify_message": getattr(exc, "verify_message", ""),
        }
    finally:
        try:
            raw.close()
        except OSError:
            pass


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
    return sorted({
        value
        for kind, value in cert.get("subjectAltName", []) or []
        if kind.lower() in {"dns", "ip address"}
    })


def _hostname_match(cert: dict, host: str) -> bool | None:
    try:
        ssl.match_hostname(cert, host)
        return True
    except Exception:
        return False if cert else None


def _summary_from_cert_dict(cert: dict, host: str) -> dict:
    not_before = _cert_time(cert.get("notBefore", ""))
    not_after = _cert_time(cert.get("notAfter", ""))
    return _certificate_summary(
        host=host,
        subject=_name_from_x509_tuple(cert.get("subject", ())),
        issuer=_name_from_x509_tuple(cert.get("issuer", ())),
        not_before=not_before,
        not_after=not_after,
        sans=_sans(cert),
        hostname_match=_hostname_match(cert, host),
    )


def _summary_from_der(der_bytes: bytes, host: str) -> dict:
    cert = x509.load_der_x509_certificate(der_bytes)
    try:
        san_extension = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = [
            *san_extension.value.get_values_for_type(x509.DNSName),
            *(str(value) for value in san_extension.value.get_values_for_type(x509.IPAddress)),
        ]
    except x509.ExtensionNotFound:
        sans = []
    common_names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    match_dict = {
        "subjectAltName": [],
        "subject": tuple((("commonName", item.value),) for item in common_names),
    }
    for value in sans:
        try:
            ipaddress.ip_address(value)
            match_dict["subjectAltName"].append(("IP Address", value))
        except ValueError:
            match_dict["subjectAltName"].append(("DNS", value))
    return _certificate_summary(
        host=host,
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        not_before=getattr(cert, "not_valid_before_utc", cert.not_valid_before.replace(tzinfo=timezone.utc)),
        not_after=getattr(cert, "not_valid_after_utc", cert.not_valid_after.replace(tzinfo=timezone.utc)),
        sans=sorted(dict.fromkeys(sans)),
        hostname_match=_hostname_match(match_dict, host),
    )


def _certificate_summary(
    *,
    host: str,
    subject: str,
    issuer: str,
    not_before: datetime | None,
    not_after: datetime | None,
    sans: list[str],
    hostname_match: bool | None,
) -> dict:
    now = datetime.now(timezone.utc)
    days_until_expiry = (
        int((not_after - now).total_seconds() // 86400)
        if not_after
        else None
    )
    return {
        "subject": subject,
        "issuer": issuer,
        "not_before": not_before.isoformat() if not_before else "",
        "not_after": not_after.isoformat() if not_after else "",
        "days_until_expiry": days_until_expiry,
        "expired": bool(not_after and not_after < now),
        "not_yet_valid": bool(not_before and not_before > now),
        "self_signed_possible": bool(subject and issuer and subject == issuer),
        "sans": sans,
        "missing_san": not sans,
        "hostname_match": hostname_match,
    }


def _collect_certificate(host: str, port: int) -> tuple[dict, str, str]:
    sock = _handshake(host, port)
    try:
        try:
            der_bytes = sock.getpeercert(binary_form=True)
        except TypeError:
            der_bytes = b""
        cert_dict = {}
        if not der_bytes:
            cert_dict = sock.getpeercert() or {}
        summary = _summary_from_der(der_bytes, host) if der_bytes else _summary_from_cert_dict(cert_dict, host)
        cipher = sock.cipher() or ()
        return summary, sock.version() or "", cipher[0] if cipher else ""
    finally:
        sock.close()


def _finding(title: str, severity: str, description: str, evidence: dict) -> dict:
    return {
        "title": title,
        "severity": severity,
        "risk": severity.lower(),
        "description": description,
        "evidence": evidence,
        "evidence_refs": ["tls_audit"],
    }


def _protocol_support(host: str, port: int) -> dict:
    results = {}
    for protocol in PROTOCOLS:
        try:
            sock = _handshake(host, port, protocol=protocol)
            sock.close()
            results[protocol] = "accepted"
        except ssl.SSLError as exc:
            results[protocol] = "error" if "unsupported" in str(exc).lower() else "refused"
        except Exception:
            results[protocol] = "error"
    return results


def tls_audit(host_or_url: str, scope: ScopeValidator) -> dict:
    scope.validate_network_target(host_or_url)
    host, port, original = _target(host_or_url)
    result = {
        "target": host,
        "port": port,
        "certificate": {},
        "validation": {},
        "protocols": {},
        "selected_tls_version": "",
        "selected_cipher": "",
        "findings": [],
        "coverage": {},
    }

    try:
        certificate, tls_version, cipher = _collect_certificate(host, port)
        result["certificate"] = certificate
        result["selected_tls_version"] = tls_version
        result["selected_cipher"] = cipher
        result["coverage"]["certificate"] = "success"
    except Exception as exc:
        result["coverage"]["certificate"] = "failed"
        result["coverage"]["error"] = type(exc).__name__

    try:
        result["validation"] = _validated_handshake(host, port)
        result["coverage"]["chain_validation"] = (
            "success" if result["validation"].get("trusted") else "failed"
        )
    except Exception as exc:
        result["validation"] = {"trusted": False, "hostname_validated": False, "error": str(exc)}
        result["coverage"]["chain_validation"] = "failed"

    result["protocols"] = _protocol_support(host, port)
    protocol_values = list(result["protocols"].values())
    if protocol_values and all(value == "error" for value in protocol_values):
        result["coverage"]["protocols"] = "failed"
        result["coverage"]["protocol_error"] = "all_protocol_checks_failed"
    else:
        result["coverage"]["protocols"] = "success"

    cert = result["certificate"]
    if cert.get("expired"):
        result["findings"].append(_finding("Expired TLS certificate", "HIGH", "The certificate is expired.", cert))
    if cert.get("not_yet_valid"):
        result["findings"].append(_finding("TLS certificate is not yet valid", "HIGH", "The certificate validity period has not started.", cert))
    days = cert.get("days_until_expiry")
    if days is not None and 0 <= days < 30:
        result["findings"].append(_finding("TLS certificate expiring soon", "MEDIUM", "The certificate expires in less than 30 days.", cert))
    if cert.get("missing_san"):
        result["findings"].append(_finding("TLS certificate missing SAN", "MEDIUM", "The certificate has no Subject Alternative Name extension.", cert))
    if cert.get("self_signed_possible"):
        result["findings"].append(_finding("Self-signed TLS certificate possible", "MEDIUM", "The certificate subject and issuer match.", cert))
    if result["validation"] and not result["validation"].get("trusted"):
        result["findings"].append(_finding("Untrusted TLS certificate chain", "HIGH", "Default trust validation failed.", result["validation"]))
    if cert.get("hostname_match") is False or result["validation"].get("hostname_validated") is False:
        result["findings"].append(_finding("TLS hostname mismatch", "HIGH", "The certificate does not match the requested hostname.", cert))
    if result["protocols"].get("TLSv1.0") == "accepted":
        result["findings"].append(_finding("TLS 1.0 accepted", "HIGH", "The server accepted TLS 1.0.", {"protocol": "TLSv1.0"}))
    if result["protocols"].get("TLSv1.1") == "accepted":
        result["findings"].append(_finding("TLS 1.1 accepted", "MEDIUM", "The server accepted TLS 1.1.", {"protocol": "TLSv1.1"}))
    cipher_name = result.get("selected_cipher", "")
    if any(marker in cipher_name.upper() for marker in WEAK_CIPHER_MARKERS):
        result["findings"].append(_finding("Weak TLS cipher selected", "HIGH", "A weak cipher was negotiated.", {"cipher": cipher_name}))
    result["coverage"]["target"] = original
    return result
