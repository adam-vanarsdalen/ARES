"""Target normalization, SSRF protection, and Rules of Engagement scope checks."""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from typing import Iterable
from urllib.parse import urlsplit, urlunsplit

from utils.config import SAFE_TARGETS


_SAFE_TARGETS = {target.lower().rstrip(".") for target in SAFE_TARGETS}
_LOCAL_HOST_SUFFIXES = (".localhost", ".local", ".internal", ".lan", ".home")
_HOST_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


@dataclass
class Scope:
    """Defines the server-approved attack surface for an engagement."""

    domains: list[str] = field(default_factory=list)
    ip_ranges: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self):
        return {
            "domains": self.domains,
            "ip_ranges": self.ip_ranges,
            "urls": self.urls,
            "notes": self.notes,
        }


def normalize_target_url(value: str, default_scheme: str = "https") -> str:
    """Return a canonical HTTP(S) URL and reject ambiguous or malformed hosts."""

    raw = str(value or "").strip()
    if not raw:
        raise ValueError("Target is required")
    if "://" not in raw:
        try:
            literal = ipaddress.ip_address(raw)
            raw = f"{default_scheme}://[{literal.compressed}]" if literal.version == 6 else f"{default_scheme}://{literal.compressed}"
        except ValueError:
            raw = f"{default_scheme}://{raw}"
    parsed = urlsplit(raw)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Target URL must use http or https")
    if parsed.username or parsed.password:
        raise ValueError("Target URL must not contain user information")
    host = parsed.hostname
    if not host or "%" in host:
        raise ValueError("Target URL contains an invalid host")
    host = host.lower().rstrip(".")
    try:
        ip = ipaddress.ip_address(host)
        normalized_host = f"[{ip.compressed}]" if ip.version == 6 else ip.compressed
    except ValueError:
        try:
            ascii_host = host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("Target URL contains an invalid host") from exc
        if len(ascii_host) > 253 or any(not _HOST_LABEL.fullmatch(label) for label in ascii_host.split(".")):
            raise ValueError("Target URL contains an invalid host")
        normalized_host = ascii_host
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Target URL contains an invalid port") from exc
    netloc = normalized_host if port is None else f"{normalized_host}:{port}"
    return urlunsplit((
        parsed.scheme.lower(),
        netloc,
        parsed.path or "",
        parsed.query,
        "",
    ))


def _target_host(value: str) -> str:
    return (urlsplit(normalize_target_url(value)).hostname or "").lower().rstrip(".")


def resolve_target_ips(value: str) -> list[str]:
    """Resolve all target addresses. Resolution failures are denied by callers."""

    normalized = normalize_target_url(value)
    parsed = urlsplit(normalized)
    host = parsed.hostname or ""
    try:
        return [ipaddress.ip_address(host).compressed]
    except ValueError:
        pass
    try:
        records = socket.getaddrinfo(
            host,
            parsed.port or (443 if parsed.scheme == "https" else 80),
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise ValueError(f"Target host could not be resolved: {host}") from exc
    addresses = []
    for record in records:
        address = ipaddress.ip_address(record[4][0]).compressed
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise ValueError(f"Target host could not be resolved: {host}")
    return addresses


def is_private_or_reserved_ip(value: str) -> bool:
    """Return True for every non-global address, including private/reserved ranges."""

    try:
        address = ipaddress.ip_address(value)
        return bool(
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
            or not address.is_global
        )
    except ValueError:
        return True


def _domain_matches(host: str, pattern: str) -> bool:
    normalized = str(pattern or "").strip().lower().rstrip(".")
    if not normalized:
        return False
    suffix = normalized.lstrip("*.")
    return host == suffix or (normalized.startswith("*.") and host.endswith("." + suffix))


def _address_in_declared_scope(address: str, roe) -> bool:
    try:
        target_ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    for item in list(getattr(roe, "allowed_ips", []) or []):
        try:
            if target_ip == ipaddress.ip_address(item):
                return True
        except ValueError:
            continue
    for item in list(getattr(roe, "allowed_cidrs", []) or []):
        try:
            if target_ip in ipaddress.ip_network(item, strict=False):
                return True
        except ValueError:
            continue
    return False


def _lab_target_matches(host: str, addresses: Iterable[str], roe) -> bool:
    for declared in list(getattr(roe, "lab_targets", []) or []):
        raw = str(declared or "").strip()
        if not raw:
            continue
        try:
            if any(ipaddress.ip_address(address) in ipaddress.ip_network(raw, strict=False) for address in addresses):
                return True
            continue
        except ValueError:
            pass
        try:
            declared_host = _target_host(raw)
        except ValueError:
            declared_host = raw.lower().rstrip(".")
        if host == declared_host or host.endswith("." + declared_host):
            return True
    return False


def is_target_allowed_by_roe(
    target: str,
    roe=None,
    profile: str = "recon",
    resolved_ips: Iterable[str] | None = None,
) -> bool:
    """Check the target against server-loaded RoE scope and lab restrictions."""

    host = _target_host(target)
    addresses = list(resolved_ips or [])
    is_internal = (
        host == "localhost"
        or host.endswith(_LOCAL_HOST_SUFFIXES)
        or any(is_private_or_reserved_ip(address) for address in addresses)
    )
    if is_internal:
        return bool(
            roe
            and str(profile or "").lower() == "lab"
            and _lab_target_matches(host, addresses, roe)
            and (
                any(_address_in_declared_scope(address, roe) for address in addresses)
                or any(_domain_matches(host, item) for item in getattr(roe, "allowed_domains", []))
            )
        )
    if roe is None:
        return True
    if any(_domain_matches(host, item) for item in getattr(roe, "forbidden_domains", [])):
        return False
    if any(_domain_matches(host, item) for item in getattr(roe, "allowed_domains", [])):
        return True
    return bool(addresses) and all(_address_in_declared_scope(address, roe) for address in addresses)


def validate_target_or_raise(
    target: str,
    roe=None,
    profile: str = "recon",
    scope: "ScopeValidator | Scope | None" = None,
    *,
    resolve: bool = True,
) -> dict:
    """Validate syntax, DNS results, blocked networks, RoE, and optional scope."""

    normalized = normalize_target_url(target)
    host = urlsplit(normalized).hostname or ""
    addresses = resolve_target_ips(normalized) if resolve else []
    if not resolve:
        try:
            addresses = [ipaddress.ip_address(host).compressed]
        except ValueError:
            addresses = []
    if (
        host == "localhost"
        or host.endswith(_LOCAL_HOST_SUFFIXES)
        or any(is_private_or_reserved_ip(address) for address in addresses)
    ) and not is_target_allowed_by_roe(normalized, roe, profile, addresses):
        raise ValueError("Private, loopback, link-local, multicast, or reserved targets are blocked")
    if roe is not None and not is_target_allowed_by_roe(normalized, roe, profile, addresses):
        raise ValueError("Target is not authorized by the selected Rules of Engagement policy")
    if scope is not None:
        validator = scope if isinstance(scope, ScopeValidator) else ScopeValidator(scope)
        valid, reason = validator._validate_scope_only(normalized)
        if not valid:
            raise ValueError(reason)
    return {"url": normalized, "host": host, "resolved_ips": addresses}


def scope_from_target_and_roe(target: str, roe=None) -> Scope:
    """Build the effective scope from a server-loaded policy or exact target only."""

    host = _target_host(target)
    if roe is not None:
        ip_ranges = list(getattr(roe, "allowed_cidrs", []) or [])
        for value in list(getattr(roe, "allowed_ips", []) or []):
            ip = ipaddress.ip_address(value)
            cidr = f"{ip.compressed}/{'32' if ip.version == 4 else '128'}"
            if cidr not in ip_ranges:
                ip_ranges.append(cidr)
        return Scope(
            domains=list(getattr(roe, "allowed_domains", []) or []),
            ip_ranges=ip_ranges,
            notes=f"Server-managed RoE scope: {getattr(roe, 'name', '')}".strip(),
        )
    try:
        ip = ipaddress.ip_address(host)
        prefix = 32 if ip.version == 4 else 128
        return Scope(ip_ranges=[f"{ip.compressed}/{prefix}"], notes="Server-managed exact-target scope")
    except ValueError:
        return Scope(domains=[host], notes="Server-managed exact-target scope")


class ScopeValidator:
    """Validate every network action against approved scope and blocked networks."""

    def __init__(
        self,
        scope: Scope,
        *,
        roe=None,
        profile: str = "recon",
        enforce_resolution: bool = False,
    ):
        self.scope = scope
        self.roe = roe
        self.profile = str(profile or "recon").lower()
        self.enforce_resolution = enforce_resolution
        self._compiled_domains = [
            (
                d.lower().rstrip(".").lstrip("*."),
                re.compile(r"(^|\.){}$".format(re.escape(d.lower().rstrip(".").lstrip("*.")))),
                d.strip().startswith("*."),
            )
            for d in scope.domains
            if str(d or "").strip()
        ]

    @staticmethod
    def _normalize_domain(domain: str) -> str:
        try:
            return _target_host(domain)
        except ValueError:
            return ""

    def is_domain_in_scope(self, domain: str) -> bool:
        normalized = self._normalize_domain(domain)
        return any(
            normalized == suffix
            or (include_subdomains and pattern.search(normalized))
            for suffix, pattern, include_subdomains in self._compiled_domains
        )

    def is_ip_in_scope(self, ip: str) -> bool:
        try:
            target_ip = ipaddress.ip_address(ip)
            return any(
                target_ip in ipaddress.ip_network(cidr, strict=False)
                for cidr in self.scope.ip_ranges
            )
        except ValueError:
            return False

    def is_url_in_scope(self, url: str) -> bool:
        host = self._normalize_domain(url)
        return self.is_domain_in_scope(host) or self.is_ip_in_scope(host)

    def _validate_scope_only(self, target: str) -> tuple[bool, str]:
        host = self._normalize_domain(target)
        if not host:
            return False, f"Target {target!r} is malformed - action blocked"
        if host in _SAFE_TARGETS or any(host.endswith("." + item) for item in _SAFE_TARGETS):
            return True, ""
        try:
            ipaddress.ip_address(host)
            if self.is_ip_in_scope(host):
                return True, f"IP {host} is within authorized scope"
            return False, f"IP {host} is NOT in authorized scope - action blocked"
        except ValueError:
            pass
        if self.is_domain_in_scope(host):
            return True, f"Domain {host} is within authorized scope"
        return False, f"Target {target} is NOT in authorized scope - action blocked"

    def validate(self, target: str) -> tuple[bool, str]:
        valid, reason = self._validate_scope_only(target)
        if not valid:
            return valid, reason
        try:
            validate_target_or_raise(
                target,
                roe=self.roe,
                profile=self.profile,
                resolve=self.enforce_resolution,
            )
        except ValueError as exc:
            return False, f"{exc} - action blocked"
        return True, reason

    def validate_network_target(self, target: str) -> dict:
        valid, reason = self._validate_scope_only(target)
        if not valid:
            raise ValueError(reason)
        return validate_target_or_raise(
            target,
            roe=self.roe,
            profile=self.profile,
            resolve=True,
        )

    def assert_in_scope(self, target: str) -> bool:
        valid, reason = self.validate(target)
        if not valid:
            raise ValueError(f"[SCOPE VIOLATION] {reason}")
        return True
