"""
ARES — Scope Validator
Ensures ARES only operates against explicitly authorized targets.
Every tool call passes through here before execution.
"""

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from utils.config import SAFE_TARGETS

_SAFE_TARGETS = {target.lower() for target in SAFE_TARGETS}


@dataclass
class Scope:
    """Defines the authorized attack surface for an engagement."""
    domains: list[str] = field(default_factory=list)
    ip_ranges: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self):
        return {
            "domains": self.domains,
            "ip_ranges": self.ip_ranges,
            "urls": self.urls,
            "notes": self.notes
        }


class ScopeValidator:
    """
    All recon, scanning, and exploitation actions must be validated
    against the defined scope before execution.
    """

    def __init__(self, scope: Scope):
        self.scope = scope
        self._compiled_domains = [
            re.compile(r"(^|\.){}$".format(re.escape(d.lstrip("*."))))
            for d in scope.domains
        ]

    @staticmethod
    def _normalize_domain(domain: str) -> str:
        value = domain.lower().strip()
        if "://" not in value:
            value = f"//{value}"
        parsed = urlsplit(value)
        host = parsed.hostname or domain.lower().strip()
        return host.rstrip(".")

    def is_domain_in_scope(self, domain: str) -> bool:
        domain = self._normalize_domain(domain)
        for pattern in self._compiled_domains:
            if pattern.search(domain):
                return True
        return False

    def is_ip_in_scope(self, ip: str) -> bool:
        try:
            target_ip = ipaddress.ip_address(ip)
            for cidr in self.scope.ip_ranges:
                if target_ip in ipaddress.ip_network(cidr, strict=False):
                    return True
        except ValueError:
            return False
        return False

    def is_url_in_scope(self, url: str) -> bool:
        host = self._normalize_domain(url)
        if self.is_domain_in_scope(host):
            return True
        try:
            return self.is_ip_in_scope(host)
        except ValueError:
            return False

    def validate(self, target: str) -> tuple[bool, str]:
        """Returns (is_valid, reason). Call before ANY action against a target."""
        target = target.strip()
        normalized_target = self._normalize_domain(target)

        if normalized_target in _SAFE_TARGETS or any(
            normalized_target.endswith("." + safe_target)
            for safe_target in _SAFE_TARGETS
        ):
            return True, ""

        # IP address check
        try:
            ipaddress.ip_address(normalized_target)
            if self.is_ip_in_scope(normalized_target):
                return True, f"IP {normalized_target} is within authorized scope"
            return False, f"IP {normalized_target} is NOT in authorized scope — action blocked"
        except ValueError:
            pass

        # URL check
        if target.startswith("http"):
            if self.is_url_in_scope(target):
                return True, f"URL {target} is within authorized scope"
            return False, f"URL {target} is NOT in authorized scope — action blocked"

        # Domain check
        if self.is_domain_in_scope(target):
            return True, f"Domain {target} is within authorized scope"

        return False, f"Target {target} is NOT in authorized scope — action blocked"

    def assert_in_scope(self, target: str) -> bool:
        """Raises ValueError if target is out of scope. Used in all tools."""
        valid, reason = self.validate(target)
        if not valid:
            raise ValueError(f"[SCOPE VIOLATION] {reason}")
        return True
