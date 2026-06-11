import socket
from unittest import mock

import pytest

from utils.roe import parse_roe_policy
from utils.scope_validator import (
    ScopeValidator,
    is_private_or_reserved_ip,
    normalize_target_url,
    scope_from_target_and_roe,
    validate_target_or_raise,
)


PUBLIC_IP = "93.184.216.34"


def test_public_domain_is_allowed_with_public_dns():
    with mock.patch("utils.scope_validator.resolve_target_ips", return_value=[PUBLIC_IP]):
        result = validate_target_or_raise("https://example.com/path")
    assert result["host"] == "example.com"
    assert result["resolved_ips"] == [PUBLIC_IP]


@pytest.mark.parametrize(
    "target",
    [
        "127.0.0.1",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "::1",
        "fc00::1",
        "fe80::1",
        "224.0.0.1",
        "0.0.0.1",
    ],
)
def test_private_reserved_and_multicast_literals_are_blocked(target):
    with pytest.raises(ValueError, match="blocked"):
        validate_target_or_raise(target)


@pytest.mark.parametrize("target", ["localhost", "api.localhost", "service.local", "host.internal"])
def test_localhost_aliases_are_blocked(target):
    with mock.patch(
        "utils.scope_validator.socket.getaddrinfo",
        return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))],
    ):
        with pytest.raises(ValueError, match="blocked"):
            validate_target_or_raise(target)


def test_dns_resolved_private_address_is_blocked():
    with mock.patch("utils.scope_validator.resolve_target_ips", return_value=["10.10.10.10"]):
        with pytest.raises(ValueError, match="blocked"):
            validate_target_or_raise("public-looking.example")


@pytest.mark.parametrize("target", ["", "http://", "ftp://example.com", "http://user:pass@example.com", "bad host"])
def test_malformed_targets_are_rejected(target):
    with pytest.raises(ValueError):
        normalize_target_url(target)


def test_exact_ip_scope_uses_correct_prefix_lengths():
    ipv4_scope = scope_from_target_and_roe("192.0.2.10")
    ipv6_scope = scope_from_target_and_roe("2001:4860:4860::8888")
    assert ipv4_scope.ip_ranges == ["192.0.2.10/32"]
    assert ipv6_scope.ip_ranges == ["2001:4860:4860::8888/128"]


def test_private_target_requires_lab_profile_and_explicit_lab_roe():
    roe = parse_roe_policy({"engagement": {
        "allowed_ips": ["127.0.0.1"],
        "allowed_cidrs": ["127.0.0.1/32"],
        "allowed_profiles": ["lab"],
        "lab_targets": ["127.0.0.1"],
    }})
    scope = scope_from_target_and_roe("127.0.0.1", roe)
    validator = ScopeValidator(scope, roe=roe, profile="lab", enforce_resolution=True)
    result = validator.validate_network_target("http://127.0.0.1:8080")
    assert result["resolved_ips"] == ["127.0.0.1"]
    with pytest.raises(ValueError):
        validate_target_or_raise("127.0.0.1", roe=roe, profile="advanced", scope=scope)


def test_non_global_documentation_ranges_are_treated_as_reserved():
    assert is_private_or_reserved_ip("192.0.2.1") is True
    assert is_private_or_reserved_ip(PUBLIC_IP) is False
