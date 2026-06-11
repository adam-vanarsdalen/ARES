from unittest import mock

import pytest

import tools.network_tools as network_tools
from tools.network_tools import probe_version_disclosure
from utils.scope_validator import Scope, ScopeValidator


def _scope():
    return ScopeValidator(Scope(domains=["example.com"]))


def _fake_request_for(responses):
    def fake_request(url, timeout, scope):
        for path, response in responses.items():
            if url.endswith(path):
                return response
        return 404, ""
    return fake_request


def test_actuator_env_200_creates_critical_redacted_finding():
    body = "password=supersecret\naws_access_key_id=AKIAABCDEFGHIJKLMNOP"
    with mock.patch.object(network_tools, "_version_disclosure_request", side_effect=_fake_request_for({
        "/actuator/env": (200, body),
    })):
        out = probe_version_disclosure("https://example.com", _scope())

    finding = next(item for item in out["findings"] if item["path"] == "/actuator/env")
    assert finding["risk"] == "critical"
    assert "supersecret" not in finding["evidence_preview"]
    assert "AKIAABCDEFGHIJKLMNOP" not in finding["evidence_preview"]
    assert "[REDACTED]" in finding["evidence_preview"]


def test_readme_with_version_creates_medium_finding():
    with mock.patch.object(network_tools, "_version_disclosure_request", side_effect=_fake_request_for({
        "/readme.txt": (200, "Example CMS version 1.2.3"),
    })):
        out = probe_version_disclosure("https://example.com", _scope())

    finding = next(item for item in out["findings"] if item["path"] == "/readme.txt")
    assert finding["risk"] == "medium"
    assert finding["description"] == "public version/build disclosure"


def test_actuator_health_401_is_protected_not_vulnerability():
    with mock.patch.object(network_tools, "_version_disclosure_request", side_effect=_fake_request_for({
        "/actuator/health": (401, ""),
    })):
        out = probe_version_disclosure("https://example.com", _scope())

    health = next(item for item in out["paths"] if item["path"] == "/actuator/health")
    assert health["exists"] is True
    assert health["protected"] is True
    assert not any(item["path"] == "/actuator/health" for item in out["findings"])


def test_secret_values_are_redacted_from_previews():
    body = "api_key=abc1234567890 Bearer tokenvalue123456789 ghp_abcdefghijklmnopqrstuvwxyz0123456789"
    with mock.patch.object(network_tools, "_version_disclosure_request", side_effect=_fake_request_for({
        "/version.txt": (200, body),
    })):
        out = probe_version_disclosure("https://example.com", _scope())

    preview = next(item for item in out["paths"] if item["path"] == "/version.txt")["evidence_preview"]
    assert "abc1234567890" not in preview
    assert "tokenvalue123456789" not in preview
    assert "ghp_abcdefghijklmnopqrstuvwxyz0123456789" not in preview


def test_out_of_scope_url_is_blocked_before_requests():
    with mock.patch.object(network_tools, "_version_disclosure_request") as request:
        with pytest.raises(ValueError):
            probe_version_disclosure("https://evil.test", _scope())

    request.assert_not_called()
