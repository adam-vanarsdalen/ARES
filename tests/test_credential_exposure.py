"""Tests for privacy-preserving HIBP domain exposure checks."""

import json
import urllib.error
from unittest.mock import patch

from tools.credential_exposure import hibp_domain_lookup


class _Response:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return json.dumps(self.payload).encode()


def test_successful_breach_response_returns_counts(monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "test-key")
    payload = {
        "alice": ["BreachA", "BreachB"],
        "bob": ["BreachA"],
    }
    with patch("urllib.request.urlopen", return_value=_Response(payload)):
        result = hibp_domain_lookup("user@example.com")
    assert result["domain"] == "example.com"
    assert result["breach_count"] == 2
    assert result["breached_aliases"] == 2
    assert result["top_breaches"][0] == "BreachA"


def test_404_returns_not_found(monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "test-key")
    error = urllib.error.HTTPError("url", 404, "not found", {}, None)
    with patch("urllib.request.urlopen", side_effect=error):
        result = hibp_domain_lookup("https://example.com/path")
    assert result["status"] == "not_found"
    assert result["breach_count"] == 0


def test_missing_api_key_is_skipped(monkeypatch):
    monkeypatch.delenv("HIBP_API_KEY", raising=False)
    with patch("urllib.request.urlopen") as urlopen:
        result = hibp_domain_lookup("example.com")
    assert result["status"] == "skipped"
    assert result["error"] == "no_api_key"
    urlopen.assert_not_called()


def test_alias_values_are_never_returned(monkeypatch):
    monkeypatch.setenv("HIBP_API_KEY", "test-key")
    with patch("urllib.request.urlopen", return_value=_Response({"private.alias": ["BreachA"]})):
        result = hibp_domain_lookup("example.com")
    assert "private.alias" not in json.dumps(result)
    assert result["sample_aliases_redacted"] == 1
