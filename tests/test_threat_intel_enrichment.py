"""Tests for CISA KEV and AbuseIPDB passive enrichment."""

import json
from unittest.mock import patch

from tools import external_enrichment as enrichment


class _Response:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return json.dumps(self.payload).encode()


def _reset_kev_cache():
    enrichment._KEV_CACHE = {}
    enrichment._KEV_CACHE_TS = 0.0


def test_kev_lookup_successful_hit():
    _reset_kev_cache()
    payload = {"vulnerabilities": [{
        "cveID": "CVE-2024-0001",
        "vendorProject": "Example",
        "product": "Widget",
        "dateAdded": "2026-01-01",
        "requiredAction": "Apply updates",
    }]}
    with patch("urllib.request.urlopen", return_value=_Response(payload)):
        result = enrichment.kev_lookup("cve-2024-0001")
    assert result["in_kev"] is True
    assert result["status"] == "success"
    assert result["vendor"] == "Example"


def test_kev_lookup_not_found():
    _reset_kev_cache()
    with patch("urllib.request.urlopen", return_value=_Response({"vulnerabilities": []})):
        result = enrichment.kev_lookup("CVE-2024-9999")
    assert result["in_kev"] is False
    assert result["status"] == "not_found"


def test_kev_lookup_network_failure_is_non_fatal():
    _reset_kev_cache()
    with patch("urllib.request.urlopen", side_effect=OSError("offline")):
        result = enrichment.kev_lookup("CVE-2024-0001")
    assert result["status"] == "failed"
    assert result["in_kev"] is False


def test_ip_reputation_without_key_is_skipped(monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    with patch("urllib.request.urlopen") as urlopen:
        result = enrichment.ip_reputation_lookup("203.0.113.10")
    assert result["status"] == "skipped"
    assert result["error"] == "no_api_key"
    urlopen.assert_not_called()
