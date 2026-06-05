import json
import urllib.error
from unittest import mock

import tools.cve_sources as cve


class _Response:
    def __init__(self, payload):
        self.payload = payload if isinstance(payload, bytes) else json.dumps(payload).encode("utf-8")

    def read(self):
        return self.payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def setup_function():
    cve._NVD_CACHE.clear()
    cve._LAST_NVD_REQUEST = 0.0


def test_nvd_429_returns_structured_error():
    err = urllib.error.HTTPError("https://services.nvd.nist.gov/rest/json/cves/2.0", 429, "Too Many", {}, None)
    with mock.patch("urllib.request.urlopen", side_effect=err):
        out = cve.fetch_nvd_cves("nginx")

    assert out["error"] == "http_429"
    assert out["coverage"]["nvd"] == "rate_limited"
    assert out["vulnerabilities"] == []


def test_nvd_cache_prevents_repeated_request_for_same_query():
    payload = {"totalResults": 0, "vulnerabilities": []}
    with mock.patch("urllib.request.urlopen", return_value=_Response(payload)) as urlopen:
        first = cve.fetch_nvd_cves("nginx")
        second = cve.fetch_nvd_cves("nginx")

    assert first["coverage"]["nvd"] == "success"
    assert second["cache_hit"] is True
    assert urlopen.call_count == 1


def test_osv_response_normalizes_ids_aliases_and_cves():
    payload = {
        "vulns": [
            {
                "id": "GHSA-1234",
                "aliases": ["CVE-2024-0001", "OSV-2024-1"],
                "summary": "bad package",
                "database_specific": {"severity": "HIGH"},
            }
        ]
    }
    with mock.patch("urllib.request.urlopen", return_value=_Response(payload)):
        out = cve.fetch_osv_vulns("django", "PyPI", "1.0")

    vuln = out["vulnerabilities"][0]
    assert vuln["id"] == "GHSA-1234"
    assert vuln["cve_ids"] == ["CVE-2024-0001"]
    assert vuln["source"] == "osv"


def test_fetch_cve_data_dedupes_across_nvd_and_osv():
    with (
        mock.patch.object(cve, "fetch_nvd_cves", return_value={"vulnerabilities": [{"id": "CVE-2024-0001", "description": "nvd", "source": "nvd"}], "total": 1, "coverage": {"nvd": "success"}}),
        mock.patch.object(cve, "fetch_osv_vulns", return_value={"vulnerabilities": [{"id": "GHSA-1", "aliases": ["CVE-2024-0001"], "cve_ids": ["CVE-2024-0001"], "summary": "osv", "source": "osv"}], "total": 1, "coverage": {"osv": "success"}}),
    ):
        out = cve.fetch_cve_data("pypi:django:1.0")

    assert len(out["vulnerabilities"]) == 1
    assert out["coverage"]["nvd"] == "success"
    assert out["coverage"]["osv"] == "success"


def test_vulners_disabled_returns_skipped():
    out = cve.fetch_vulners_lucene("nginx")

    assert out["status"] == "skipped"
    assert out["coverage"]["vulners"] == "skipped"
