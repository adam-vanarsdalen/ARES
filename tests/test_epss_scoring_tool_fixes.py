import json
import unittest
from unittest import mock


import tools.epss_scoring as epss


class _Resp:
    def __init__(self, payload: bytes):
        self._payload = payload

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class TestEPSSScoringToolFixes(unittest.TestCase):
    def test_c1_success_and_missing_entries(self):
        payload = {
            "data": [
                {"cve": "CVE-2024-0001", "epss": "0.12", "percentile": "0.9", "date": "2026-01-01"},
            ]
        }
        with mock.patch("urllib.request.urlopen", return_value=_Resp(json.dumps(payload).encode("utf-8"))):
            res = epss.get_epss_scores(["CVE-2024-0001", "CVE-2024-0002"])

        self.assertIn("CVE-2024-0001", res)
        self.assertIn("CVE-2024-0002", res)
        self.assertAlmostEqual(res["CVE-2024-0001"]["epss"], 0.12)
        self.assertEqual(res["CVE-2024-0002"]["epss"], 0.0)
        self.assertIn("unavailable", res["CVE-2024-0002"]["exploitation_likelihood"].lower())

    def test_c1_http_error_returns_per_cve_entries_and_logs(self):
        with mock.patch("urllib.request.urlopen", side_effect=OSError("nope")):
            with self.assertLogs("tools.epss_scoring", level="ERROR") as logs:
                res = epss.get_epss_scores(["CVE-2024-0001"])
        self.assertEqual(res["CVE-2024-0001"]["epss"], 0.0)
        self.assertIn("fetch failed", res["CVE-2024-0001"]["exploitation_likelihood"].lower())
        self.assertTrue(any("EPSS fetch failed" in m for m in logs.output))

    def test_c1_json_error_returns_per_cve_entries(self):
        with mock.patch("urllib.request.urlopen", return_value=_Resp(b"not json")):
            with self.assertLogs("tools.epss_scoring", level="ERROR"):
                res = epss.get_epss_scores(["CVE-2024-0001"])
        self.assertIn("CVE-2024-0001", res)
        self.assertIn("fetch failed", res["CVE-2024-0001"]["exploitation_likelihood"].lower())


if __name__ == "__main__":
    unittest.main()
