import unittest
from unittest import mock
import urllib.error

import tools.network_tools as network_tools
from utils.scope_validator import Scope, ScopeValidator


class TestHttpProbeFallback(unittest.TestCase):
    def test_vulnweb_targets_get_extended_timeout_profile(self):
        profile = network_tools._target_timeout_profile("https://testphp.vulnweb.com")  # type: ignore[attr-defined]
        self.assertGreaterEqual(profile["probe_get"], 16.0)
        self.assertGreaterEqual(profile["probe_head"], 6.0)
        self.assertGreaterEqual(profile["probe_curl"], 18.0)
        self.assertGreaterEqual(profile["total_budget"], 40.0)
        self.assertGreaterEqual(profile["misconfig_budget"], 35.0)

    def test_vulnweb_probe_candidates_try_http_first(self):
        candidates = network_tools._build_probe_candidates("https://testphp.vulnweb.com")
        self.assertEqual(candidates[0], "http://testphp.vulnweb.com")

    def test_loopback_probe_candidates_include_common_app_ports(self):
        candidates = network_tools._build_probe_candidates("https://127.0.0.1")
        self.assertIn("http://127.0.0.1:3000", candidates)
        self.assertIn("http://127.0.0.1:8080", candidates)
        self.assertLess(
            candidates.index("http://127.0.0.1:8080"),
            candidates.index("http://127.0.0.1/default.aspx"),
        )

    def test_http_probe_uses_head_fallback_after_get_timeout(self):
        scope = ScopeValidator(Scope(domains=["example.com", "*.example.com"]))

        def fake_do_request(url, timeout=10, method="GET", scope=None):
            if method == "GET":
                raise TimeoutError("timed out")
            return (
                {
                    "Server": "nginx/1.19.0",
                    "X-Frame-Options": "DENY",
                },
                "",
                200,
            )

        with mock.patch.object(network_tools, "_do_request", side_effect=fake_do_request):
            out = network_tools.http_probe("https://example.com", scope)

        self.assertEqual(out["url"], "https://example.com")
        self.assertTrue(out["partial"])
        self.assertIn("timed out", out["error"])
        self.assertIn("nginx 1.19.0", out["tech_signals"])
        self.assertEqual(out["status_code"], 200)
        self.assertEqual(out["probe_method"], "HEAD")

    def test_http_probe_tries_common_entrypoints_when_root_fails(self):
        scope = ScopeValidator(Scope(domains=["example.com", "*.example.com"]))

        def fake_do_request(url, timeout=10, method="GET", scope=None):
            if url.endswith("/index.php") and method == "GET":
                return (
                    {
                        "Server": "Apache/2.4.49",
                        "X-Powered-By": "PHP/5.6.40",
                    },
                    "<html></html>",
                    200,
                )
            raise TimeoutError("timed out")

        with mock.patch.object(network_tools, "_do_request", side_effect=fake_do_request):
            with mock.patch.object(network_tools, "_curl_headers", side_effect=RuntimeError("curl unavailable")):
                with mock.patch.object(network_tools, "_curl_body", side_effect=RuntimeError("curl unavailable")):
                    out = network_tools.http_probe("https://example.com", scope)

        self.assertEqual(out["url"], "https://example.com/index.php")
        self.assertIn("Apache 2.4.49", out["tech_signals"])
        self.assertIn("PHP 5.6.40", out["tech_signals"])
        self.assertTrue(out["partial"])

    def test_http_probe_uses_curl_fallback_after_urllib_failures(self):
        scope = ScopeValidator(Scope(domains=["example.com", "*.example.com"]))

        with mock.patch.object(network_tools, "_do_request", side_effect=TimeoutError("timed out")):
            with mock.patch.object(network_tools, "_curl_headers", return_value=({"Server": "nginx/1.19.0"}, 200, "https://example.com")):
                with mock.patch.object(network_tools, "_curl_body", return_value=("<html></html>", 200, "https://example.com")):
                    out = network_tools.http_probe("https://example.com", scope)

        self.assertEqual(out["probe_transport"], "curl")
        self.assertEqual(out["probe_method"], "GET")
        self.assertEqual(out["status_code"], 200)
        self.assertIn("nginx 1.19.0", out["tech_signals"])

    def test_http_probe_clears_partial_on_recovered_legacy_tls_handshake(self):
        scope = ScopeValidator(Scope(domains=["example.com", "*.example.com"]))
        handshake_error = urllib.error.URLError(
            "SSL: SSLV3_ALERT_HANDSHAKE_FAILURE ssl/tls alert handshake failure"
        )

        with mock.patch.object(network_tools, "_do_request", side_effect=handshake_error):
            with mock.patch.object(
                network_tools,
                "_curl_headers",
                return_value=({"Server": "Apache/2.2.6"}, 200, "https://example.com"),
            ):
                with mock.patch.object(
                    network_tools,
                    "_curl_body",
                    return_value=("<html><body>ok</body></html>", 200, "https://example.com"),
                ):
                    out = network_tools.http_probe("https://example.com", scope)

        self.assertEqual(out["probe_transport"], "curl")
        self.assertEqual(out["probe_method"], "GET")
        self.assertEqual(out["status_code"], 200)
        self.assertFalse(out["partial"])
        self.assertEqual(out["error"], "")

    def test_http_probe_records_blocked_redirect_without_body(self):
        scope = ScopeValidator(Scope(domains=["example.com"]))
        blocked = {
            "source_url": "https://example.com",
            "destination_url": "http://127.0.0.1/private",
            "status_code": 302,
            "body_fetched": False,
            "reason": "blocked",
        }
        response = (
            {"Location": "http://127.0.0.1/private"},
            "",
            302,
            "https://example.com",
            [],
            blocked,
        )
        with mock.patch.object(network_tools, "_do_request", return_value=response):
            out = network_tools.http_probe("https://example.com", scope)
        self.assertEqual(out["blocked_redirect"], blocked)
        self.assertEqual(out["body_preview"], "")

    def test_curl_fallback_does_not_enable_blind_redirects(self):
        source = open(network_tools.__file__, encoding="utf-8").read()
        self.assertNotIn('"curl", "-k", "-sS", "-L"', source)


if __name__ == "__main__":
    unittest.main()
