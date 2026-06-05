import threading
import time
import unittest
from unittest import mock


import tools.cert_transparency as ct
from utils.scope_validator import Scope, ScopeValidator


class TestCertTransparencyToolFixes(unittest.TestCase):
    def test_b1_query_logs_on_network_error(self):
        with mock.patch("urllib.request.urlopen", side_effect=OSError("boom")):
            with self.assertLogs("tools.cert_transparency", level="ERROR") as logs:
                res = ct.query_crt_sh("example.com")
        self.assertEqual(res, [])
        self.assertTrue(any("crt.sh query failed" in m for m in logs.output))

    def test_b2_resolve_is_concurrent_and_deterministic_and_cached(self):
        scope = Scope(domains=["example.com", "*.example.com"])
        validator = ScopeValidator(scope)

        ct_results = [{"subdomain": f"s{i}.example.com"} for i in range(12)]
        # Add duplicates to exercise caching.
        ct_results.insert(3, {"subdomain": "s5.example.com"})
        ct_results.insert(7, {"subdomain": "s5.example.com"})

        lock = threading.Lock()
        active = 0
        max_active = 0
        calls = {}

        def fake_gethostbyname(host):
            nonlocal active, max_active
            with lock:
                calls[host] = calls.get(host, 0) + 1
                active += 1
                max_active = max(max_active, active)
            time.sleep(0.02)
            with lock:
                active -= 1
            return "1.2.3.4"

        with mock.patch("tools.cert_transparency.socket.gethostbyname", side_effect=fake_gethostbyname):
            enriched = ct.resolve_ct_subdomains(ct_results, validator)

        # Concurrency: should have had >1 resolver active at least once.
        self.assertGreater(max_active, 1)

        # Determinism: preserve input order (minus any filtered items; none here).
        self.assertEqual([e["subdomain"] for e in enriched], [e["subdomain"] for e in ct_results])

        # Cache: duplicates should not trigger multiple DNS calls for the same hostname.
        self.assertEqual(calls.get("s5.example.com"), 1)

    def test_b2_timeout_marks_dead_and_logs(self):
        scope = Scope(domains=["example.com", "*.example.com"])
        validator = ScopeValidator(scope)
        ct_results = [{"subdomain": "slow.example.com"}]

        def slow_gethostbyname(host):
            time.sleep(0.05)
            return "1.2.3.4"

        with mock.patch("tools.cert_transparency.socket.gethostbyname", side_effect=slow_gethostbyname):
            with mock.patch("tools.cert_transparency._DNS_LOOKUP_TIMEOUT_S", 0.001):
                with self.assertLogs("tools.cert_transparency", level="ERROR") as logs:
                    enriched = ct.resolve_ct_subdomains(ct_results, validator)
        self.assertEqual(len(enriched), 1)
        self.assertFalse(enriched[0]["live"])
        self.assertIsNone(enriched[0]["ip"])
        self.assertTrue(any("timed out" in m.lower() for m in logs.output))


if __name__ == "__main__":
    unittest.main()

