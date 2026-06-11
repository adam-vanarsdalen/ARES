import unittest

from utils.roe import parse_roe_policy
from utils.scope_validator import Scope, ScopeValidator


class TestScopeValidator(unittest.TestCase):
    def test_domain_and_subdomain_in_scope(self):
        scope = Scope(domains=["example.com", "*.example.com"])
        v = ScopeValidator(scope)
        self.assertTrue(v.is_domain_in_scope("example.com"))
        self.assertTrue(v.is_domain_in_scope("sub.example.com"))
        self.assertFalse(v.is_domain_in_scope("example.com.evil.com"))

    def test_domain_with_port_normalization(self):
        scope = Scope(domains=["example.com"])
        v = ScopeValidator(scope)
        self.assertTrue(v.is_domain_in_scope("example.com:8080"))

    def test_url_scope_with_port_and_path(self):
        scope = Scope(domains=["example.com", "*.example.com"])
        v = ScopeValidator(scope)
        self.assertTrue(v.is_url_in_scope("https://sub.example.com:8443/path"))
        self.assertFalse(v.is_url_in_scope("https://evil.com/path"))

    def test_ip_range_scope(self):
        scope = Scope(domains=[], ip_ranges=["192.0.2.0/24"])
        v = ScopeValidator(scope)
        ok, _ = v.validate("192.0.2.10")
        bad, _ = v.validate("198.51.100.1")
        self.assertFalse(ok)
        self.assertFalse(bad)

    def test_ip_url_scope_with_port(self):
        roe = parse_roe_policy({"engagement": {
            "allowed_ips": ["127.0.0.1"],
            "allowed_cidrs": ["127.0.0.1/32"],
            "allowed_profiles": ["lab"],
            "lab_targets": ["127.0.0.1"],
        }})
        scope = Scope(domains=[], ip_ranges=["127.0.0.1/32"])
        v = ScopeValidator(scope, roe=roe, profile="lab")
        self.assertTrue(v.is_url_in_scope("http://127.0.0.1:3000"))
        ok, _ = v.validate("http://127.0.0.1:3000")
        self.assertTrue(ok)


if __name__ == "__main__":
    unittest.main()
