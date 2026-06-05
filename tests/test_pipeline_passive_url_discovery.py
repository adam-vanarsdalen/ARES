import unittest
from unittest.mock import patch

import pipeline
from utils.scope_validator import Scope


async def _fast_sleep(*args, **kwargs):
    return None


class TestPipelinePassiveUrlDiscovery(unittest.IsolatedAsyncioTestCase):
    def _make_pipeline(self):
        self.events = []

        def log(tag, msg, color=""):
            self.events.append(("log", tag, msg, color))

        def phase(name, status, detail=""):
            self.events.append(("phase", name, status, detail))

        def emit(event_type, data):
            self.events.append((event_type, data))

        return pipeline.ARESPipeline(
            target="example.com",
            scope=Scope(domains=["example.com"]),
            mode="osint_only",
            session={"abort": False},
            log_fn=log,
            phase_fn=phase,
            emit_fn=emit,
        )

    async def test_passive_urls_are_reported_and_fed_to_js_intelligence(self):
        p = self._make_pipeline()
        passive_data = {
            "base_url": "http://example.com",
            "robots": {"status_code": 200, "allow": ["http://example.com/public"], "disallow": ["http://example.com/admin"], "urls": ["http://example.com/public", "http://example.com/admin"]},
            "sitemaps": {"status_code": 200, "urls": ["http://example.com/products"], "child_sitemaps": []},
            "security_txt": {"status_code": 404, "fields": {}},
            "discovered_urls": ["http://example.com/public", "http://example.com/admin", "http://example.com/products"],
            "suggested_dorks": ["site:example.com inurl:admin"],
            "coverage": {"suggested_dorks": {"status": "generated_not_executed", "count": 1}},
        }
        js_calls = {}

        def fake_js(url, scope, max_scripts=8, seed_html="", fallback_urls=None):
            js_calls["fallback_urls"] = fallback_urls or []
            return {
                "endpoints": [],
                "secrets": [],
                "internal_hosts": [],
                "cloud_resources": [],
                "script_count": 0,
                "pages_crawled": [],
                "form_count": 0,
            }

        with (
            patch.object(pipeline, "dns_lookup", return_value={"domain": "example.com", "records": {}, "resolved_ip": "93.184.216.34"}),
            patch.object(pipeline, "internetdb_lookup", return_value={"ip": "93.184.216.34", "ports": [], "hostnames": [], "vulns": [], "cpes": [], "tags": [], "source": "shodan_internetdb", "status": "no_data", "error": ""}),
            patch.object(pipeline, "whois_lookup", return_value={"domain": "example.com", "fields": {}}),
            patch.object(pipeline, "subdomain_enumerate", return_value={"discovered_subdomains": []}),
            patch.object(pipeline, "cert_transparency_recon", return_value={"total_unique": 0, "interesting_subdomains": [], "live_subdomains": [], "live_count": 0}),
            patch.object(pipeline, "http_probe", return_value={"url": "http://example.com", "candidate_urls": ["http://example.com/index.html"], "status_code": 200, "tech_signals": [], "cpe_strings": [], "tech_details": [], "missing_security_headers": [], "security_headers": {}, "error": ""}),
            patch.object(pipeline, "passive_url_discovery", return_value=passive_data),
            patch.object(pipeline, "js_intelligence", side_effect=fake_js),
            patch.object(pipeline, "check_common_misconfigs", return_value={"findings": [], "restricted_findings": [], "budget_exhausted": False, "paths_checked": 0, "paths_total": 33}),
            patch.object(pipeline.client.messages, "create", side_effect=ValueError("llm down")),
            patch.object(pipeline.asyncio, "sleep", new=_fast_sleep),
        ):
            out = await p._run_osint()

        assert out["_passive_urls"] == passive_data
        assert out["_suggested_dorks"] == ["site:example.com inurl:admin"]
        assert out["passive_url_discovery"] == passive_data
        assert "http://example.com/products" in js_calls["fallback_urls"]
        assert any(event[0] == "tool_result" and event[1]["tool"] == "passive_url_discovery" for event in self.events)


if __name__ == "__main__":
    unittest.main()
