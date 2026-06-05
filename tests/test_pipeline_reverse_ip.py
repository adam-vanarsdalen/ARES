import unittest
from unittest.mock import patch

import pipeline
from utils.scope_validator import Scope


async def _fast_sleep(*args, **kwargs):
    return None


_EMPTY_PASSIVE = {
    "robots": {"allow": [], "disallow": [], "urls": []},
    "sitemaps": {"urls": [], "child_sitemaps": []},
    "security_txt": {"status_code": 0, "fields": {}},
    "discovered_urls": [],
    "suggested_dorks": [],
    "coverage": {},
}


class TestPipelineReverseIP(unittest.IsolatedAsyncioTestCase):
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

    async def test_reverse_ip_is_skipped_by_default(self):
        p = self._make_pipeline()

        with (
            patch.object(pipeline, "ENABLE_REVERSE_IP", False),
            patch.object(pipeline, "dns_lookup", return_value={"domain": "example.com", "records": {}, "resolved_ip": "93.184.216.34"}),
            patch.object(pipeline, "internetdb_lookup", return_value={"ip": "93.184.216.34", "ports": [], "hostnames": [], "vulns": [], "cpes": [], "tags": [], "source": "shodan_internetdb", "status": "no_data", "error": ""}),
            patch.object(pipeline, "whois_lookup", return_value={"domain": "example.com", "fields": {}, "org_osint": {"organization": "", "registrar": "", "emails": [], "abuse_emails": [], "source": "whois"}}),
            patch.object(pipeline, "reverse_ip_lookup", side_effect=AssertionError("reverse IP should be disabled")),
            patch.object(pipeline, "subdomain_enumerate", return_value={"discovered_subdomains": []}),
            patch.object(pipeline, "cert_transparency_recon", return_value={"total_unique": 0, "interesting_subdomains": [], "live_subdomains": [], "live_count": 0}),
            patch.object(pipeline, "http_probe", return_value={"status_code": 200, "tech_signals": [], "cpe_strings": [], "tech_details": [], "missing_security_headers": [], "security_headers": {}, "error": ""}),
            patch.object(pipeline, "passive_url_discovery", return_value=_EMPTY_PASSIVE),
            patch.object(pipeline, "js_intelligence", return_value={"endpoints": [], "secrets": [], "internal_hosts": [], "cloud_resources": [], "script_count": 0}),
            patch.object(pipeline, "check_common_misconfigs", return_value={"findings": [], "restricted_findings": [], "budget_exhausted": False, "paths_checked": 0, "paths_total": 33}),
            patch.object(pipeline.client.messages, "create", side_effect=ValueError("llm down")),
            patch.object(pipeline.asyncio, "sleep", new=_fast_sleep),
        ):
            out = await p._run_osint()

        assert out["_external_enrichment"]["reverse_ip"]["status"] == "skipped"

    async def test_reverse_ip_hostnames_do_not_expand_active_scope(self):
        p = self._make_pipeline()
        reverse_ip = {
            "query": "93.184.216.34",
            "hostnames": ["shared-host.other.test"],
            "ownership_unverified": True,
            "source": "hackertarget_reverse_ip",
            "status": "success",
            "error": "",
        }

        with (
            patch.object(pipeline, "ENABLE_REVERSE_IP", True),
            patch.object(pipeline, "dns_lookup", return_value={"domain": "example.com", "records": {}, "resolved_ip": "93.184.216.34"}),
            patch.object(pipeline, "internetdb_lookup", return_value={"ip": "93.184.216.34", "ports": [], "hostnames": [], "vulns": [], "cpes": [], "tags": [], "source": "shodan_internetdb", "status": "no_data", "error": ""}),
            patch.object(pipeline, "whois_lookup", return_value={"domain": "example.com", "fields": {}, "org_osint": {"organization": "", "registrar": "", "emails": [], "abuse_emails": [], "source": "whois"}}),
            patch.object(pipeline, "reverse_ip_lookup", return_value=reverse_ip),
            patch.object(pipeline, "subdomain_enumerate", return_value={"discovered_subdomains": []}),
            patch.object(pipeline, "cert_transparency_recon", return_value={"total_unique": 0, "interesting_subdomains": [], "live_subdomains": [], "live_count": 0}),
            patch.object(pipeline, "http_probe", return_value={"status_code": 200, "tech_signals": [], "cpe_strings": [], "tech_details": [], "missing_security_headers": [], "security_headers": {}, "error": ""}),
            patch.object(pipeline, "passive_url_discovery", return_value=_EMPTY_PASSIVE),
            patch.object(pipeline, "js_intelligence", return_value={"endpoints": [], "secrets": [], "internal_hosts": [], "cloud_resources": [], "script_count": 0}),
            patch.object(pipeline, "check_common_misconfigs", return_value={"findings": [], "restricted_findings": [], "budget_exhausted": False, "paths_checked": 0, "paths_total": 33}),
            patch.object(pipeline.client.messages, "create", side_effect=ValueError("llm down")),
            patch.object(pipeline.asyncio, "sleep", new=_fast_sleep),
        ):
            out = await p._run_osint()

        assert out["_external_enrichment"]["reverse_ip"] == reverse_ip
        assert not p.validator.is_domain_in_scope("shared-host.other.test")
        assert any(event[0] == "tool_result" and event[1]["tool"] == "reverse_ip_lookup" for event in self.events)


if __name__ == "__main__":
    unittest.main()
