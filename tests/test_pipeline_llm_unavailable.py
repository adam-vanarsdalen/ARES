import unittest
from unittest.mock import patch

import pipeline
from utils.scope_validator import Scope


async def _fast_sleep(*args, **kwargs):
    return None


class _Graph:
    nodes = ["target"]

    def get_critical_paths(self):
        return []

    def to_dict(self):
        return {"nodes": []}


class TestPipelineLLMUnavailable(unittest.IsolatedAsyncioTestCase):
    def _make_pipeline(self, mode="full"):
        self.events = []

        def log(tag, msg, color=""):
            self.events.append(("log", tag, msg))

        def phase(phase_name, status, detail=""):
            self.events.append(("phase", phase_name, status, detail))

        def emit(event_type, data):
            self.events.append((event_type, data))

        return pipeline.ARESPipeline(
            target="example.com",
            scope=Scope(domains=["example.com", "*.example.com"]),
            mode=mode,
            session={"abort": False},
            log_fn=log,
            phase_fn=phase,
            emit_fn=emit,
        )

    async def test_osint_ai_failure_falls_back_to_grounded_report(self):
        p = self._make_pipeline(mode="osint_only")

        with (
            patch.object(pipeline, "dns_lookup", return_value={"domain": "example.com", "records": {}, "resolved_ip": "93.184.216.34"}),
            patch.object(pipeline, "whois_lookup", return_value={"domain": "example.com", "fields": {"Registrant Organization": "Example Org"}}),
            patch.object(pipeline, "subdomain_enumerate", return_value={"discovered_subdomains": []}),
            patch.object(pipeline, "cert_transparency_recon", return_value={"total_unique": 0, "interesting_subdomains": [], "live_subdomains": [], "live_count": 0}),
            patch.object(pipeline, "http_probe", return_value={"status_code": 200, "tech_signals": [], "cpe_strings": [], "missing_security_headers": ["Content-Security-Policy"], "security_headers": {}, "error": ""}),
            patch.object(pipeline, "js_intelligence", return_value={"endpoints": [], "secrets": [], "internal_hosts": [], "cloud_resources": [], "script_count": 0}),
            patch.object(pipeline, "check_common_misconfigs", return_value={"findings": [], "budget_exhausted": False, "paths_checked": 0, "paths_total": 33}),
            patch.object(pipeline.client.messages, "create", side_effect=ValueError("Ollama call failed: down")),
            patch.object(pipeline, "generate_report", return_value="reports/fake.md"),
            patch.object(pipeline.asyncio, "sleep", new=_fast_sleep),
        ):
            out = await p.run()

        self.assertIn("osint", out)
        self.assertEqual(out["osint"]["infrastructure"]["hosting"], "Unknown")
        self.assertEqual(out["osint"]["technology_stack"], [])
        self.assertEqual(out["osint"]["misconfig_count"], 0)
        self.assertTrue(any(item[:3] == ("log", "WARN", "AI synthesis failed: Ollama call failed: down") for item in self.events))

    async def test_full_pipeline_ai_failures_use_grounded_fallbacks(self):
        p = self._make_pipeline(mode="full")

        with (
            patch.object(pipeline, "dns_lookup", return_value={"domain": "example.com", "records": {}, "resolved_ip": "93.184.216.34"}),
            patch.object(pipeline, "whois_lookup", return_value={"domain": "example.com", "fields": {"Registrant Organization": "Example Org"}}),
            patch.object(pipeline, "subdomain_enumerate", return_value={"discovered_subdomains": []}),
            patch.object(pipeline, "cert_transparency_recon", return_value={"total_unique": 0, "interesting_subdomains": [], "live_subdomains": [], "live_count": 0}),
            patch.object(pipeline, "http_probe", return_value={"status_code": 200, "tech_signals": [], "cpe_strings": [], "missing_security_headers": [], "security_headers": {}, "error": "timeout"}),
            patch.object(pipeline, "js_intelligence", return_value={"endpoints": [], "secrets": [], "internal_hosts": [], "cloud_resources": [], "script_count": 0}),
            patch.object(pipeline, "check_common_misconfigs", return_value={"findings": [], "budget_exhausted": True, "paths_checked": 10, "paths_total": 33}),
            patch.object(pipeline, "port_scan", return_value={"open_ports": [], "error": "nmap unavailable"}),
            patch.object(pipeline, "fetch_cve_data", return_value={"total": 0, "vulnerabilities": []}),
            patch.object(pipeline, "build_attack_graph", return_value=_Graph()),
            patch.object(pipeline, "generate_kill_chains", return_value={"kill_chains": [], "worst_case_scenario": "", "overall_chain_risk": "LOW"}),
            patch.object(pipeline.client.messages, "create", side_effect=ValueError("Ollama call failed: down")),
            patch.object(pipeline, "generate_report", return_value="reports/fake.md"),
            patch.object(pipeline.asyncio, "sleep", new=_fast_sleep),
        ):
            out = await p.run()

        self.assertIn("recon", out)
        self.assertIn("redteam", out)
        self.assertIn("Coverage gaps:", out["recon"]["scan_summary"])
        self.assertEqual(out["redteam"]["overall_risk"], "MEDIUM")
        warn_msgs = [item[2] for item in self.events if item[0] == "log" and item[1] == "WARN"]
        self.assertTrue(any(msg.startswith("AI synthesis failed:") for msg in warn_msgs))
        self.assertTrue(any(msg.startswith("AI vuln analysis failed:") for msg in warn_msgs))
        self.assertTrue(any(msg.startswith("AI red team synthesis failed:") for msg in warn_msgs))


if __name__ == "__main__":
    unittest.main()
