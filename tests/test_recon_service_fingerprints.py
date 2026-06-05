import unittest
from unittest.mock import patch

import pipeline
from utils.scope_validator import Scope


async def _fast_sleep(*args, **kwargs):
    return None


class TestReconServiceFingerprints(unittest.IsolatedAsyncioTestCase):
    async def test_recon_uses_port_scan_detected_tech_for_cve_lookup(self):
        events = []

        def log(tag, msg, color=""):
            events.append(("log", tag, msg))

        def phase(name, status, detail=""):
            events.append(("phase", name, status, detail))

        def emit(event_type, data):
            events.append((event_type, data))

        p = pipeline.ARESPipeline(
            target="example.com",
            scope=Scope(domains=["example.com", "*.example.com"]),
            mode="full",
            session={},
            log_fn=log,
            phase_fn=phase,
            emit_fn=emit,
        )

        osint_data = {
            "technology_stack": [],
            "_cpe_strings": [],
            "_js_data": {"secrets": []},
            "_js_endpoints_count": 0,
            "misconfig_count": 0,
            "coverage_gaps": [],
        }

        with (
            patch.object(
                pipeline,
                "port_scan",
                return_value={
                    "open_ports": ["80/tcp open http nginx/1.19.0"],
                    "detected_tech": [{"name": "nginx 1.19.0", "version": "1.19.0", "cpe": "nginx:nginx:1.19.0"}],
                    "service_inventory": [
                        {
                            "port": 80,
                            "protocol": "tcp",
                            "service": "http",
                            "product": "nginx",
                            "version": "1.19.0",
                            "extrainfo": "",
                            "tunnel": "",
                            "candidate_cpes": ["cpe:2.3:a:nginx:nginx:1.19.0:*:*:*:*:*:*:*"],
                            "confidence": "HIGH",
                        }
                    ],
                },
            ),
            patch.object(
                pipeline,
                "fetch_cve_data",
                return_value={
                    "total": 1,
                    "vulnerabilities": [
                        {"id": "CVE-2024-0001", "description": "example", "cvss_score": 7.5, "severity": "HIGH"}
                    ],
                },
            ) as fetch_cve_data,
            patch.object(pipeline, "probe_version_disclosure", return_value={"base_url": "https://example.com", "paths": [], "findings": [], "coverage": {"paths_total": 18, "exposed": 0, "protected": 0, "absent": 18}}),
            patch.object(pipeline, "tls_audit", return_value={"target": "example.com", "port": 443, "certificate": {}, "protocols": {}, "selected_cipher": "", "findings": [], "coverage": {}}),
            patch.object(pipeline, "enrich_cves_with_epss", side_effect=lambda items: items),
            patch.object(pipeline, "epss_summary", return_value={}),
            patch.object(pipeline, "map_to_mitre", side_effect=lambda items: items),
            patch.object(
                pipeline.ARESPipeline,
                "_ai_vuln_analysis",
                return_value={
                    "critical_findings": [],
                    "high_findings": [],
                    "medium_findings": [],
                    "attack_vectors": [],
                    "scan_summary": "",
                    "coverage_gaps": [],
                },
            ),
            patch.object(pipeline.asyncio, "sleep", new=_fast_sleep),
        ):
            out = await p._run_recon(osint_data)

        fetch_cve_data.assert_called_with("cpe:2.3:a:nginx:nginx:1.19.0:*:*:*:*:*:*:*")
        self.assertEqual(len(out["cve_matches"]), 1)
        self.assertIn("nginx 1.19.0", osint_data["technology_stack"])
        self.assertEqual(out["_service_inventory"][0]["product"], "nginx")


if __name__ == "__main__":
    unittest.main()
