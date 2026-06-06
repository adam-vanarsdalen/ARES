import unittest
from unittest.mock import patch

import pipeline
import tools.cve_sources as cve_sources
from utils.scope_validator import Scope


async def _fast_sleep(*args, **kwargs):
    return None


def _empty_analysis():
    return {
        "critical_findings": [],
        "high_findings": [],
        "medium_findings": [],
        "attack_vectors": [],
        "scan_summary": "",
        "coverage_gaps": [],
    }


class TestPipelineStabilizationWiring(unittest.IsolatedAsyncioTestCase):
    def _pipeline(self, events):
        return pipeline.ARESPipeline(
            target="example.com",
            scope=Scope(domains=["example.com"]),
            mode="full",
            session={},
            log_fn=lambda tag, msg, color="": events.append((tag, msg)),
            phase_fn=lambda *args, **kwargs: None,
            emit_fn=lambda *args, **kwargs: None,
        )

    async def _run_recon(self, *, nuclei_enabled, nuclei_result=None, cve_result=None):
        events = []
        instance = self._pipeline(events)
        osint_data = {
            "technology_stack": ["nginx 1.25.0"] if cve_result else [],
            "_cpe_strings": ["cpe:2.3:a:nginx:nginx:1.25.0:*:*:*:*:*:*:*"] if cve_result else [],
            "_js_data": {"secrets": []},
            "_js_endpoints_count": 0,
            "misconfig_count": 0,
            "coverage_gaps": [],
        }

        with (
            patch.object(pipeline, "ENABLE_NUCLEI", nuclei_enabled),
            patch.object(
                pipeline,
                "run_nuclei",
                return_value=nuclei_result
                or {"status": "success", "profile": "safe", "findings": []},
            ) as run_nuclei,
            patch.object(
                pipeline,
                "port_scan",
                return_value={"open_ports": [], "detected_tech": [], "service_inventory": []},
            ),
            patch.object(
                pipeline,
                "probe_version_disclosure",
                return_value={
                    "base_url": "https://example.com",
                    "paths": [],
                    "findings": [],
                    "coverage": {},
                },
            ),
            patch.object(
                pipeline,
                "tls_audit",
                return_value={
                    "target": "example.com",
                    "port": 443,
                    "certificate": {},
                    "protocols": {},
                    "selected_cipher": "",
                    "findings": [],
                    "coverage": {},
                },
            ),
            patch.object(
                pipeline,
                "fetch_cve_data",
                return_value=cve_result or {"total": 0, "vulnerabilities": [], "coverage": {}},
            ),
            patch.object(pipeline, "enrich_cves_with_epss", side_effect=lambda items: items),
            patch.object(pipeline, "epss_summary", return_value={}),
            patch.object(pipeline, "map_to_mitre", side_effect=lambda items: items),
            patch.object(pipeline.ARESPipeline, "_ai_vuln_analysis", return_value=_empty_analysis()),
            patch.object(pipeline.asyncio, "sleep", new=_fast_sleep),
        ):
            result = await instance._run_recon(osint_data)

        return result, events, run_nuclei

    async def test_disabled_nuclei_is_not_called_or_logged(self):
        result, events, run_nuclei = await self._run_recon(nuclei_enabled=False)

        run_nuclei.assert_not_called()
        self.assertEqual(
            result["nuclei"],
            {"status": "skipped", "reason": "disabled", "findings": []},
        )
        self.assertFalse(any("nuclei" in message.lower() for _, message in events))

    async def test_enabled_nuclei_preserves_runtime_call(self):
        nuclei_result = {"status": "success", "profile": "safe", "findings": []}
        result, _, run_nuclei = await self._run_recon(
            nuclei_enabled=True,
            nuclei_result=nuclei_result,
        )

        run_nuclei.assert_called_once()
        self.assertEqual(result["nuclei"], nuclei_result)

    async def test_pipeline_accepts_cve_fallback_coverage_shape(self):
        self.assertIs(pipeline.fetch_cve_data, cve_sources.fetch_cve_data)
        cve_result = {
            "total": 1,
            "vulnerabilities": [
                {
                    "id": "CVE-2025-0001",
                    "description": "fallback source result",
                    "cvss_score": 5.0,
                    "severity": "MEDIUM",
                }
            ],
            "coverage": {
                "nvd": "rate_limited",
                "osv": "success",
                "vulners": "skipped",
            },
        }

        result, _, _ = await self._run_recon(
            nuclei_enabled=False,
            cve_result=cve_result,
        )

        self.assertEqual(result["cve_matches"][0]["id"], "CVE-2025-0001")
        self.assertEqual(result["_cve_source_coverage"][0]["coverage"]["osv"], "success")


if __name__ == "__main__":
    unittest.main()
