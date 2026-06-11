import json
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

import pipeline
from utils.report_generator import generate_report
from utils.roe import parse_roe_policy
from utils.scope_validator import Scope


async def _fast_sleep(*args, **kwargs):
    return None


def _pipeline(mode: str = "full"):
    return pipeline.ARESPipeline(
        target="example.com",
        scope=Scope(domains=["example.com", "*.example.com"]),
        mode=mode,
        session={},
        log_fn=lambda *args, **kwargs: None,
        phase_fn=lambda *args, **kwargs: None,
        emit_fn=lambda *args, **kwargs: None,
    )


class TestModeSemantics(unittest.IsolatedAsyncioTestCase):
    async def test_passive_only_does_not_run_active_http_nmap_or_redteam(self):
        p = _pipeline("passive_only")
        with (
            patch.object(pipeline, "dns_lookup", return_value={"resolved_ip": "93.184.216.34", "records": {}}),
            patch.object(pipeline, "internetdb_lookup", return_value={"status": "success", "ip": "93.184.216.34", "ports": [], "hostnames": [], "vulns": [], "cpes": []}),
            patch.object(pipeline, "whois_lookup", return_value={"fields": {}}),
            patch.object(pipeline, "cert_transparency_recon", return_value={"total_unique": 0, "live_subdomains": [], "interesting_subdomains": [], "live_count": 0}),
            patch.object(pipeline, "subdomain_enumerate") as subdomain_enumerate,
            patch.object(pipeline, "http_probe") as http_probe,
            patch.object(pipeline, "port_scan") as port_scan,
            patch.object(pipeline.ARESPipeline, "_run_redteam", new_callable=AsyncMock) as redteam,
            patch.object(pipeline.asyncio, "sleep", new=_fast_sleep),
        ):
            out = await p.run()

        assert out["osint"]["run_manifest"]["mode"] == "passive_only"
        subdomain_enumerate.assert_not_called()
        http_probe.assert_not_called()
        port_scan.assert_not_called()
        redteam.assert_not_called()

    async def test_light_active_does_not_run_nmap(self):
        p = _pipeline("light_active")
        osint_data = {
            "technology_stack": [],
            "_cpe_strings": [],
            "_asset_inventory": [],
            "_js_data": {"endpoints": [], "forms": [], "pages_crawled": []},
            "_passive_urls": {"discovered_urls": []},
            "_external_enrichment": {"internetdb": {"hostnames": []}},
            "_ct_subdomains": [],
            "subdomains": [],
            "collection_summary": {"http_url": "https://example.com"},
            "coverage_gaps": [],
        }
        with (
            patch.object(pipeline, "port_scan") as port_scan,
            patch.object(pipeline, "probe_version_disclosure", return_value={"base_url": "https://example.com", "paths": [], "findings": [], "coverage": {}}),
            patch.object(pipeline, "tls_audit", return_value={"target": "example.com", "port": 443, "findings": [], "coverage": {}}),
            patch.object(pipeline.ARESPipeline, "_ai_vuln_analysis", return_value={"critical_findings": [], "high_findings": [], "medium_findings": [], "coverage_gaps": []}),
            patch.object(pipeline.asyncio, "sleep", new=_fast_sleep),
        ):
            await p._run_recon(osint_data)

        port_scan.assert_not_called()

    async def test_full_mode_runs_redteam_phase_when_advanced_profile_is_authorized(self):
        p = _pipeline("full")
        p.profile = pipeline.CapabilityProfile.ADVANCED
        p.roe = parse_roe_policy({
            "engagement": {
                "allowed_profiles": ["advanced"],
                "allowed_methods": ["GET", "HEAD", "OPTIONS"],
                "advanced_verification": True,
            }
        })
        osint = {"subdomains": [], "_ct_subdomains": [], "_js_endpoints_count": 0}
        recon = {"critical_findings": [], "high_findings": [], "medium_findings": [], "_epss_summary": {}}
        with (
            patch("utils.roe.ENABLE_ADVANCED_VERIFICATION", True),
            patch("utils.roe.REQUIRE_ROE_FOR_ADVANCED", True),
            patch.object(pipeline.ARESPipeline, "_run_osint", new_callable=AsyncMock, return_value=osint),
            patch.object(pipeline.ARESPipeline, "_run_recon", new_callable=AsyncMock, return_value=recon),
            patch.object(pipeline.ARESPipeline, "_run_redteam", new_callable=AsyncMock, return_value={"overall_risk": "LOW", "kill_chains": []}) as redteam,
            patch.object(pipeline.ARESPipeline, "_finalize", return_value={"ok": True}),
        ):
            await p.run()

        redteam.assert_called_once()


def test_reports_include_run_manifest():
    manifest = {
        "target": "example.com",
        "scope": {"domains": ["example.com"], "ip_ranges": []},
        "mode": "full",
        "started_at": "2026-06-04T00:00:00Z",
        "completed_at": "2026-06-04T00:00:01Z",
        "tools_executed": ["dns_lookup"],
        "caps": {},
        "coverage_gaps": [],
        "external_sources_used": [],
        "safety_flags": ["raw-secrets-not-persisted"],
    }
    with tempfile.TemporaryDirectory() as td:
        path = generate_report(
            "example.com",
            {"summary": "ok", "infrastructure": {}, "subdomains": [], "technology_stack": [], "run_manifest": manifest},
            {"critical_findings": [], "high_findings": [], "medium_findings": [], "cve_matches": []},
            {"overall_risk": "LOW", "confirmed_vulnerabilities": [], "proof_of_concepts": [], "recommendations": []},
            output_dir=td,
            run_manifest=manifest,
        )
        md = open(path).read()
        js = json.load(open(path.replace(".md", ".json")))

    assert "## Run Manifest" in md
    assert js["run_manifest"]["mode"] == "full"
    assert "raw-secrets-not-persisted" in md


def test_invalid_mode_is_rejected_by_pipeline():
    with unittest.TestCase().assertRaises(ValueError):
        _pipeline("unsafe_mode")
