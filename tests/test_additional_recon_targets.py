import unittest
from unittest.mock import patch

import pipeline
from utils.scope_validator import Scope, ScopeValidator


async def _fast_sleep(*args, **kwargs):
    return None


def _validator():
    return ScopeValidator(Scope(domains=["example.com", "*.example.com"]))


def test_js_endpoints_become_additional_targets():
    osint = {
        "collection_summary": {"http_url": "https://example.com"},
        "_js_data": {"endpoints": ["/api/users"]},
    }

    targets = pipeline.build_additional_recon_targets("example.com", osint, validator=_validator())

    assert targets[0]["url"] == "https://example.com/api/users"
    assert targets[0]["source"] == "js"
    assert targets[0]["priority"] == 0


def test_forms_become_targets_but_keep_post_as_metadata_only():
    osint = {
        "collection_summary": {"http_url": "https://example.com"},
        "_js_data": {"forms": [{"method": "POST", "action": "/login"}]},
    }

    targets = pipeline.build_additional_recon_targets("example.com", osint, validator=_validator())

    assert targets[0]["url"] == "https://example.com/login"
    assert targets[0]["source"] == "form"
    assert targets[0]["method"] == "POST"
    assert "not submitted" in targets[0]["reason"]


def test_passive_sitemap_urls_become_additional_targets():
    osint = {
        "collection_summary": {"http_url": "https://example.com"},
        "_passive_urls": {"discovered_urls": ["https://example.com/docs"]},
    }

    targets = pipeline.build_additional_recon_targets("example.com", osint, validator=_validator())

    assert targets[0]["url"] == "https://example.com/docs"
    assert targets[0]["source"] == "passive_url"


def test_out_of_scope_additional_targets_are_dropped():
    osint = {
        "collection_summary": {"http_url": "https://example.com"},
        "_js_data": {"endpoints": ["https://evil.test/api"]},
        "_passive_urls": {"discovered_urls": ["https://evil.test/admin"]},
    }

    assert pipeline.build_additional_recon_targets("example.com", osint, validator=_validator()) == []


def test_additional_target_cap_is_honored():
    osint = {
        "collection_summary": {"http_url": "https://example.com"},
        "_js_data": {"endpoints": [f"/api/{idx}" for idx in range(10)]},
    }

    targets = pipeline.build_additional_recon_targets("example.com", osint, max_targets=3, validator=_validator())

    assert len(targets) == 3


class TestAdditionalReconPipeline(unittest.IsolatedAsyncioTestCase):
    async def test_cpes_from_additional_targets_merge_into_lookup_set(self):
        events = []

        def log(tag, msg, color=""):
            events.append(("log", tag, msg, color))

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
            "_js_data": {"endpoints": ["/api/status"], "forms": [], "pages_crawled": []},
            "_passive_urls": {"discovered_urls": []},
            "_external_enrichment": {"internetdb": {"hostnames": []}},
            "_ct_subdomains": [],
            "subdomains": [],
            "collection_summary": {"http_url": "https://example.com"},
            "coverage_gaps": [],
        }

        additional_cpe = "cpe:2.3:a:nginx:nginx:1.25.0:*:*:*:*:*:*:*"
        with (
            patch.object(pipeline, "port_scan", return_value={"open_ports": [], "detected_tech": [], "service_inventory": []}),
            patch.object(pipeline, "probe_version_disclosure", return_value={"base_url": "https://example.com", "paths": [], "findings": [], "coverage": {"paths_total": 18, "exposed": 0, "protected": 0, "absent": 18}}),
            patch.object(pipeline, "tls_audit", return_value={"target": "example.com", "port": 443, "certificate": {}, "protocols": {}, "selected_cipher": "", "findings": [], "coverage": {}}),
            patch.object(pipeline, "http_probe", return_value={"status_code": 200, "tech_signals": ["nginx 1.25.0"], "missing_security_headers": [], "cpe_strings": [additional_cpe], "error": ""}) as http_probe,
            patch.object(pipeline, "fetch_cve_data", return_value={"total": 0, "vulnerabilities": []}) as fetch_cve_data,
            patch.object(pipeline, "map_to_mitre", side_effect=lambda items: items),
            patch.object(
                pipeline.ARESPipeline,
                "_ai_vuln_analysis",
                return_value={"critical_findings": [], "high_findings": [], "medium_findings": [], "attack_vectors": [], "scan_summary": "", "coverage_gaps": []},
            ),
            patch.object(pipeline.asyncio, "sleep", new=_fast_sleep),
        ):
            out = await p._run_recon(osint_data)

        http_probe.assert_called_with("https://example.com/api/status", p.validator)
        fetch_cve_data.assert_called_with(additional_cpe)
        assert out["_additional_targets"]["coverage"]["probed"] == 1
        assert out["_additional_targets"]["probes"][0]["cpe_strings"] == [additional_cpe]


if __name__ == "__main__":
    unittest.main()
