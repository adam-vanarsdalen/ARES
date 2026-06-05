import unittest
from unittest.mock import patch

import pipeline
from utils.scope_validator import Scope, ScopeValidator


async def _fast_sleep(*args, **kwargs):
    return None


def _validator():
    return ScopeValidator(Scope(domains=["target.com", "*.target.com"]))


def test_api_subdomain_gets_higher_priority_than_www():
    inventory = pipeline.build_asset_inventory(
        "target.com",
        dns={"resolved_ip": "203.0.113.10"},
        subdomains={
            "discovered_subdomains": [
                {"subdomain": "www.target.com"},
                {"subdomain": "api.target.com"},
            ]
        },
        ct_data={"live_subdomains": [], "interesting_subdomains": []},
        internetdb={},
        passive_urls={},
        js_data={},
        http_data={"url": "https://target.com", "tech_signals": [], "cpe_strings": []},
        validator=_validator(),
    )
    by_host = {asset["host"]: asset for asset in inventory}

    assert by_host["api.target.com"]["priority"] < by_host["www.target.com"]["priority"]
    assert "priority marker: api" in by_host["api.target.com"]["risk_hints"]


def test_out_of_scope_internetdb_hostname_is_not_probed():
    inventory = pipeline.build_asset_inventory(
        "target.com",
        dns={},
        subdomains={"discovered_subdomains": []},
        ct_data={"live_subdomains": [], "interesting_subdomains": []},
        internetdb={
            "hostnames": ["cdn.third-party.test", "api.target.com"],
            "cpes": ["cpe:2.3:a:nginx:nginx:1.25.0:*:*:*:*:*:*:*"],
        },
        passive_urls={},
        js_data={},
        http_data={"url": "https://target.com", "tech_signals": [], "cpe_strings": []},
        validator=_validator(),
    )
    hosts = {asset["host"] for asset in inventory}
    probe_targets = pipeline.select_inventory_http_probe_targets(inventory)

    assert "cdn.third-party.test" not in hosts
    assert [asset["host"] for asset in probe_targets] == ["api.target.com"]


def test_per_host_tech_stack_is_preserved():
    inventory = pipeline.merge_additional_recon_into_inventory(
        [
            {
                "asset_id": "asset-main",
                "host": "target.com",
                "url": "https://target.com",
                "source": "target",
                "in_scope": True,
                "http_probe": {},
                "tech_stack": ["nginx"],
                "cpe_strings": ["cpe:2.3:a:nginx:nginx:1.25.0:*:*:*:*:*:*:*"],
                "risk_hints": [],
                "priority": 1,
                "notable_findings_count": 0,
            }
        ],
        {
            "targets": [{"url": "https://api.target.com/api/status", "priority": 0, "reason": "API endpoint", "source": "js"}],
            "probes": [
                {
                    "url": "https://api.target.com/api/status",
                    "tech_signals": ["Apache Tomcat"],
                    "cpe_strings": ["cpe:2.3:a:apache:tomcat:10:*:*:*:*:*:*:*"],
                }
            ],
        },
        _validator(),
    )
    by_host = {asset["host"]: asset for asset in inventory}

    assert by_host["target.com"]["tech_stack"] == ["nginx"]
    assert by_host["api.target.com"]["tech_stack"] == ["Apache Tomcat"]


class TestPerAssetRecon(unittest.IsolatedAsyncioTestCase):
    async def test_recon_queries_cpes_per_asset(self):
        events = []

        def log(tag, msg, color=""):
            events.append(("log", tag, msg, color))

        def phase(name, status, detail=""):
            events.append(("phase", name, status, detail))

        def emit(event_type, data):
            events.append((event_type, data))

        p = pipeline.ARESPipeline(
            target="target.com",
            scope=Scope(domains=["target.com", "*.target.com"]),
            mode="full",
            session={},
            log_fn=log,
            phase_fn=phase,
            emit_fn=emit,
        )
        asset_cpe = "cpe:2.3:a:apache:tomcat:10:*:*:*:*:*:*:*"
        osint_data = {
            "technology_stack": [],
            "_cpe_strings": [],
            "_asset_inventory": [
                {
                    "asset_id": "asset-api",
                    "host": "api.target.com",
                    "url": "https://api.target.com",
                    "source": "subdomain",
                    "in_scope": True,
                    "http_probe": {},
                    "tech_stack": ["Apache Tomcat"],
                    "cpe_strings": [asset_cpe],
                    "risk_hints": ["priority marker: api"],
                    "priority": 0,
                    "notable_findings_count": 1,
                }
            ],
            "_js_data": {"endpoints": [], "forms": [], "pages_crawled": []},
            "_passive_urls": {"discovered_urls": []},
            "_external_enrichment": {"internetdb": {"hostnames": []}},
            "_ct_subdomains": [],
            "subdomains": [],
            "collection_summary": {"http_url": "https://target.com"},
            "coverage_gaps": [],
        }

        with (
            patch.object(pipeline, "port_scan", return_value={"open_ports": [], "detected_tech": [], "service_inventory": []}),
            patch.object(pipeline, "probe_version_disclosure", return_value={"base_url": "https://target.com", "paths": [], "findings": [], "coverage": {"paths_total": 18, "exposed": 0, "protected": 0, "absent": 18}}),
            patch.object(pipeline, "tls_audit", return_value={"target": "target.com", "port": 443, "certificate": {}, "protocols": {}, "selected_cipher": "", "findings": [], "coverage": {}}),
            patch.object(pipeline, "fetch_cve_data", return_value={"total": 1, "vulnerabilities": [{"id": "CVE-2099-0001", "description": "test", "cvss_score": 7.5}]}) as fetch_cve_data,
            patch.object(pipeline, "enrich_cves_with_epss", side_effect=lambda cves: cves),
            patch.object(pipeline, "epss_summary", return_value={"p1_immediate": 0}),
            patch.object(pipeline, "map_to_mitre", side_effect=lambda items: items),
            patch.object(
                pipeline.ARESPipeline,
                "_ai_vuln_analysis",
                return_value={"critical_findings": [], "high_findings": [], "medium_findings": [], "attack_vectors": [], "scan_summary": "", "coverage_gaps": []},
            ),
            patch.object(pipeline.asyncio, "sleep", new=_fast_sleep),
        ):
            out = await p._run_recon(osint_data)

        fetch_cve_data.assert_called_with(asset_cpe)
        assert out["per_asset_recon"]["asset-api"]["cve_queries"] == [asset_cpe]
        assert out["per_asset_recon"]["asset-api"]["cve_count"] == 1


if __name__ == "__main__":
    unittest.main()
