import unittest


import tools.attack_graph as ag
from tools.attack_graph import build_attack_graph, generate_kill_chains


class _FailingAI:
    class messages:
        @staticmethod
        def create(**kwargs):
            raise RuntimeError("offline")


class TestAttackGraphToolFixes(unittest.TestCase):
    def test_a0_recon_findings_create_graph_paths(self):
        osint = {
            "technology_stack": ["nginx 1.19.0"],
            "subdomains": [],
            "_misconfigs": [],
        }
        recon = {
            "cve_matches": [],
            "high_findings": [
                {
                    "title": "Outdated nginx",
                    "description": "Legacy nginx version detected",
                    "affected": "nginx 1.19.0",
                    "cvss_score": 7.5,
                }
            ],
            "critical_findings": [],
            "medium_findings": [],
        }

        graph = build_attack_graph("example.com", osint, recon, ct_data=None, js_data=None)
        labels = [n.label for n in graph.nodes.values()]
        self.assertIn("Outdated nginx", labels)
        self.assertTrue(graph.get_critical_paths())

    def test_a1_node_id_collisions_do_not_collapse(self):
        osint = {
            "technology_stack": ["nginx 1.19.0"],
            "subdomains": [{"subdomain": "a.example.com", "ip": "1.2.3.4"}],
            "_misconfigs": [],
        }
        recon = {"cve_matches": []}
        js = {
            "secrets": [
                {"type": "API Key", "value_preview": "aaaa...bbbb", "full_length": 32, "severity": "HIGH"},
                {"type": "API Key", "value_preview": "cccc...dddd", "full_length": 32, "severity": "HIGH"},
            ],
            "internal_hosts": [],
            "cloud_resources": [
                {"type": "CloudFront", "value": "aaaa...bbbb"},
                {"type": "CloudFront", "value": "cccc...dddd"},
            ],
            "endpoints": [],
        }

        graph = build_attack_graph("example.com", osint, recon, ct_data=None, js_data=js)

        secret_nodes = [
            n for n in graph.nodes.values()
            if "Hardcoded API Key in JavaScript" in n.label
        ]
        self.assertEqual(len(secret_nodes), 2)
        self.assertEqual(len({n.id for n in secret_nodes}), 2)

        cloud_nodes = [n for n in graph.nodes.values() if n.label.startswith("CloudFront:")]
        self.assertEqual(len(cloud_nodes), 2)
        self.assertEqual(len({n.id for n in cloud_nodes}), 2)

    def test_a2_fallback_kill_chain_technique_mapping_uses_node_kind(self):
        osint = {"technology_stack": [], "subdomains": [], "_misconfigs": []}
        recon = {"cve_matches": []}
        js = {
            "secrets": [{"type": "AWS Access Key", "value_preview": "AKIA...WXYZ", "full_length": 20, "severity": "CRITICAL"}],
            "internal_hosts": [],
            "cloud_resources": [],
            "endpoints": [],
        }
        graph = build_attack_graph("example.com", osint, recon, ct_data=None, js_data=js)
        chains = generate_kill_chains(graph, _FailingAI(), model="unused")
        self.assertTrue(chains.get("kill_chains"))
        first_chain = chains["kill_chains"][0]
        self.assertTrue(first_chain.get("steps"))
        # Expect js_secret nodes to map to T1552.001
        techniques = {s.get("technique") for s in first_chain["steps"]}
        self.assertIn("T1552.001", techniques)

    def test_a3_technology_stack_normalization_accepts_common_shapes(self):
        shapes = [
            None,
            "nginx 1.19.0",
            ["nginx 1.19.0", "PHP 8.3"],
            {"name": "nginx", "version": "1.19.0"},
            [{"name": "nginx", "version": "1.19.0"}, {"name": "PHP", "version": "8.3"}],
            [{"weird": "x"}],
        ]
        for shape in shapes:
            with self.subTest(shape=type(shape).__name__):
                osint = {"technology_stack": shape, "subdomains": [], "_misconfigs": []}
                graph = build_attack_graph("example.com", osint, {"cve_matches": []}, ct_data=None, js_data=None)
                self.assertIn("target:example.com", graph.nodes)

    def test_a4_version_disclosure_findings_create_graph_nodes(self):
        osint = {
            "technology_stack": [],
            "subdomains": [],
            "_misconfigs": [],
            "_version_disclosure": {
                "findings": [
                    {
                        "path": "/actuator/env",
                        "url": "https://example.com/actuator/env",
                        "risk": "high",
                        "description": "Spring Actuator environment exposure",
                    }
                ]
            },
        }
        graph = build_attack_graph("example.com", osint, {"cve_matches": []}, ct_data=None, js_data=None)
        labels = [node.label for node in graph.nodes.values()]

        self.assertIn("Framework exposure: /actuator/env", labels)

    def test_a5_structured_service_inventory_creates_product_service_nodes(self):
        osint = {"technology_stack": [], "subdomains": [], "_misconfigs": []}
        recon = {
            "cve_matches": [],
            "_service_inventory": [
                {
                    "port": 443,
                    "protocol": "tcp",
                    "service": "https",
                    "product": "Apache httpd",
                    "version": "2.4.49",
                    "candidate_cpes": ["cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"],
                    "confidence": "HIGH",
                }
            ],
        }
        graph = build_attack_graph("example.com", osint, recon, ct_data=None, js_data=None)
        services = [node for node in graph.nodes.values() if node.label.startswith("Service: 443/tcp")]

        self.assertEqual(len(services), 1)
        self.assertEqual(services[0].data["product"], "Apache httpd")
        self.assertEqual(services[0].data["candidate_cpes"], ["cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"])

    def test_a6_tls_findings_create_graph_nodes(self):
        osint = {"technology_stack": [], "subdomains": [], "_misconfigs": []}
        recon = {
            "cve_matches": [],
            "_tls_audit": {
                "findings": [
                    {"title": "TLS 1.0 accepted", "severity": "HIGH", "description": "legacy TLS"}
                ]
            },
        }
        graph = build_attack_graph("example.com", osint, recon, ct_data=None, js_data=None)
        labels = [node.label for node in graph.nodes.values()]

        self.assertIn("TLS 1.0 accepted", labels)

    def test_a7_js_pages_forms_and_endpoints_create_explicit_surface_nodes(self):
        osint = {"technology_stack": [], "subdomains": [], "_misconfigs": []}
        js = {
            "pages_crawled": [{"url": "https://example.com/login", "routes": 2, "forms": 1}],
            "forms": [{"method": "POST", "action": "https://example.com/login", "fields": ["user", "pass"]}],
            "endpoints": ["/api/v1/users", "/search.jsp"],
            "secrets": [],
            "internal_hosts": [],
            "cloud_resources": [],
        }

        graph = build_attack_graph("example.com", osint, {"cve_matches": []}, ct_data=None, js_data=js)

        types = [node.type for node in graph.nodes.values()]
        self.assertIn("route", types)
        self.assertIn("form", types)
        self.assertIn("api_endpoint", types)
        labels = [node.label for node in graph.nodes.values()]
        self.assertIn("Route: /login", labels)
        self.assertIn("API Endpoint: /api/v1/users", labels)
        self.assertIn("API Endpoint: /search.jsp", labels)

    def test_a8_passive_and_internetdb_enrichment_create_nodes(self):
        osint = {
            "technology_stack": [],
            "subdomains": [],
            "_misconfigs": [],
            "_passive_urls": {"discovered_urls": ["https://example.com/robots-only"]},
            "_external_enrichment": {
                "internetdb": {
                    "status": "success",
                    "ip": "203.0.113.10",
                    "ports": [80, 443],
                    "hostnames": ["www.example.com"],
                    "cpes": ["cpe:/a:apache:http_server"],
                    "vulns": ["CVE-2024-0001"],
                }
            },
        }

        graph = build_attack_graph("example.com", osint, {"cve_matches": []}, ct_data=None, js_data=None)

        types = [node.type for node in graph.nodes.values()]
        self.assertIn("passive_url", types)
        self.assertIn("external_enrichment", types)
        self.assertIn("internetdb_vuln", types)
        labels = [node.label for node in graph.nodes.values()]
        self.assertIn("InternetDB vuln: CVE-2024-0001", labels)

    def test_a9_redteam_verifications_and_auth_panels_create_nodes(self):
        osint = {
            "technology_stack": [],
            "subdomains": [],
            "_misconfigs": [],
            "_js_data": {
                "pages_crawled": [{"url": "https://example.com/login", "routes": 1, "forms": 0}],
                "forms": [],
                "endpoints": [],
            },
        }
        redteam = [
            {"test": "open_redirect", "finding": "Open Redirect", "result": {"confirmed": True, "url": "https://example.com/login"}},
            {"test": "auth_panel_discovery", "finding": "Auth", "result": {"panels": [{"path": "/admin", "url": "https://example.com/admin", "status_code": 403}]}},
            {"test": "api_endpoint_discovery", "finding": "API", "result": {"discovered": [{"url": "https://example.com/api", "status_code": 401}]}},
        ]

        graph = build_attack_graph("example.com", osint, {"cve_matches": []}, redteam_results=redteam)

        types = [node.type for node in graph.nodes.values()]
        self.assertIn("verification_result", types)
        self.assertIn("auth_panel", types)
        self.assertIn("api_endpoint", types)

    def test_b0_info_only_surface_generates_review_paths_not_compromise_chain(self):
        osint = {
            "technology_stack": [],
            "subdomains": [],
            "_misconfigs": [],
            "_js_data": {
                "pages_crawled": [{"url": "https://example.com/help", "routes": 0, "forms": 0}],
                "forms": [],
                "endpoints": [],
            },
        }
        graph = build_attack_graph("example.com", osint, {"cve_matches": []})
        chains = generate_kill_chains(graph, _FailingAI(), model="unused")

        rendered = str(chains).lower()
        self.assertIn("review", rendered)
        self.assertNotIn("full compromise achievable", rendered)
        self.assertEqual(chains["overall_chain_risk"], "LOW")

    def test_b1_route_form_api_caps_record_overflow_count(self):
        old_route = ag.ATTACK_GRAPH_MAX_ROUTE_NODES
        old_form = ag.ATTACK_GRAPH_MAX_FORM_NODES
        old_api = ag.ATTACK_GRAPH_MAX_API_NODES
        ag.ATTACK_GRAPH_MAX_ROUTE_NODES = 2
        ag.ATTACK_GRAPH_MAX_FORM_NODES = 1
        ag.ATTACK_GRAPH_MAX_API_NODES = 2
        try:
            js = {
                "pages_crawled": [
                    {"url": f"https://example.com/page-{idx}", "routes": 0, "forms": 0}
                    for idx in range(4)
                ],
                "forms": [
                    {"method": "POST", "action": f"https://example.com/form-{idx}", "fields": []}
                    for idx in range(3)
                ],
                "endpoints": [f"/api/{idx}" for idx in range(5)],
                "secrets": [],
                "internal_hosts": [],
                "cloud_resources": [],
            }
            graph = build_attack_graph(
                "example.com",
                {"technology_stack": [], "subdomains": [], "_misconfigs": []},
                {"cve_matches": []},
                js_data=js,
            )
        finally:
            ag.ATTACK_GRAPH_MAX_ROUTE_NODES = old_route
            ag.ATTACK_GRAPH_MAX_FORM_NODES = old_form
            ag.ATTACK_GRAPH_MAX_API_NODES = old_api

        overflow = graph.nodes[graph.root_id].data["overflow_count"]
        self.assertEqual(overflow["route"], 2)
        self.assertEqual(overflow["form"], 2)
        self.assertEqual(overflow["api_endpoint"], 3)


if __name__ == "__main__":
    unittest.main()
