import unittest


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


if __name__ == "__main__":
    unittest.main()
