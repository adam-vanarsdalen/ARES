import os
import tempfile
import unittest

import pipeline
from utils.report_generator import generate_report


class TestReportGenerator(unittest.TestCase):
    def test_grounded_reports_do_not_invent_stack_or_versions(self):
        osint = pipeline._ground_osint_report(  # type: ignore[attr-defined]
            target="example.com",
            dns={"resolved_ip": ""},
            whois={"fields": {}},
            subdomains={"discovered_subdomains": []},
            http={"tech_signals": [], "missing_security_headers": [], "error": "timeout"},
            misconfigs={"findings": [], "budget_exhausted": True, "paths_checked": 1, "paths_total": 33},
            ct_data={"total_unique": 0, "interesting_subdomains": []},
            js_data={"endpoints": [], "secrets": []},
            report={"summary": "invented aws/apache/php"},
        )
        vuln = pipeline._ground_vuln_report(  # type: ignore[attr-defined]
            target="example.com",
            osint={**osint, "_js_data": {"secrets": []}, "_misconfigs": [], "_missing_security_headers": []},
            ports={"open_ports": []},
            cves=[],
            report={"high_findings": [{"title": "Upgrade Apache", "description": "invented"}]},
        )
        red = pipeline._ground_redteam_report(  # type: ignore[attr-defined]
            target="example.com",
            vulns={**vuln, "cve_matches": []},
            test_results=[],
            kill_chain_data={"kill_chains": []},
            report={"recommendations": [{"priority": "HIGH", "recommendation": "Upgrade MySQL 8.0.36"}]},
        )

        self.assertEqual(osint["infrastructure"]["hosting"], "Unknown")
        self.assertEqual(osint["technology_stack"], [])
        self.assertEqual(osint["open_ports"], [])
        self.assertTrue(osint["coverage_gaps"])
        self.assertEqual(vuln["high_findings"], [])
        self.assertTrue(vuln["coverage_gaps"])
        self.assertEqual(red["overall_risk"], "MEDIUM")
        rec_text = " ".join(r["recommendation"] for r in red["recommendations"])
        self.assertNotIn("MySQL", rec_text)
        self.assertNotIn("Apache", rec_text)

    def test_report_generator_sanitizes_filename(self):
        with tempfile.TemporaryDirectory() as td:
            out_dir = os.path.join(td, "reports")
            path = generate_report(
                target="../weird/target\\name",
                osint_report={
                    "summary": "ok",
                    "infrastructure": {},
                    "subdomains": [],
                    "technology_stack": [],
                    "risk_score": 1,
                    "misconfig_count": 0,
                },
                vuln_report={"critical_findings": [], "high_findings": [], "medium_findings": [], "cve_matches": []},
                redteam_report={"overall_risk": "LOW", "confirmed_vulnerabilities": [], "proof_of_concepts": [], "recommendations": []},
                output_dir=out_dir,
            )
            self.assertTrue(os.path.exists(path))
            self.assertTrue(os.path.abspath(path).startswith(os.path.abspath(out_dir) + os.sep))
            self.assertNotIn("..", os.path.basename(path))
            self.assertTrue(os.path.exists(path.replace(".md", ".json")))
            self.assertTrue(os.path.exists(path.replace(".md", ".sarif.json")))
            self.assertTrue(os.path.exists(path.replace(".md", ".cdx.json")))

    def test_report_marks_inconclusive_tls_and_uses_current_brand(self):
        with tempfile.TemporaryDirectory() as td:
            path = generate_report(
                target="example.com",
                osint_report={"summary": "Recon only.", "technology_stack": [], "subdomains": []},
                vuln_report={
                    "critical_findings": [],
                    "high_findings": [],
                    "medium_findings": [],
                    "cve_matches": [],
                    "tls_audit": {
                        "target": "example.com",
                        "port": 443,
                        "protocols": {"TLSv1.2": "error"},
                        "coverage": {"certificate": "failed", "protocols": "failed"},
                    },
                },
                redteam_report={
                    "overall_risk": "UNKNOWN",
                    "confirmed_vulnerabilities": [],
                    "proof_of_concepts": [],
                    "recommendations": [],
                },
                output_dir=td,
            )
            rendered = open(path).read()

        self.assertIn("TLS collection was inconclusive", rendered)
        self.assertIn("Authorized Recon & Evidence System", rendered)
        self.assertNotIn("Autonomous Recon & Exploitation System", rendered)


if __name__ == "__main__":
    unittest.main()
