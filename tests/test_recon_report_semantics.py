from pipeline import _ground_redteam_report, _ground_vuln_report
from utils.confidence_matrix import downgrade_overclaimed_findings
from utils.finding_lifecycle import initialize_findings


def test_recon_only_cve_is_candidate_with_grounded_recommendations():
    osint = {
        "technology_stack": ["IIS 8.5"],
        "_missing_security_headers": ["Content-Security-Policy", "X-Frame-Options"],
        "_tls_audit": {
            "target": "example.com",
            "port": 443,
            "protocols": {"TLSv1.0": "error", "TLSv1.2": "error"},
            "findings": [],
            "coverage": {"certificate": "failed", "protocols": "failed"},
        },
        "coverage_gaps": [],
    }
    cves = [{
        "id": "CVE-2014-4078",
        "description": "IIS feature-specific issue",
        "cvss_score": 5.1,
        "severity": "MEDIUM",
        "epss": 0.1044,
    }]
    recon = _ground_vuln_report(
        "example.com",
        osint,
        {"open_ports": ["80/tcp open http"], "service_inventory": []},
        cves,
        {},
    )
    findings = recon["critical_findings"] + recon["high_findings"] + recon["medium_findings"]
    downgrade_overclaimed_findings(findings, {})
    initialize_findings({"recon": recon})
    redteam = _ground_redteam_report(
        "example.com",
        {**recon, "cve_matches": cves},
        [],
        {"kill_chains": []},
        {},
    )

    cve_finding = next(item for item in findings if item["title"] == "CVE-2014-4078")
    assert cve_finding["priority"] == "P3"
    assert cve_finding["confidence_class"] == "needs_manual_verification"
    assert cve_finding["reportability_score"] < 70
    assert "tls_audit_inconclusive" in recon["coverage_gaps"]
    assert redteam["overall_risk"] == "MEDIUM"
    recommendation_text = " ".join(item["recommendation"] for item in redteam["recommendations"])
    assert "Verify whether CVE-2014-4078 applies" in recommendation_text
    assert "Content-Security-Policy" in recommendation_text
    assert "Repeat TLS validation" in recommendation_text
