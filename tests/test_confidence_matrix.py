from utils.confidence_matrix import downgrade_overclaimed_findings, explain_confidence


def test_single_missing_header_is_not_critical():
    finding = {
        "title": "Missing Security Headers",
        "severity": "CRITICAL",
        "cvss_score": 9.0,
        "evidence_refs": ["http_probe"],
    }
    downgrade_overclaimed_findings([finding], {})
    assert finding["severity"] == "MEDIUM"
    assert finding["cvss_score"] <= 5.9
    assert finding["confidence_class"] == "moderate_indicator"


def test_cors_requires_reflection_credentials_and_sensitive_context_for_high():
    finding = {
        "title": "CORS misconfiguration",
        "severity": "HIGH",
        "evidence_refs": ["http_probe"],
    }
    evidence = {
        "verification_results": [{
            "test": "cors",
            "finding": "CORS misconfiguration",
            "result": {
                "status": "strongly_indicated",
                "origin_reflected": True,
                "allow_credentials": False,
            },
        }]
    }
    downgrade_overclaimed_findings([finding], evidence)
    assert finding["severity"] == "MEDIUM"
    assert finding["confidence_class"] == "needs_manual_verification"


def test_internetdb_only_cve_is_not_confirmed():
    finding = {
        "title": "InternetDB CVE indicator",
        "severity": "HIGH",
        "source": "internetdb",
        "evidence_refs": ["internetdb"],
        "confirmed": True,
    }
    downgrade_overclaimed_findings([finding], {})
    assert finding["confirmed"] is False
    assert finding["confidence_class"] == "weak_indicator"
    assert finding["severity"] == "MEDIUM"


def test_redteam_verification_confirms_relevant_finding():
    finding = {
        "title": "Open redirect",
        "severity": "MEDIUM",
        "evidence_refs": ["http_probe"],
    }
    evidence = {
        "verification_results": [{
            "test": "open_redirect",
            "finding": "Open redirect",
            "result": {"status": "confirmed"},
        }]
    }
    downgrade_overclaimed_findings([finding], evidence)
    assert finding["confidence_class"] == "confirmed"
    assert finding["confidence"] == "HIGH"
    assert "verification" in explain_confidence(finding).lower()


def test_api_403_is_surface_not_vulnerability():
    finding = {
        "title": "API endpoint existence",
        "severity": "HIGH",
        "source": "api_endpoint_discovery",
        "status_code": 403,
        "evidence_refs": ["api"],
    }
    downgrade_overclaimed_findings([finding], {})
    assert finding["severity"] == "INFO"
    assert finding["confidence_class"] == "informational"
