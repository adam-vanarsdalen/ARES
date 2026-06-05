import json
import os
import tempfile
from unittest import mock

import pipeline
from tools.network_tools import whois_lookup
from utils.report_generator import generate_report
from utils.scope_validator import Scope, ScopeValidator


class _RunResult:
    def __init__(self, stdout):
        self.stdout = stdout


def test_whois_lookup_extracts_org_registrar_and_contact_emails():
    sample = """
    Domain Name: EXAMPLE.COM
    Registrar: Example Registrar, Inc.
    Registrant Organization: Example Org LLC
    Admin Email: admin@example.com
    Tech Email: tech@example.com
    Registrar Abuse Contact Email: abuse@example-registrar.test
    """
    validator = ScopeValidator(Scope(domains=["example.com"]))

    with mock.patch("subprocess.run", return_value=_RunResult(sample)):
        out = whois_lookup("example.com", validator)

    assert out["org_osint"] == {
        "organization": "Example Org LLC",
        "registrar": "Example Registrar, Inc.",
        "emails": ["admin@example.com", "tech@example.com"],
        "abuse_emails": ["abuse@example-registrar.test"],
        "source": "whois",
    }


def test_public_report_redacts_whois_emails():
    osint = pipeline._ground_osint_report(  # type: ignore[attr-defined]
        target="example.com",
        dns={"resolved_ip": ""},
        whois={
            "fields": {"Registrant Organization": "Example Org LLC", "Registrar": "Example Registrar"},
            "org_osint": {
                "organization": "Example Org LLC",
                "registrar": "Example Registrar",
                "emails": ["admin@example.com", "tech@example.com"],
                "abuse_emails": ["abuse@example-registrar.test"],
                "source": "whois",
            },
        },
        subdomains={"discovered_subdomains": []},
        http={"tech_signals": [], "missing_security_headers": [], "error": ""},
        misconfigs={"findings": [], "budget_exhausted": False, "paths_checked": 0, "paths_total": 33},
        ct_data={"total_unique": 0, "interesting_subdomains": []},
        js_data={"endpoints": [], "secrets": []},
        report={},
    )

    with tempfile.TemporaryDirectory() as td:
        path = generate_report(
            target="example.com",
            osint_report={**osint, "_org_osint": {"emails": ["admin@example.com"]}},
            vuln_report={"critical_findings": [], "high_findings": [], "medium_findings": [], "cve_matches": []},
            redteam_report={"overall_risk": "LOW", "confirmed_vulnerabilities": [], "proof_of_concepts": [], "recommendations": []},
            output_dir=td,
        )
        with open(path) as f:
            md = f.read()
        with open(path.replace(".md", ".json")) as f:
            data = json.load(f)

    assert "admin@example.com" not in md
    assert "tech@example.com" not in md
    assert "abuse@example-registrar.test" not in md
    assert "ad***@example.com" in md
    assert "te***@example.com" in md
    assert "ab***@example-registrar.test" in md
    assert "admin@example.com" not in json.dumps(data)
