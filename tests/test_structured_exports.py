import json

from exporters.csaf_exporter import build_csaf_advisory
from exporters.openvex_exporter import build_openvex
from exporters.oscal_exporter import build_oscal_assessment_results
from exporters.stix_exporter import build_stix_bundle


RAW_SECRET = "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"


def _data():
    finding = {
        "finding_id": "finding:1",
        "title": "CVE-2026-0001 vulnerable service",
        "description": f"Observed issue; token={RAW_SECRET}",
        "severity": "HIGH",
        "lifecycle_state": "confirmed",
        "evidence_refs": ["evidence:1"],
        "reportability_score": 90,
        "standards": {
            "attack": [{"technique_id": "T1190", "name": "Exploit Public-Facing Application"}],
            "nist_800_53": [{"control_id": "SI-2", "name": "Flaw Remediation"}],
        },
    }
    osint = {"asset_inventory": [{"asset_id": "asset:1", "host": "example.com"}]}
    vuln = {
        "asset_inventory": osint["asset_inventory"],
        "critical_findings": [],
        "high_findings": [finding],
        "medium_findings": [],
    }
    redteam = {
        "evidence_ledger": [{
            "evidence_id": "evidence:1",
            "asset_id": "asset:1",
            "body_preview_redacted": "[REDACTED]",
            "raw_secret_stored": False,
        }]
    }
    manifest = {"run_id": "run-1", "audit_chain_head": "abc123"}
    return osint, vuln, redteam, manifest


def test_all_exports_are_json_and_have_expected_top_level_sections():
    osint, vuln, redteam, manifest = _data()
    exports = {
        "stix": build_stix_bundle("example.com", osint, vuln, redteam, manifest),
        "oscal": build_oscal_assessment_results("example.com", osint, vuln, redteam, manifest),
        "openvex": build_openvex("example.com", osint, vuln, redteam, manifest),
        "csaf": build_csaf_advisory("example.com", osint, vuln, redteam, manifest),
    }
    assert exports["stix"]["type"] == "bundle"
    assert "assessment-results" in exports["oscal"]
    assert "statements" in exports["openvex"]
    assert {"document", "product_tree", "vulnerabilities"} <= exports["csaf"].keys()
    for payload in exports.values():
        assert json.loads(json.dumps(payload))


def test_exports_include_evidence_refs_and_no_raw_secret():
    osint, vuln, redteam, manifest = _data()
    payloads = [
        build_stix_bundle("example.com", osint, vuln, redteam, manifest),
        build_oscal_assessment_results("example.com", osint, vuln, redteam, manifest),
        build_openvex("example.com", osint, vuln, redteam, manifest),
        build_csaf_advisory("example.com", osint, vuln, redteam, manifest),
    ]
    combined = json.dumps(payloads)
    assert "evidence:1" in combined
    assert RAW_SECRET not in combined
    assert "abc123" in combined


def test_openvex_status_derives_from_lifecycle():
    osint, vuln, redteam, manifest = _data()
    statuses = {}
    for state in ("confirmed", "false_positive", "fixed", "needs_review"):
        vuln["high_findings"][0]["lifecycle_state"] = state
        statuses[state] = build_openvex("example.com", osint, vuln, redteam, manifest)["statements"][0]["status"]
    assert statuses == {
        "confirmed": "affected",
        "false_positive": "not_affected",
        "fixed": "fixed",
        "needs_review": "under_investigation",
    }
