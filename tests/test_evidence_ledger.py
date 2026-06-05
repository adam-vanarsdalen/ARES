import json

from utils.evidence_ledger import (
    attach_evidence_to_finding,
    build_pipeline_evidence_ledger,
    create_evidence_record,
    get_evidence_for_finding,
    hash_body,
    redact_evidence_preview,
    serialize_evidence_ledger,
)


def test_evidence_preview_redacts_common_secret_formats():
    raw = "Authorization: Bearer ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ AKIAABCDEFGHIJKLMNOP"
    redacted = redact_evidence_preview(raw)
    assert "ghp_" not in redacted
    assert "AKIAABCDEFGHIJKLMNOP" not in redacted
    assert "[REDACTED]" in redacted


def test_finding_references_evidence_id_and_can_be_queried():
    finding = {"title": "Missing CSP", "affected": "https://example.com"}
    record = create_evidence_record(
        run_id="run-1",
        finding_id="finding-1",
        tool_name="http_probe",
        phase="recon",
        profile="recon",
        url="https://example.com",
        body="CSP absent",
        reproduction_hint="Request the page and inspect response headers.",
    )
    finding["finding_id"] = "finding-1"
    attach_evidence_to_finding(finding, record)
    ledger = serialize_evidence_ledger([record])
    assert record.evidence_id in finding["evidence_refs"]
    assert get_evidence_for_finding(ledger, "finding-1")[0]["evidence_id"] == record.evidence_id


def test_body_hash_changes_when_body_changes():
    assert hash_body("body one") != hash_body("body two")
    assert hash_body("body one") == hash_body("body one")


def test_confirmed_finding_gets_reproduction_steps():
    finding = {"title": "Open redirect", "affected": "https://example.com/login"}
    record = create_evidence_record(
        run_id="run-2",
        tool_name="open_redirect",
        phase="redteam",
        profile="advanced",
        url=finding["affected"],
        status_code=302,
        body="Location: https://example.invalid/",
        reproduction_hint="Repeat with the non-routable marker destination.",
    )
    attach_evidence_to_finding(finding, record)
    assert finding["reproduction_steps"]
    assert any("non-routable" in step for step in finding["reproduction_steps"])


def test_raw_secret_stored_is_always_false():
    record = create_evidence_record(
        run_id="run-3",
        tool_name="js_intelligence",
        phase="osint",
        profile="recon",
        body_preview="token=" + "sk_" + "live_" + "abcdefghijklmnopqrstuvwxyz",
    )
    rendered = json.dumps(record.to_dict())
    assert record.raw_secret_stored is False
    assert "sk_live_" not in rendered


def test_pipeline_ledger_covers_findings_verification_and_lab_simulation():
    recon = {
        "evidence_log": [],
        "critical_findings": [],
        "high_findings": [{
            "title": "Exposed path",
            "description": "HTTP 403 confirms route existence.",
            "affected": "https://example.com/admin",
            "evidence_refs": ["http_probe"],
        }],
        "medium_findings": [],
    }
    redteam = {
        "verification_results": [{
            "test": "exposed_path",
            "finding": "Exposed path",
            "result": {
                "status": "confirmed",
                "url": "https://example.com/admin",
                "status_code": 403,
                "next_best_manual_test": "Review authorization with a test account.",
            },
        }],
        "lab_simulations": [{
            "target": "127.0.0.1",
            "impact_narrative": "Synthetic impact.",
            "safe_reproduction": "Use the local demo.",
        }],
    }
    ledger = build_pipeline_evidence_ledger("run-4", "lab", "127.0.0.1", {}, recon, redteam)
    assert len(ledger) == 3
    assert all(item["raw_secret_stored"] is False for item in ledger)
    assert recon["high_findings"][0]["evidence_refs"][-1].startswith("evidence:")
