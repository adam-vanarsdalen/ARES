"""Finding review state, validation, and persistence-friendly helpers."""

from __future__ import annotations

from utils.reportability import calculate_reportability_score, operational_priority


LIFECYCLE_STATES = {
    "new",
    "needs_review",
    "confirmed",
    "false_positive",
    "duplicate",
    "accepted_risk",
    "reported",
    "fixed",
    "retest_passed",
}


def initialize_finding(finding: dict) -> dict:
    finding.setdefault("lifecycle_state", "new")
    finding.setdefault("analyst_notes", "")
    finding.setdefault("evidence_refs", [])
    finding.setdefault("confidence", "MEDIUM")
    finding.setdefault("duplicate_of", "")
    finding.setdefault("false_positive_reason", "")
    finding.setdefault("accepted_risk_reason", "")
    finding.setdefault("next_best_manual_test", "")
    score = calculate_reportability_score(finding)
    finding["reportability_score"] = score
    finding["operational_priority"] = operational_priority(score, finding["lifecycle_state"])
    return finding


def review_finding(finding: dict, updates: dict) -> dict:
    state = str(updates.get("lifecycle_state", finding.get("lifecycle_state", "new")))
    if state not in LIFECYCLE_STATES:
        raise ValueError(f"Invalid lifecycle state: {state}")
    allowed_fields = {
        "lifecycle_state",
        "analyst_notes",
        "duplicate_of",
        "false_positive_reason",
        "accepted_risk_reason",
        "next_best_manual_test",
    }
    for key in allowed_fields:
        if key in updates:
            finding[key] = str(updates[key] or "")
    if state == "false_positive" and not finding.get("false_positive_reason"):
        raise ValueError("false_positive_reason is required")
    if state == "duplicate" and not finding.get("duplicate_of"):
        raise ValueError("duplicate_of is required")
    if state == "accepted_risk" and not finding.get("accepted_risk_reason"):
        raise ValueError("accepted_risk_reason is required")
    return initialize_finding(finding)


def initialize_findings(results: dict) -> list[dict]:
    findings = []
    recon = results.get("recon", results)
    for key in ("critical_findings", "high_findings", "medium_findings"):
        for finding in recon.get(key, []):
            initialize_finding(finding)
            findings.append(finding)
    return findings


def find_finding(results: dict, finding_id: str) -> dict | None:
    for finding in initialize_findings(results):
        if finding.get("finding_id") == finding_id:
            return finding
    return None
