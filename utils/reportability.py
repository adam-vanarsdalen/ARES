"""Deterministic reportability scoring and operational priority."""

from __future__ import annotations


def calculate_reportability_score(finding: dict) -> int:
    state = finding.get("lifecycle_state", "new")
    if state in {"false_positive", "duplicate"}:
        return 0
    severity = str(finding.get("severity", "")).upper()
    score = {"CRITICAL": 30, "HIGH": 24, "MEDIUM": 16, "LOW": 8, "INFO": 3}.get(severity, 8)
    confidence = str(finding.get("confidence", "MEDIUM")).upper()
    score += {"HIGH": 18, "MEDIUM": 10, "LOW": 3}.get(confidence, 5)
    if finding.get("evidence_refs"):
        score += min(16, 6 + len(finding["evidence_refs"]) * 2)
    if finding.get("reproduction_steps"):
        score += 10
    if finding.get("in_scope", True):
        score += 8
    score += {"critical": 10, "high": 7, "medium": 4, "low": 1}.get(
        str(finding.get("asset_importance", "medium")).lower(), 4
    )
    cvss = float(finding.get("cvss_score") or 0)
    score += min(10, round(cvss))
    if finding.get("epss", 0) >= 0.1 or finding.get("kev"):
        score += 8
    if finding.get("verification_status") == "confirmed" or finding.get("confirmed"):
        score += 8
    if finding.get("false_positive_risk") == "high":
        score -= 15
    if state == "confirmed":
        score += 8
    elif state in {"accepted_risk", "reported", "fixed", "retest_passed"}:
        score -= 5
    return max(0, min(100, int(score)))


def operational_priority(score: int, lifecycle_state: str = "new") -> str:
    if lifecycle_state in {"false_positive", "duplicate", "fixed", "retest_passed"}:
        return "informational"
    if lifecycle_state == "needs_review" and score < 60:
        return "do_not_report_yet"
    if score >= 80:
        return "patch_now"
    if score >= 55:
        return "investigate_this_week"
    if score >= 30:
        return "monitor"
    return "informational"
