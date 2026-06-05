"""Evidence-based confidence classification and overclaim reduction."""

from __future__ import annotations


CONFIDENCE_CLASSES = {
    "confirmed",
    "strong_indicator",
    "moderate_indicator",
    "weak_indicator",
    "informational",
    "needs_manual_verification",
    "not_reproduced",
}


def _verification_for(finding: dict, evidence: dict) -> list[dict]:
    title = str(finding.get("title", "")).lower()
    return [
        item for item in evidence.get("verification_results", [])
        if str(item.get("finding", "")).lower() == title
    ]


def explain_confidence(finding: dict) -> str:
    if finding.get("confidence_rationale"):
        return finding["confidence_rationale"]
    confidence_class = finding.get("confidence_class", "needs_manual_verification")
    refs = len(finding.get("evidence_refs", []))
    return f"Classified as {confidence_class} from {refs} linked evidence source(s)."


def downgrade_overclaimed_findings(findings: list[dict], evidence: dict | None = None) -> list[dict]:
    evidence = evidence or {}
    for finding in findings:
        title = str(finding.get("title", "")).lower()
        source = str(finding.get("source", "")).lower()
        refs = finding.get("evidence_refs", [])
        verifications = _verification_for(finding, evidence)
        statuses = {item.get("result", {}).get("status") for item in verifications}

        if "confirmed" in statuses:
            finding["confidence_class"] = "confirmed"
            finding["confidence"] = "HIGH"
            finding["verification_status"] = "confirmed"
            finding["confidence_rationale"] = "A finding-specific non-destructive verification reproduced the condition."
            continue
        if "not_reproduced" in statuses:
            finding["confidence_class"] = "not_reproduced"
            finding["confidence"] = "LOW"
            finding["confidence_rationale"] = "The relevant verification did not reproduce the reported condition."
            continue

        if "cors" in title:
            cors_results = [item.get("result", {}) for item in verifications if item.get("test") == "cors"]
            exploitable = any(
                result.get("origin_reflected")
                and result.get("allow_credentials")
                and (
                    finding.get("sensitive_endpoint")
                    or finding.get("authenticated_context")
                    or result.get("sensitive_endpoint")
                )
                for result in cors_results
            )
            if not exploitable:
                if str(finding.get("severity", "")).upper() in {"CRITICAL", "HIGH"}:
                    finding["severity"] = "MEDIUM"
                    finding["cvss_score"] = min(float(finding.get("cvss_score") or 5.3), 6.5)
                finding["confidence_class"] = "needs_manual_verification"
                finding["confidence"] = "MEDIUM"
                finding["confidence_rationale"] = "High-impact CORS requires origin reflection, credentials, and sensitive/authenticated data context."
                continue

        if "missing security header" in title or "missing security headers" in title:
            if str(finding.get("severity", "")).upper() in {"CRITICAL", "HIGH"} and not finding.get("sensitive_endpoint"):
                finding["severity"] = "MEDIUM"
                finding["cvss_score"] = min(float(finding.get("cvss_score") or 5.0), 5.9)
            finding["confidence_class"] = "moderate_indicator"
            finding["confidence_rationale"] = "Header absence is directly observable, but impact depends on the affected page and attack context."
            continue

        if source == "internetdb" or "internetdb" in [str(ref).lower() for ref in refs]:
            finding["confidence_class"] = "weak_indicator"
            finding["confidence"] = "LOW"
            finding["confirmed"] = False
            if str(finding.get("severity", "")).upper() in {"CRITICAL", "HIGH"}:
                finding["severity"] = "MEDIUM"
            finding["confidence_rationale"] = "InternetDB vulnerability attribution is passive and may be stale until verified on the current asset."
            continue

        status_code = int(finding.get("status_code") or 0)
        if ("api endpoint" in title or source == "api_endpoint_discovery") and status_code in {401, 403}:
            finding["severity"] = "INFO"
            finding["confidence_class"] = "informational"
            finding["confidence_rationale"] = "HTTP 401/403 confirms endpoint surface and access control, not a vulnerability by itself."
            continue

        if "version disclosure" in title or source == "probe_version_disclosure":
            if not finding.get("sensitive_endpoint") and not finding.get("sensitive_body_exposed"):
                if str(finding.get("severity", "")).upper() in {"CRITICAL", "HIGH"}:
                    finding["severity"] = "MEDIUM"
                finding["confidence_class"] = "moderate_indicator"
                finding["confidence_rationale"] = "Version disclosure is confirmed exposure but has limited standalone impact."
                continue

        if len(set(refs)) >= 2:
            finding["confidence_class"] = "strong_indicator"
            finding["confidence"] = "HIGH"
            finding["confidence_rationale"] = "Multiple independent evidence references support the condition."
        elif refs:
            finding["confidence_class"] = "moderate_indicator"
            finding["confidence_rationale"] = "One direct evidence source supports the condition; manual confirmation is still recommended."
        else:
            finding["confidence_class"] = "weak_indicator"
            finding["confidence"] = "LOW"
            finding["confidence_rationale"] = "The finding has no linked reproducible evidence and cannot be treated as confirmed."
    return findings
