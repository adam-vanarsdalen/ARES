"""Executive scorecard derived from ARES evidence and lifecycle data."""

from __future__ import annotations


def _clamp(value: float) -> int:
    return max(0, min(100, round(value)))


def build_executive_scorecard(osint: dict, recon: dict, redteam: dict, manifest: dict | None = None) -> dict:
    manifest = manifest or {}
    findings = [
        finding
        for bucket in ("critical_findings", "high_findings", "medium_findings")
        for finding in recon.get(bucket, [])
    ]
    active = [
        finding for finding in findings
        if finding.get("lifecycle_state") not in {"false_positive", "duplicate", "fixed", "retest_passed"}
    ]
    confirmed = [finding for finding in active if finding.get("confidence_class") == "confirmed" or finding.get("lifecycle_state") == "confirmed"]
    reportable = sorted(active, key=lambda item: -item.get("reportability_score", 0))
    manual = [
        finding for finding in reportable
        if finding.get("confidence_class") in {"needs_manual_verification", "weak_indicator", "moderate_indicator"}
        or finding.get("lifecycle_state") in {"new", "needs_review"}
    ]
    evidence = redteam.get("evidence_ledger", [])
    assets = recon.get("asset_inventory", osint.get("asset_inventory", []))
    coverage_gaps = list(manifest.get("coverage_gaps", []))

    severity_weight = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10, "LOW": 4, "INFO": 1}
    exposure = _clamp(sum(severity_weight.get(str(item.get("severity", "")).upper(), 5) for item in active))
    if confirmed:
        exposure = _clamp(exposure + min(25, len(confirmed) * 8))

    linked = sum(1 for item in active if item.get("evidence_refs"))
    reproducible = sum(1 for item in active if item.get("reproduction_steps"))
    evidence_quality = _clamp(
        (linked / max(1, len(active))) * 50
        + (reproducible / max(1, len(active))) * 30
        + min(20, len(evidence) * 2)
    )

    exploitability = _clamp(max([
        float(item.get("cvss_score") or 0) * 7
        + (20 if item.get("kev") else 0)
        + min(20, float(item.get("epss") or 0) * 100)
        + (10 if item in confirmed else 0)
        for item in active
    ] or [0]))

    mode = str(manifest.get("mode") or "full")
    expected_tools = {
        "recon_only": {
            "http_probe",
            "port_scan",
            "probe_version_disclosure",
            "tls_audit",
            "cve_lookup",
            "epss_scoring",
        },
        "light_active": {"http_probe", "probe_version_disclosure", "tls_audit"},
        "osint_only": {"dns_lookup", "whois_lookup", "cert_transparency", "http_probe"},
        "passive_only": {"dns_lookup", "whois_lookup", "cert_transparency"},
    }.get(mode, {"dns_lookup", "http_probe", "port_scan", "tls_audit", "cve_lookup"})
    executed_tools = set(manifest.get("tools_executed", []))
    completed = len(expected_tools & executed_tools)
    gap_penalty = min(completed, len(coverage_gaps))
    control_coverage = _clamp(((completed - gap_penalty) / max(1, len(expected_tools))) * 100)
    confirmed_scores = [item.get("reportability_score", 0) for item in confirmed]
    candidate_scores = [
        min(60, item.get("reportability_score", 0))
        for item in active
        if item not in confirmed
    ]
    remediation_urgency = max(confirmed_scores + candidate_scores or [0])
    vdp_reportability = _clamp(sum(item.get("reportability_score", 0) for item in reportable[:5]) / max(1, min(5, len(reportable))))
    roe_loaded = bool((manifest.get("roe") or {}).get("loaded"))
    scope_confidence = _clamp(85 + (10 if roe_loaded else 0) - min(60, len(coverage_gaps) * 10))
    false_positive_risk = _clamp(
        (sum(1 for item in active if item.get("confidence_class") in {"weak_indicator", "needs_manual_verification"}) / max(1, len(active))) * 100
    )

    critical_exploitation = [
        item for item in active
        if item.get("kev") or float(item.get("epss") or 0) >= 0.1 or float(item.get("cvss_score") or 0) >= 9
    ]
    blocked_actions = [
        item for item in manifest.get("capability_audit", [])
        if item.get("allowed") is False
    ]
    remediation_actions = []
    for recommendation in redteam.get("recommendations", []):
        remediation_actions.append(
            recommendation if isinstance(recommendation, str) else recommendation.get("recommendation", "")
        )

    return {
        "metrics": {
            "exposure_score": exposure,
            "evidence_quality_score": evidence_quality,
            "exploitability_score": exploitability,
            "control_coverage_score": control_coverage,
            "remediation_urgency": remediation_urgency,
            "vdp_reportability_score": vdp_reportability,
            "scope_confidence_score": scope_confidence,
            "false_positive_risk": false_positive_risk,
        },
        "top_confirmed_findings": confirmed[:5],
        "top_reportable_findings": reportable[:5],
        "manual_verification_candidates": manual[:5],
        "remediation_actions": remediation_actions[:5],
        "kev_epss_criticals": critical_exploitation[:5],
        "asset_exposure_summary": {
            "assets": len(assets),
            "assets_with_findings": sum(1 for asset in assets if asset.get("notable_findings_count", 0)),
            "active_findings": len(active),
            "confirmed_findings": len(confirmed),
        },
        "coverage_gaps": coverage_gaps,
        "blocked_actions": blocked_actions[:10],
        "safety_flags": manifest.get("safety_flags", []),
        "capability_profile": (manifest.get("profile") or {}).get("profile", "recon"),
        "roe_loaded": roe_loaded,
    }
