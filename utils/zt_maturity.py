"""DoD Zero Trust pillar risk scoring for ARES findings."""

from __future__ import annotations

from utils.standards_mapping import classify_finding_type


ZT_PILLARS = [
    "user",
    "device",
    "application_workload",
    "data",
    "network_environment",
    "automation_orchestration",
    "visibility_analytics",
]


def _clamp(value: float) -> int:
    """Clamp and round a score to the inclusive 0-100 range."""
    return max(0, min(100, round(value)))


def _maturity_level(score: int) -> str:
    """Translate an overall Zero Trust risk score into its maturity label."""
    if score <= 25:
        return "target"
    if score <= 50:
        return "advanced"
    if score <= 75:
        return "basic"
    return "traditional"


def compute_zt_maturity(findings: list[dict], assets: list[dict]) -> dict:
    """
    Score findings against the seven DoD Zero Trust pillars.

    Higher values represent worse exposure, matching the executive scorecard's
    existing risk-oriented scoring convention.
    """
    del assets
    scores = {pillar: 0 for pillar in ZT_PILLARS}
    pillar_findings = {pillar: [] for pillar in ZT_PILLARS}
    normalized = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        title = str(finding.get("title") or "Untitled finding")
        text = " ".join([
            title,
            str(finding.get("description") or ""),
            str(finding.get("source") or ""),
        ]).lower()
        normalized.append((finding, title, text, classify_finding_type(finding)))

    def matching(*, types: set[str] | None = None, terms: tuple[str, ...] = (), predicate=None) -> list[str]:
        """Return unique finding titles matching type, text, or custom criteria."""
        titles = []
        for finding, title, text, finding_type in normalized:
            matched = bool(types and finding_type in types)
            matched = matched or bool(terms and any(term in text for term in terms))
            matched = matched or bool(predicate and predicate(finding, finding_type, text))
            if matched and title not in titles:
                titles.append(title)
        return titles

    def add_signal(pillar: str, points: int, titles: list[str]) -> None:
        """Add one scoring signal and record the findings that triggered it."""
        if not titles:
            return
        scores[pillar] += points
        for title in titles:
            if title not in pillar_findings[pillar]:
                pillar_findings[pillar].append(title)

    add_signal("user", 30, matching(terms=("admin panel", "default creds", "auth", "login")))
    add_signal("user", 20, matching(terms=("mfa", "multi-factor", "multifactor")))
    add_signal("device", 25, matching(types={"weak_tls"}))
    add_signal("device", 15, matching(types={"version_disclosure"}))
    add_signal("application_workload", 30, matching(types={"exposed_actuator", "exposed_api_docs"}))
    add_signal("application_workload", 20, matching(types={"cors_misconfiguration"}))
    add_signal("data", 35, matching(types={"exposed_secret"}))
    add_signal("data", 20, matching(types={"exposed_phpinfo"}))
    add_signal(
        "network_environment",
        30,
        matching(predicate=lambda finding, _finding_type, text: "internetdb" in str(finding.get("source", "")).lower() and "port" in text),
    )
    add_signal("network_environment", 20, matching(types={"cors_misconfiguration", "host_header_injection"}))
    add_signal(
        "automation_orchestration",
        25,
        matching(predicate=lambda finding, finding_type, _text: finding_type == "vulnerable_service" and float(finding.get("cvss_score") or 0) >= 7.0),
    )
    add_signal("automation_orchestration", 15, matching(types={"missing_security_headers"}))
    add_signal("visibility_analytics", 20, matching(types={"missing_security_headers"}))
    add_signal("visibility_analytics", 15, matching(types={"version_disclosure"}))

    scores = {pillar: _clamp(score) for pillar, score in scores.items()}
    overall = _clamp(sum(scores.values()) / len(ZT_PILLARS))
    return {
        "pillar_scores": scores,
        "overall_zt_risk": overall,
        "zt_maturity_level": _maturity_level(overall),
        "pillar_findings": pillar_findings,
        "framework_reference": "DoD Zero Trust Strategy FY2027",
    }
