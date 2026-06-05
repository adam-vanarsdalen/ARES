from exporters.common import all_findings, evidence_refs, manifest_metadata, sanitize_export


def _status(state: str) -> str:
    if state in {"fixed", "retest_passed"}:
        return "fixed"
    if state == "false_positive":
        return "not_affected"
    if state in {"confirmed", "accepted_risk", "reported"}:
        return "affected"
    if state in {"new", "needs_review"}:
        return "under_investigation"
    return "unknown"


def build_openvex(target: str, osint_report: dict, vuln_report: dict, redteam_report: dict, run_manifest: dict) -> dict:
    return sanitize_export({
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"https://ares.local/vex/{run_manifest.get('run_id', 'assessment')}",
        "author": "ARES",
        "role": "Automated evidence collector",
        "version": 1,
        "metadata": manifest_metadata(run_manifest),
        "statements": [{
            "vulnerability": {"@id": finding.get("template_id") or finding.get("finding_id") or finding.get("title")},
            "products": [{"@id": f"pkg:generic/ares-target/{target}"}],
            "status": _status(finding.get("lifecycle_state", "new")),
            "status_notes": finding.get("confidence_rationale", ""),
            "justification": "component_not_present" if finding.get("lifecycle_state") == "false_positive" else None,
            "impact_statement": finding.get("description", ""),
            "action_statement": finding.get("operational_priority", "investigate_this_week"),
            "evidence_refs": evidence_refs(finding),
        } for finding in all_findings(vuln_report)],
    })
