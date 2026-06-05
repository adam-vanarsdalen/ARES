from exporters.common import all_findings, evidence_refs, manifest_metadata, sanitize_export


DISCLAIMER = "Human assessor review required; this export is not an authorization or compliance determination."


def build_oscal_assessment_results(target: str, osint_report: dict, vuln_report: dict, redteam_report: dict, run_manifest: dict) -> dict:
    findings = all_findings(vuln_report)
    return sanitize_export({
        "assessment-results": {
            "uuid": run_manifest.get("run_id", target),
            "metadata": {"title": f"ARES Assessment Results: {target}", "remarks": DISCLAIMER, **manifest_metadata(run_manifest)},
            "results": [{
                "uuid": f"result-{run_manifest.get('run_id', 'ares')}",
                "title": "ARES automated evidence collection",
                "observations": [{
                    "uuid": evidence.get("evidence_id"),
                    "description": evidence.get("body_preview_redacted", ""),
                    "methods": ["TEST"],
                    "subjects": [{"subject-uuid": evidence.get("asset_id") or target, "type": "component"}],
                } for evidence in redteam_report.get("evidence_ledger", [])],
                "findings": [{
                    "uuid": finding.get("finding_id", finding.get("title", "")),
                    "title": finding.get("title", ""),
                    "description": finding.get("description", ""),
                    "target": {
                        "type": "objective-id",
                        "target-id": (
                            finding.get("standards", {}).get("nist_800_53", [{}])[0].get("control_id", "unmapped")
                            if finding.get("standards", {}).get("nist_800_53") else "unmapped"
                        ),
                    },
                    "related-observations": [{"observation-uuid": ref} for ref in evidence_refs(finding)],
                    "props": [
                        {"name": "lifecycle_state", "value": finding.get("lifecycle_state", "new")},
                        {"name": "reportability_score", "value": str(finding.get("reportability_score", 0))},
                    ],
                } for finding in findings],
                "risks": [{
                    "uuid": f"risk-{finding.get('finding_id', index)}",
                    "title": finding.get("title", ""),
                    "description": finding.get("description", ""),
                    "status": "open" if finding.get("lifecycle_state") not in {"fixed", "retest_passed"} else "closed",
                } for index, finding in enumerate(findings)],
            }],
        }
    })
