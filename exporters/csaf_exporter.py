from exporters.common import all_findings, evidence_refs, manifest_metadata, sanitize_export


def build_csaf_advisory(target: str, osint_report: dict, vuln_report: dict, redteam_report: dict, run_manifest: dict) -> dict:
    product_id = f"CSAFPID-ARES-{target}"
    return sanitize_export({
        "document": {
            "category": "csaf_security_advisory",
            "csaf_version": "2.0",
            "title": f"ARES Draft Security Advisory: {target}",
            "publisher": {"category": "discoverer", "name": "ARES", "namespace": "https://ares.local"},
            "tracking": {
                "id": run_manifest.get("run_id", target),
                "status": "draft",
                "version": "1",
                "revision_history": [],
                "initial_release_date": run_manifest.get("started_at", ""),
                "current_release_date": run_manifest.get("completed_at", run_manifest.get("started_at", "")),
            },
            "notes": [
                {"category": "description", "title": "Scope", "text": f"Authorized assessment of {target}."},
                {"category": "other", "title": "ARES metadata", "text": str(manifest_metadata(run_manifest))},
            ],
        },
        "product_tree": {
            "branches": [{
                "category": "product_name",
                "name": target,
                "product": {"name": target, "product_id": product_id},
            }]
        },
        "vulnerabilities": [{
            "title": finding.get("title", ""),
            "cve": finding.get("cve_id") or (finding.get("title") if str(finding.get("title", "")).startswith("CVE-") else None),
            "product_status": {
                "known_affected": [product_id]
                if finding.get("lifecycle_state") in {"confirmed", "reported", "accepted_risk"} else [],
                "under_investigation": [product_id]
                if finding.get("lifecycle_state", "new") in {"new", "needs_review"} else [],
                "known_not_affected": [product_id] if finding.get("lifecycle_state") == "false_positive" else [],
                "fixed": [product_id] if finding.get("lifecycle_state") in {"fixed", "retest_passed"} else [],
            },
            "notes": [{"category": "description", "title": "Evidence", "text": ", ".join(evidence_refs(finding))}],
            "remediations": [{
                "category": "mitigation",
                "details": finding.get("next_best_manual_test") or finding.get("description", "Review and remediate the finding."),
                "product_ids": [product_id],
            }],
        } for finding in all_findings(vuln_report)],
    })
