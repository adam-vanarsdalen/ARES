from __future__ import annotations

from datetime import datetime, timezone

from exporters.common import all_findings, evidence_refs, manifest_metadata, sanitize_export, stable_id


def build_stix_bundle(target: str, osint_report: dict, vuln_report: dict, redteam_report: dict, run_manifest: dict) -> dict:
    now = datetime.now(timezone.utc).isoformat()
    identity_id = stable_id("identity", "ARES")
    report_id = stable_id("report", f"{target}|{run_manifest.get('run_id', '')}")
    objects = [{
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": now,
        "modified": now,
        "name": "ARES",
        "identity_class": "system",
    }]
    object_refs = []
    for asset in vuln_report.get("asset_inventory", osint_report.get("asset_inventory", [])):
        observed_id = stable_id("observed-data", asset.get("asset_id", asset.get("host", target)))
        objects.append({
            "type": "observed-data",
            "spec_version": "2.1",
            "id": observed_id,
            "created": now,
            "modified": now,
            "first_observed": now,
            "last_observed": now,
            "number_observed": 1,
            "object_refs": [],
            "x_ares_asset": sanitize_export(asset),
        })
        object_refs.append(observed_id)
    for finding in all_findings(vuln_report):
        vulnerability_id = stable_id("vulnerability", finding.get("finding_id", finding.get("title", "")))
        objects.append({
            "type": "vulnerability",
            "spec_version": "2.1",
            "id": vulnerability_id,
            "created": now,
            "modified": now,
            "name": finding.get("title", "ARES finding"),
            "description": finding.get("description", ""),
            "external_references": [{"source_name": "ARES evidence", "external_id": ref} for ref in evidence_refs(finding)],
            "x_ares_lifecycle_state": finding.get("lifecycle_state", "new"),
            "x_ares_reportability_score": finding.get("reportability_score", 0),
        })
        object_refs.append(vulnerability_id)
        for mapping in finding.get("standards", {}).get("attack", []):
            attack_id = stable_id("attack-pattern", mapping.get("technique_id", mapping.get("name", "")))
            if not any(item.get("id") == attack_id for item in objects):
                objects.append({
                    "type": "attack-pattern",
                    "spec_version": "2.1",
                    "id": attack_id,
                    "created": now,
                    "modified": now,
                    "name": mapping.get("name", ""),
                    "external_references": [{"source_name": "mitre-attack", "external_id": mapping.get("technique_id", "")}],
                })
            objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": stable_id("relationship", f"{vulnerability_id}|{attack_id}"),
                "created": now,
                "modified": now,
                "relationship_type": "related-to",
                "source_ref": vulnerability_id,
                "target_ref": attack_id,
            })
            object_refs.append(attack_id)
    objects.append({
        "type": "report",
        "spec_version": "2.1",
        "id": report_id,
        "created": now,
        "modified": now,
        "name": f"ARES assessment: {target}",
        "published": now,
        "report_types": ["vulnerability"],
        "object_refs": list(dict.fromkeys(object_refs)),
        "created_by_ref": identity_id,
        "x_ares_metadata": manifest_metadata(run_manifest),
    })
    return sanitize_export({"type": "bundle", "id": stable_id("bundle", report_id), "objects": objects})
