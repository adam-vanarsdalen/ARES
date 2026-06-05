"""
Structured export helpers for enterprise workflows.

Exports:
- SARIF 2.1.0-like findings feed for triage tooling
- CycloneDX 1.6-like component/vulnerability inventory
"""

from __future__ import annotations

from datetime import datetime, timezone


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sarif_level(severity: str) -> str:
    sev = (severity or "").upper()
    if sev == "CRITICAL":
        return "error"
    if sev == "HIGH":
        return "error"
    if sev == "MEDIUM":
        return "warning"
    return "note"


def build_sarif_report(target: str, vuln_report: dict, redteam_report: dict) -> dict:
    results = []
    rules = {}

    for bucket in ("critical_findings", "high_findings", "medium_findings"):
        for finding in vuln_report.get(bucket, []):
            rule_id = finding.get("mitre_technique") or finding.get("title") or "ARES.FINDING"
            rules.setdefault(rule_id, {
                "id": rule_id,
                "name": finding.get("title", rule_id),
                "shortDescription": {"text": finding.get("title", rule_id)},
                "fullDescription": {"text": finding.get("description", "")},
                "help": {"text": finding.get("description", "")},
            })
            results.append({
                "ruleId": rule_id,
                "level": _sarif_level(finding.get("severity", bucket.replace("_findings", "").upper())),
                "message": {"text": finding.get("description", finding.get("title", "ARES finding"))},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": target},
                    }
                }],
                "properties": {
                    "severity": finding.get("severity"),
                    "priority": finding.get("priority"),
                    "confidence": finding.get("confidence"),
                    "affected": finding.get("affected"),
                    "evidence_refs": finding.get("evidence_refs", []),
                },
            })

    for finding in redteam_report.get("confirmed_vulnerabilities", []):
        rule_id = f"ARES.CONFIRMED.{finding.get('name', 'finding').replace(' ', '_')}"
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": finding.get("name", "Confirmed finding"),
            "shortDescription": {"text": finding.get("name", "Confirmed finding")},
            "fullDescription": {"text": finding.get("evidence", "")},
        })
        results.append({
            "ruleId": rule_id,
            "level": _sarif_level(finding.get("severity", "MEDIUM")),
            "message": {"text": finding.get("evidence", finding.get("name", "Confirmed finding"))},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": target},
                }
            }],
            "properties": {
                "confirmed": True,
                "severity": finding.get("severity"),
                "exploitable": finding.get("exploitable"),
            },
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ARES",
                    "informationUri": "https://github.com/",
                    "rules": list(rules.values()),
                }
            },
            "automationDetails": {"id": f"ARES::{target}"},
            "invocations": [{"executionSuccessful": True, "endTimeUtc": _now_iso()}],
            "results": results,
        }],
    }


def build_cyclonedx_report(target: str, osint_report: dict, vuln_report: dict) -> dict:
    components = []
    seen_components = set()

    for tech in osint_report.get("technology_inventory", []) or []:
        name = tech.get("product") or tech.get("name")
        version = tech.get("version", "")
        key = (name, version)
        if not name or key in seen_components:
            continue
        seen_components.add(key)
        component = {
            "type": "framework",
            "name": name,
            "version": version or None,
            "properties": [
                {"name": "ares:confidence", "value": tech.get("confidence", "MEDIUM")},
            ],
        }
        cpe = tech.get("cpe")
        if cpe:
            component["cpe"] = cpe
        components.append({k: v for k, v in component.items() if v not in (None, [], {})})

    vulnerabilities = []
    for cve in vuln_report.get("cve_matches", []):
        vulnerabilities.append({
            "id": cve.get("id"),
            "ratings": [{
                "severity": str(cve.get("severity", "unknown")).lower(),
                "score": cve.get("cvss_score"),
                "method": "CVSS",
            }],
            "description": cve.get("description", ""),
            "properties": [
                {"name": "ares:epss", "value": str(cve.get("epss", ""))},
                {"name": "ares:priority", "value": cve.get("priority", "")},
            ],
        })

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "timestamp": _now_iso(),
            "component": {
                "type": "application",
                "name": "ARES Assessment Target",
                "version": "1",
                "properties": [{"name": "ares:target", "value": target}],
            },
        },
        "components": components,
        "vulnerabilities": vulnerabilities,
    }
