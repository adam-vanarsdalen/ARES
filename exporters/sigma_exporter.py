"""Sigma detection rule generation from classified ARES findings."""

from __future__ import annotations

import uuid
from datetime import date
from pathlib import Path

import yaml

from utils.standards_mapping import classify_finding_type


def _attack_technique_id(finding: dict) -> str:
    """Extract the first ATT&CK technique identifier attached to a finding."""
    standards = finding.get("standards", {})
    attack = standards.get("attack", []) if isinstance(standards, dict) else []
    if isinstance(attack, list) and attack and isinstance(attack[0], dict):
        technique_id = str(attack[0].get("technique_id") or "").strip()
        if technique_id:
            return technique_id
    return str(
        finding.get("mitre_technique")
        or finding.get("attack_technique_id")
        or ""
    ).strip()


def _load_templates() -> dict:
    """Load Sigma templates from the repository mappings directory."""
    path = Path(__file__).resolve().parent.parent / "mappings" / "sigma_templates.yaml"
    try:
        with path.open("r", encoding="utf-8") as handle:
            loaded = yaml.safe_load(handle) or {}
        return loaded if isinstance(loaded, dict) else {}
    except (OSError, yaml.YAMLError):
        return {}


def build_sigma_rules(target: str, vuln_report: dict) -> list[dict]:
    """
    Generate one Sigma rule dict per unique mapped finding type.

    Findings without a matching template are skipped, and duplicate finding
    types are intentionally collapsed into a single detection rule.
    """
    del target
    templates = _load_templates()
    rules = []
    seen_types = set()
    for bucket in ("critical_findings", "high_findings", "medium_findings"):
        for finding in vuln_report.get(bucket, []):
            finding_type = classify_finding_type(finding)
            if finding_type in seen_types:
                continue
            template = templates.get(finding_type)
            if not isinstance(template, dict):
                continue
            seen_types.add(finding_type)
            technique_id = _attack_technique_id(finding)
            rules.append({
                "title": str(template.get("title") or finding.get("title") or "ARES Detection Rule"),
                "id": str(uuid.uuid4()),
                "status": "experimental",
                "description": str(template.get("description") or ""),
                "references": [f"ARES finding: {finding.get('title', '')}"],
                "author": "ARES",
                "date": date.today().isoformat(),
                "logsource": {
                    "category": str(template.get("category") or ""),
                    "product": str(template.get("logsource_product") or ""),
                },
                "detection": {
                    "keywords": list(template.get("detection_keywords") or []),
                    "condition": str(template.get("condition") or "keywords"),
                },
                "falsepositives": list(template.get("falsepositives") or []),
                "level": str(template.get("level") or "medium"),
                "tags": [f"attack.{technique_id}"] if technique_id else [],
            })
    return rules
