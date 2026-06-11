"""ATT&CK technique overlap hints for cautious APT attribution reporting."""

from __future__ import annotations

from pathlib import Path

import yaml


def _technique_id(finding: dict) -> str:
    """Extract an ATT&CK technique ID using the required field priority."""
    standards = finding.get("standards", {})
    attack = standards.get("attack", []) if isinstance(standards, dict) else []
    if isinstance(attack, list) and attack and isinstance(attack[0], dict):
        technique_id = str(attack[0].get("technique_id") or "").strip()
        if technique_id:
            return technique_id
    for key in ("mitre_technique", "attack_technique_id"):
        technique_id = str(finding.get(key) or "").strip()
        if technique_id:
            return technique_id
    return ""


def attribute_findings_to_apt_groups(
    findings: list[dict],
    mapping_dir: str | Path | None = None,
) -> dict:
    """
    Map observed ATT&CK techniques to groups that are documented users.

    Results are overlap hints rather than claims of attribution. Confidence is
    low for one matched technique, moderate for two or three, and high for four
    or more.
    """
    root = Path(mapping_dir) if mapping_dir is not None else Path(__file__).resolve().parent.parent / "mappings"
    path = root / "apt_groups_mapping.yaml"
    if not path.is_file():
        return {}
    try:
        with path.open("r", encoding="utf-8") as handle:
            mappings = yaml.safe_load(handle) or {}
    except (OSError, yaml.YAMLError):
        return {}
    if not isinstance(mappings, dict):
        return {}

    technique_ids = {
        technique_id
        for finding in findings
        if isinstance(finding, dict)
        for technique_id in [_technique_id(finding)]
        if technique_id
    }
    groups = {}
    for technique_id in sorted(technique_ids):
        entries = mappings.get(technique_id, [])
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict) or not entry.get("group"):
                continue
            group_name = str(entry["group"])
            result = groups.setdefault(group_name, {
                "group": group_name,
                "also_known_as": str(entry.get("also_known_as") or ""),
                "nation_state": str(entry.get("nation_state") or ""),
                "sector_targets": list(entry.get("sector_targets") or []),
                "matched_techniques": [],
                "technique_count": 0,
                "confidence": "low",
            })
            if technique_id not in result["matched_techniques"]:
                result["matched_techniques"].append(technique_id)

    for result in groups.values():
        result["matched_techniques"].sort()
        count = len(result["matched_techniques"])
        result["technique_count"] = count
        result["confidence"] = "high" if count >= 4 else "moderate" if count >= 2 else "low"
    return groups
