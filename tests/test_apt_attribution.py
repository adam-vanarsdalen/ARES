"""Tests for ATT&CK-based APT attribution hints."""

from utils.apt_attribution import attribute_findings_to_apt_groups


def test_known_techniques_produce_group_matches():
    findings = [
        {"standards": {"attack": [{"technique_id": "T1566.001"}]}},
        {"mitre_technique": "T1078"},
    ]
    groups = attribute_findings_to_apt_groups(findings)
    assert groups["APT29"]["matched_techniques"] == ["T1078", "T1566.001"]
    assert groups["APT29"]["technique_count"] == 2


def test_findings_without_techniques_return_empty():
    assert attribute_findings_to_apt_groups([{"title": "No mapping"}]) == {}


def test_confidence_levels_follow_match_count():
    low = attribute_findings_to_apt_groups([{"mitre_technique": "T1203"}])
    moderate = attribute_findings_to_apt_groups([
        {"mitre_technique": "T1203"},
        {"mitre_technique": "T1059.003"},
    ])
    high = attribute_findings_to_apt_groups([
        {"mitre_technique": "T1566.001"},
        {"mitre_technique": "T1078"},
        {"mitre_technique": "T1059.001"},
        {"mitre_technique": "T1041"},
    ])
    assert low["APT28"]["confidence"] == "low"
    assert moderate["APT28"]["confidence"] == "moderate"
    assert high["APT29"]["confidence"] == "high"
