"""Tests for Sigma rule generation."""

from exporters.sigma_exporter import build_sigma_rules


def _finding(title="Exposed actuator endpoint"):
    return {
        "title": title,
        "description": "Spring actuator is reachable.",
        "standards": {"attack": [{"technique_id": "T1190"}]},
    }


def test_exposed_actuator_produces_complete_sigma_rule():
    rules = build_sigma_rules("example.com", {
        "critical_findings": [],
        "high_findings": [_finding()],
        "medium_findings": [],
    })
    assert len(rules) == 1
    assert {
        "title",
        "id",
        "status",
        "description",
        "references",
        "author",
        "date",
        "logsource",
        "detection",
        "falsepositives",
        "level",
        "tags",
    } <= rules[0].keys()
    assert rules[0]["tags"] == ["attack.T1190"]


def test_duplicate_finding_types_produce_one_rule():
    rules = build_sigma_rules("example.com", {
        "critical_findings": [_finding()],
        "high_findings": [_finding("Another actuator exposure")],
        "medium_findings": [],
    })
    assert len(rules) == 1


def test_unknown_finding_types_are_skipped():
    rules = build_sigma_rules("example.com", {
        "critical_findings": [],
        "high_findings": [{"title": "Unclassified observation"}],
        "medium_findings": [],
    })
    assert rules == []
