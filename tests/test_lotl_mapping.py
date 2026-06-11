"""Tests for Living-off-the-Land standards mappings."""

from utils.standards_mapping import map_finding_to_standards


def test_exposed_actuator_maps_to_lotl():
    result = map_finding_to_standards({"title": "Exposed actuator endpoint"})
    assert result["lotl"][0]["technique_id"] == "T1218"


def test_unknown_finding_has_empty_lotl_mapping():
    result = map_finding_to_standards({"title": "Unclassified observation"})
    assert result["lotl"] == []


def test_lotl_key_is_always_present():
    assert "lotl" in map_finding_to_standards({})
