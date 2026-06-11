"""Tests for D3FEND countermeasure mappings."""

from utils.standards_mapping import map_finding_to_standards


def test_exposed_actuator_maps_to_d3fend():
    result = map_finding_to_standards({"title": "Exposed actuator endpoint"})
    assert result["d3fend"][0]["technique_id"] == "D3-NTF"


def test_d3fend_key_is_always_present():
    assert "d3fend" in map_finding_to_standards({})


def test_unknown_finding_has_empty_d3fend_mapping():
    result = map_finding_to_standards({"title": "Unclassified observation"})
    assert result["d3fend"] == []
