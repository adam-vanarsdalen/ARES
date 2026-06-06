from pathlib import Path

import pytest

from utils.standards_mapping import DISCLAIMER, load_standards_mappings, map_finding_to_standards


def test_known_finding_maps_to_all_frameworks():
    mapping = map_finding_to_standards({
        "title": "Clickjacking exposure",
        "description": "Frame protections absent.",
        "confidence_class": "confirmed",
    })
    assert mapping["attack"][0]["technique_id"] == "T1189"
    assert mapping["owasp_asvs"][0]["control_id"] == "V14.4.3"
    assert mapping["nist_800_53"][0]["control_id"] == "SI-10"
    assert mapping["ssdf"][0]["practice_id"] == "PW.5.1"


def test_unknown_finding_maps_gracefully():
    mapping = map_finding_to_standards({"title": "Unclassified observation"})
    assert mapping["attack"] == []
    assert mapping["owasp_asvs"] == []
    assert mapping["nist_800_53"] == []
    assert mapping["ssdf"] == []


def test_disclaimer_always_appears():
    known = map_finding_to_standards({"title": "Weak TLS"})
    unknown = map_finding_to_standards({"title": "Unknown"})
    assert known["disclaimer"] == DISCLAIMER
    assert unknown["disclaimer"] == DISCLAIMER


def test_exposed_secret_maps_to_credential_controls():
    mapping = map_finding_to_standards({"title": "Exposed secrets in JavaScript"})
    assert mapping["attack"][0]["technique_id"] == "T1552"
    assert mapping["nist_800_53"][0]["control_id"] == "IA-5"


def test_mapping_files_load():
    loaded = load_standards_mappings()
    assert loaded["warnings"] == []
    assert all(loaded["mappings"][framework] for framework in (
        "attack", "owasp_asvs", "nist_800_53", "ssdf"
    ))


def test_missing_mapping_directory_does_not_crash(tmp_path):
    missing = tmp_path / "missing"
    with pytest.warns(RuntimeWarning, match="directory is missing"):
        mapping = map_finding_to_standards({"title": "Clickjacking"}, missing)
    assert mapping["attack"] == []
    assert mapping["warnings"]
    assert mapping["disclaimer"] == DISCLAIMER


def test_missing_single_mapping_file_loads_remaining_frameworks(tmp_path):
    source = Path(__file__).resolve().parent.parent / "mappings"
    for path in source.glob("*.yaml"):
        if path.name != "attack_mapping.yaml":
            (tmp_path / path.name).write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
    with pytest.warns(RuntimeWarning, match="file is missing"):
        mapping = map_finding_to_standards({"title": "Clickjacking"}, tmp_path)
    assert mapping["attack"] == []
    assert mapping["owasp_asvs"]
    assert mapping["warnings"]


def test_malformed_yaml_is_handled_gracefully(tmp_path):
    source = Path(__file__).resolve().parent.parent / "mappings"
    for path in source.glob("*.yaml"):
        content = "[unterminated" if path.name == "attack_mapping.yaml" else path.read_text(encoding="utf-8")
        (tmp_path / path.name).write_text(content, encoding="utf-8")
    with pytest.warns(RuntimeWarning, match="could not be loaded"):
        mapping = map_finding_to_standards({"title": "Clickjacking"}, tmp_path)
    assert mapping["attack"] == []
    assert mapping["nist_800_53"]
    assert mapping["disclaimer"] == DISCLAIMER
