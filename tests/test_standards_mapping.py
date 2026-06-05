from utils.standards_mapping import DISCLAIMER, map_finding_to_standards


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
