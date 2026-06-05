"""Per-finding security framework mappings without compliance overclaims."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml


DISCLAIMER = "Mappings are control-relevant evidence, not compliance certification."
MAPPING_FILES = {
    "attack": "attack_mapping.yaml",
    "owasp_asvs": "owasp_asvs_mapping.yaml",
    "nist_800_53": "nist_800_53_mapping.yaml",
    "ssdf": "ssdf_mapping.yaml",
}


@lru_cache(maxsize=1)
def load_standards_mappings() -> dict:
    root = Path(__file__).resolve().parent.parent / "mappings"
    mappings = {}
    for framework, filename in MAPPING_FILES.items():
        with (root / filename).open("r", encoding="utf-8") as handle:
            mappings[framework] = yaml.safe_load(handle) or {}
    return mappings


def classify_finding_type(finding: dict) -> str:
    text = " ".join([
        str(finding.get("title", "")),
        str(finding.get("description", "")),
        str(finding.get("source", "")),
    ]).lower()
    aliases = (
        ("missing security header", "missing security headers"),
        ("clickjack", "clickjacking"),
        ("cors", "cors misconfiguration"),
        ("open redirect", "open redirect"),
        ("actuator", "exposed actuator"),
        ("phpinfo", "exposed phpinfo"),
        ("version disclosure", "version disclosure"),
        ("weak tls", "weak tls"),
        ("api docs", "exposed api docs"),
        ("swagger", "exposed api docs"),
        ("openapi", "exposed api docs"),
        ("secret", "exposed secrets"),
        ("host header", "host header injection"),
        ("api endpoint", "api endpoint exposure"),
        ("cve-", "vulnerable service/cve"),
        ("vulnerable service", "vulnerable service/cve"),
        ("admin panel", "exposed admin panel"),
        ("exposed path /admin", "exposed admin panel"),
    )
    for marker, finding_type in aliases:
        if marker in text:
            return finding_type
    return "unknown"


def map_finding_to_standards(finding: dict) -> dict:
    finding_type = classify_finding_type(finding)
    mappings = load_standards_mappings()
    output = {"attack": [], "owasp_asvs": [], "nist_800_53": [], "ssdf": [], "disclaimer": DISCLAIMER}
    if finding_type == "unknown":
        return output
    rationale = f"The observed `{finding_type}` condition is relevant to this control or adversary behavior."
    for framework, entries in mappings.items():
        entry = entries.get(finding_type)
        if not entry:
            continue
        mapped = dict(entry)
        mapped["rationale"] = rationale
        if framework == "attack":
            mapped["confidence"] = finding.get("confidence_class", finding.get("confidence", "MEDIUM"))
        output[framework].append(mapped)
    return output


def attach_standards_mappings(findings: list[dict]) -> list[dict]:
    for finding in findings:
        finding["standards"] = map_finding_to_standards(finding)
    return findings
