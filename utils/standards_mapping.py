"""Per-finding security framework mappings without compliance overclaims."""

from __future__ import annotations

from pathlib import Path
import warnings

import yaml


DISCLAIMER = "Mappings are control-relevant evidence, not compliance certification."
MAPPING_FILES = {
    "attack": "attack_mapping.yaml",
    "owasp_asvs": "owasp_asvs_mapping.yaml",
    "nist_800_53": "nist_800_53_mapping.yaml",
    "ssdf": "ssdf_mapping.yaml",
}


def load_standards_mappings(mapping_dir: str | Path | None = None) -> dict:
    root = Path(mapping_dir) if mapping_dir is not None else Path(__file__).resolve().parent.parent / "mappings"
    mappings = {}
    load_warnings = []
    if not root.is_dir():
        message = f"Standards mapping directory is missing: {root}"
        warnings.warn(message, RuntimeWarning, stacklevel=2)
        return {
            "mappings": {framework: {} for framework in MAPPING_FILES},
            "warnings": [message],
        }
    for framework, filename in MAPPING_FILES.items():
        path = root / filename
        if not path.is_file():
            message = f"Standards mapping file is missing: {path}"
            warnings.warn(message, RuntimeWarning, stacklevel=2)
            load_warnings.append(message)
            mappings[framework] = {}
            continue
        try:
            with path.open("r", encoding="utf-8") as handle:
                loaded = yaml.safe_load(handle) or {}
            if not isinstance(loaded, dict):
                raise ValueError("top-level YAML value must be a mapping")
            mappings[framework] = loaded
        except (OSError, ValueError, yaml.YAMLError) as exc:
            message = f"Standards mapping file could not be loaded ({path}): {exc}"
            warnings.warn(message, RuntimeWarning, stacklevel=2)
            load_warnings.append(message)
            mappings[framework] = {}
    return {"mappings": mappings, "warnings": load_warnings}


def classify_finding_type(finding: dict) -> str:
    text = " ".join([
        str(finding.get("title", "")),
        str(finding.get("description", "")),
        str(finding.get("source", "")),
    ]).lower()
    aliases = (
        ("missing security header", "missing_security_headers"),
        ("clickjack", "clickjacking"),
        ("cors", "cors_misconfiguration"),
        ("open redirect", "open_redirect"),
        ("actuator", "exposed_actuator"),
        ("phpinfo", "exposed_phpinfo"),
        ("version disclosure", "version_disclosure"),
        ("weak tls", "weak_tls"),
        ("api docs", "exposed_api_docs"),
        ("swagger", "exposed_api_docs"),
        ("openapi", "exposed_api_docs"),
        ("secret", "exposed_secret"),
        ("host header", "host_header_injection"),
        ("api endpoint", "api_endpoint_exposure"),
        ("cve-", "vulnerable_service"),
        ("vulnerable service", "vulnerable_service"),
        ("admin panel", "exposed_admin_panel"),
        ("exposed path /admin", "exposed_admin_panel"),
    )
    for marker, finding_type in aliases:
        if marker in text:
            return finding_type
    return "unknown"


def map_finding_to_standards(finding: dict, mapping_dir: str | Path | None = None) -> dict:
    finding_type = classify_finding_type(finding)
    loaded = load_standards_mappings(mapping_dir)
    mappings = loaded["mappings"]
    output = {
        "attack": [],
        "owasp_asvs": [],
        "nist_800_53": [],
        "ssdf": [],
        "warnings": loaded["warnings"],
        "disclaimer": DISCLAIMER,
    }
    if finding_type == "unknown":
        return output
    rationale = f"The observed `{finding_type}` condition is relevant to this control or adversary behavior."
    for framework, entries in mappings.items():
        entry = entries.get(finding_type)
        if not entry:
            continue
        mapped = dict(entry)
        mapped.setdefault("rationale", rationale)
        if framework == "attack":
            mapped.setdefault("confidence", finding.get("confidence_class", finding.get("confidence", "MEDIUM")))
        output[framework].append(mapped)
    return output


def attach_standards_mappings(findings: list[dict]) -> list[dict]:
    for finding in findings:
        finding["standards"] = map_finding_to_standards(finding)
    return findings
