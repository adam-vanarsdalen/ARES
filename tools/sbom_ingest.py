"""CycloneDX SBOM ingestion with existing ARES CVE and EPSS correlation."""

from __future__ import annotations

import hashlib
import json
import logging
import urllib.parse

from tools.cve_sources import fetch_cve_data
from tools.epss_scoring import enrich_cves_with_epss


logger = logging.getLogger(__name__)


def _empty_result(status: str = "failed", error: str = "") -> dict:
    """Return the normalized SBOM analysis result shape."""
    return {
        "target": "unknown",
        "sbom_version": "",
        "component_count": 0,
        "vulnerable_component_count": 0,
        "critical_findings": [],
        "high_findings": [],
        "medium_findings": [],
        "low_findings": [],
        "asset_inventory": [],
        "status": status,
        "error": error,
    }


def _purl_parts(purl: str) -> tuple[str, str, str]:
    """Extract ecosystem, package name, and version from a package URL."""
    value = str(purl or "").strip()
    if not value.startswith("pkg:"):
        return "", "", ""
    body = value[4:].split("#", 1)[0].split("?", 1)[0]
    if "/" not in body:
        return "", "", ""
    ecosystem, package_part = body.split("/", 1)
    if "@" in package_part:
        package_path, version = package_part.rsplit("@", 1)
    else:
        package_path, version = package_part, ""
    package_name = urllib.parse.unquote(package_path).strip("/")
    return ecosystem.lower(), package_name, urllib.parse.unquote(version)


def _license_names(component: dict) -> list[str]:
    """Extract normalized license names or identifiers from a component."""
    names = []
    for entry in component.get("licenses", []) or []:
        if not isinstance(entry, dict):
            continue
        license_data = entry.get("license", entry)
        if not isinstance(license_data, dict):
            continue
        value = str(license_data.get("id") or license_data.get("name") or "").strip()
        if value and value not in names:
            names.append(value)
    return names


def _severity_bucket(score: float) -> tuple[str, str]:
    """Return the finding severity label and report bucket for a CVSS score."""
    if score >= 9.0:
        return "CRITICAL", "critical_findings"
    if score >= 7.0:
        return "HIGH", "high_findings"
    if score >= 4.0:
        return "MEDIUM", "medium_findings"
    return "LOW", "low_findings"


def _finding(component: dict, cve: dict) -> tuple[dict, str]:
    """Build a pipeline-compatible finding for one vulnerable component."""
    cve_ids = [
        str(cve_id)
        for cve_id in cve.get("cve_ids", []) or []
        if str(cve_id).startswith("CVE-")
    ]
    cve_id = cve_ids[0] if cve_ids else str(cve.get("id") or "CVE")
    try:
        score = float(cve.get("cvss_score") or 0)
    except (TypeError, ValueError):
        score = 0.0
    severity, bucket = _severity_bucket(score)
    name = str(component.get("name") or "unknown")
    version = str(component.get("version") or "")
    affected = f"{name} {version}".strip()
    epss = float(cve.get("epss") or 0)
    finding = {
        "title": f"{cve_id} in {affected}",
        "description": str(cve.get("description") or cve.get("summary") or ""),
        "cvss_score": score,
        "severity": severity,
        "affected": affected,
        "component_name": name,
        "component_version": version,
        "purl": str(component.get("purl") or ""),
        "cve_id": cve_id,
        "epss": epss,
        "epss_percent": float(cve.get("epss_percent") or 0),
        "priority": str(cve.get("priority") or "P4"),
        "source": "sbom_cve_correlation",
        "applicability_status": "unverified",
        "confirmed": False,
        "confidence": "MEDIUM",
        "evidence_refs": ["sbom_ingest", "fetch_cve_data", "epss_scoring"],
        "exploitability": "HIGH" if epss >= 0.1 else "MEDIUM",
        "business_impact": "HIGH" if score >= 7.0 else "MEDIUM",
        "next_best_manual_test": (
            "Confirm the deployed component version and affected feature "
            "against the vendor advisory before remediation."
        ),
    }
    return finding, bucket


def ingest_sbom(sbom_data: dict | str) -> dict:
    """
    Parse a CycloneDX 1.4-1.6 SBOM and correlate components with CVEs and EPSS.

    Per-component lookup failures are logged and retained as coverage errors
    without aborting analysis of the remaining components.
    """
    result = _empty_result()
    try:
        sbom = json.loads(sbom_data) if isinstance(sbom_data, str) else sbom_data
        if not isinstance(sbom, dict):
            raise ValueError("sbom_must_be_object")
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        result["error"] = type(exc).__name__
        return result

    metadata = sbom.get("metadata", {})
    root_component = metadata.get("component", {}) if isinstance(metadata, dict) else {}
    result["target"] = str(root_component.get("name") or "unknown")
    result["sbom_version"] = str(sbom.get("specVersion") or "")
    components = sbom.get("components", [])
    if not isinstance(components, list):
        result["error"] = "invalid_components"
        return result

    result["component_count"] = len(components)
    component_errors = []
    vulnerable_components = 0
    for index, component in enumerate(components):
        if not isinstance(component, dict):
            component_errors.append(f"component_{index}:invalid_component")
            continue
        name = str(component.get("name") or "unknown")
        version = str(component.get("version") or "")
        purl = str(component.get("purl") or "")
        ecosystem, package_name, purl_version = _purl_parts(purl)
        query_name = package_name or name
        query_version = purl_version or version
        query = (
            f"{ecosystem}:{query_name}:{query_version}"
            if ecosystem and query_name
            else " ".join(part for part in (query_name, query_version) if part)
        )
        asset = {
            "asset_id": "component:" + hashlib.sha256(
                f"{name}|{version}|{purl}|{index}".encode()
            ).hexdigest()[:12],
            "asset_type": "sbom_component",
            "name": name,
            "version": version,
            "purl": purl,
            "licenses": _license_names(component),
            "source": "cyclonedx_sbom",
            "vulnerable": False,
            "cve_count": 0,
        }
        result["asset_inventory"].append(asset)
        try:
            cve_result = fetch_cve_data(query)
            vulnerabilities = list(cve_result.get("vulnerabilities", []) or [])
            enriched = enrich_cves_with_epss(vulnerabilities)
            if enriched:
                vulnerable_components += 1
                asset["vulnerable"] = True
                asset["cve_count"] = len(enriched)
            for cve in enriched:
                finding, bucket = _finding(component, cve)
                result[bucket].append(finding)
        except Exception as exc:
            logger.warning(
                "SBOM CVE correlation failed for component %s: %s",
                name,
                exc,
            )
            component_errors.append(f"{name}:{type(exc).__name__}")

    result["vulnerable_component_count"] = vulnerable_components
    result["status"] = "success"
    result["error"] = ";".join(component_errors)
    return result
