"""Tests for CycloneDX SBOM ingestion and CVE correlation."""

from unittest.mock import patch

from fastapi.testclient import TestClient

import server
from tools.sbom_ingest import ingest_sbom


def _sbom(components):
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {"component": {"name": "example-app"}},
        "components": components,
    }


def test_vulnerable_component_is_bucketed_by_cvss():
    cve_result = {
        "vulnerabilities": [{
            "id": "CVE-2026-0001",
            "description": "Example vulnerability",
            "cvss_score": 9.4,
        }]
    }
    enriched = [{
        **cve_result["vulnerabilities"][0],
        "epss": 0.2,
        "epss_percent": 20.0,
        "priority": "P1",
    }]
    with (
        patch("tools.sbom_ingest.fetch_cve_data", return_value=cve_result),
        patch("tools.sbom_ingest.enrich_cves_with_epss", return_value=enriched),
    ):
        result = ingest_sbom(_sbom([{
            "name": "example-lib",
            "version": "1.0.0",
            "purl": "pkg:pypi/example-lib@1.0.0",
        }]))
    assert result["status"] == "success"
    assert result["vulnerable_component_count"] == 1
    assert result["critical_findings"][0]["cve_id"] == "CVE-2026-0001"


def test_sbom_without_components_is_successful_and_empty():
    result = ingest_sbom(_sbom([]))
    assert result["component_count"] == 0
    assert result["critical_findings"] == []
    assert result["high_findings"] == []
    assert result["medium_findings"] == []
    assert result["low_findings"] == []


def test_malformed_json_returns_failed():
    result = ingest_sbom("{not valid json")
    assert result["status"] == "failed"
    assert result["error"]


def test_sbom_route_rejects_invalid_json():
    client = TestClient(server.app)
    response = client.post(
        "/sbom/analyze",
        content="{not valid json",
        headers={
            "Content-Type": "application/json",
            "X-ARES-Key": "test-key-123",
        },
    )
    assert response.status_code == 400
    assert response.json() == {"error": "invalid_sbom_json"}


def test_sbom_route_returns_analysis():
    client = TestClient(server.app)
    response = client.post(
        "/sbom/analyze",
        json=_sbom([]),
        headers={"X-ARES-Key": "test-key-123"},
    )
    assert response.status_code == 200
    assert response.json()["component_count"] == 0
