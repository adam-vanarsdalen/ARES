import os
import sys
from unittest.mock import patch

from fastapi.testclient import TestClient

from utils.finding_lifecycle import initialize_finding, review_finding
from utils.reportability import calculate_reportability_score


def test_false_positive_reduces_reportability():
    finding = initialize_finding({
        "title": "Candidate issue",
        "severity": "HIGH",
        "confidence": "HIGH",
        "evidence_refs": ["evidence:1"],
        "reproduction_steps": ["Repeat request."],
    })
    assert finding["reportability_score"] > 0
    reviewed = review_finding(finding, {
        "lifecycle_state": "false_positive",
        "false_positive_reason": "Control response matched.",
    })
    assert reviewed["reportability_score"] == 0
    assert reviewed["operational_priority"] == "informational"


def test_evidence_backed_finding_scores_higher():
    base = {"title": "Finding", "severity": "MEDIUM", "confidence": "MEDIUM"}
    weak = calculate_reportability_score(dict(base))
    strong = calculate_reportability_score({
        **base,
        "confidence": "HIGH",
        "evidence_refs": ["evidence:1", "evidence:2"],
        "reproduction_steps": ["Repeat request."],
        "confirmed": True,
    })
    assert strong > weak


def _client():
    os.environ["ARES_API_KEY"] = "finding-test-key"
    os.environ["ARES_ENV"] = "dev"
    os.environ["ARES_DB_PATH"] = ":memory:"
    for module in list(sys.modules):
        if module == "server" or module == "utils.config" or module == "utils.session_store":
            sys.modules.pop(module, None)
    with patch("ollama_compat.check_ollama", return_value={"running": True, "models": []}):
        import server

        server.init_db()
        return server, TestClient(server.app)


def test_finding_state_transition_persists():
    server, client = _client()
    server.create_session("finding-session", "example.com", "full", "2026-06-05T00:00:00Z")
    server.update_session("finding-session", results={
        "recon": {
            "critical_findings": [],
            "high_findings": [{
                "finding_id": "finding:abc",
                "title": "Exposed admin",
                "severity": "HIGH",
                "confidence": "HIGH",
                "evidence_refs": ["evidence:1"],
            }],
            "medium_findings": [],
        }
    })
    response = client.patch(
        "/assess/finding-session/findings/finding:abc/review",
        headers={"X-ARES-Key": "finding-test-key"},
        json={"lifecycle_state": "confirmed", "analyst_notes": "Reproduced manually."},
    )
    assert response.status_code == 200
    stored = server.get_session("finding-session")["results"]["recon"]["high_findings"][0]
    assert stored["lifecycle_state"] == "confirmed"
    assert stored["analyst_notes"] == "Reproduced manually."


def test_finding_patch_requires_authentication():
    server, client = _client()
    server.create_session("auth-session", "example.com", "full", "2026-06-05T00:00:00Z")
    response = client.patch(
        "/assess/auth-session/findings/finding:abc/review",
        json={"lifecycle_state": "confirmed"},
    )
    assert response.status_code == 401
