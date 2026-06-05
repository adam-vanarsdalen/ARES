from pathlib import Path
from unittest.mock import patch

import pytest

from tools.lab_simulation import run_lab_simulations, simulate_lab_scenario
from utils.report_generator import generate_report
from utils.roe import evaluate_capability_action, parse_roe_policy
from utils.scope_validator import Scope, ScopeValidator


def _lab_roe():
    return parse_roe_policy({
        "engagement": {
            "name": "local-lab",
            "allowed_profiles": ["lab"],
            "allowed_methods": ["GET", "HEAD", "OPTIONS"],
            "lab_targets": ["127.0.0.1"],
        }
    })


def test_lab_simulation_blocked_for_public_domain():
    validator = ScopeValidator(Scope(domains=["example.com"]))
    with patch("utils.roe.ENABLE_LAB_EXPLOIT_SIMULATION", True):
        decision = evaluate_capability_action(
            {"name": "lab_exploit_simulation", "target": "https://example.com"},
            "lab",
            _lab_roe(),
            validator,
        )
    assert decision["allowed"] is False
    assert decision["matched_rule"] == "lab_target_required"


def test_lab_simulation_allowed_for_localhost_when_enabled():
    validator = ScopeValidator(Scope(ip_ranges=["127.0.0.1/32"]))
    with patch("utils.roe.ENABLE_LAB_EXPLOIT_SIMULATION", True):
        decision = evaluate_capability_action(
            {"name": "lab_exploit_simulation", "target": "127.0.0.1"},
            "lab",
            _lab_roe(),
            validator,
        )
    assert decision["allowed"] is True
    assert "audit-required" in decision["safety_flags"]


def test_simulation_produces_evidence_and_impact_narrative():
    simulation = simulate_lab_scenario(
        "127.0.0.1",
        "exposed_actuator_secret_chain",
        observed_evidence_refs=["evidence:http-1"],
    )
    assert simulation["lab_only"] is True
    assert simulation["real_target_execution_allowed"] is False
    assert simulation["evidence_refs"]
    assert simulation["impact_narrative"]
    assert simulation["safe_reproduction"]


def test_manifest_runs_declared_lab_scenarios():
    simulations = run_lab_simulations("127.0.0.1")
    assert {item["scenario"] for item in simulations} >= {
        "exposed_actuator_secret_chain",
        "weak_cors_data_read_chain",
        "open_redirect_phishing_chain",
        "api_docs_to_endpoint_chain",
    }


def test_public_target_cannot_call_simulator():
    with pytest.raises(PermissionError):
        simulate_lab_scenario("example.com", "open_redirect_phishing_chain")


def test_report_labels_lab_simulation(tmp_path):
    simulation = simulate_lab_scenario("127.0.0.1", "open_redirect_phishing_chain")
    report_path = generate_report(
        target="127.0.0.1",
        osint_report={"summary": "Local demo."},
        vuln_report={},
        redteam_report={
            "profile": "lab",
            "profile_badge": "LAB",
            "overall_risk": "LOW",
            "lab_simulations": [simulation],
        },
        output_dir=str(tmp_path),
    )
    report = Path(report_path).read_text(encoding="utf-8")
    assert "Lab Exploit Simulation" in report
    assert "Simulation only" in report
    assert "Real-target execution allowed: `False`" in report
