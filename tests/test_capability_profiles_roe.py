from unittest.mock import patch

from utils.capability_profiles import CapabilityProfile, actions_for_profile, resolve_profile
from utils.roe import evaluate_capability_action, parse_roe_policy
from utils.scope_validator import Scope, ScopeValidator


def _scope():
    return ScopeValidator(Scope(domains=["example.com", "*.example.com"], ip_ranges=["127.0.0.1/32"]))


def _advanced_roe(**overrides):
    engagement = {
        "name": "test",
        "allowed_domains": ["example.com"],
        "allowed_methods": ["GET", "HEAD", "OPTIONS", "TRACE"],
        "risky_methods_allowed": [],
        "explicitly_allowed_risky_paths": [],
        "allowed_profiles": ["advanced"],
        "advanced_verification": True,
        "lab_targets": [],
        "allowed_capabilities": [],
    }
    engagement.update(overrides)
    return parse_roe_policy({"engagement": engagement})


def test_profile_resolution_and_action_sets():
    assert resolve_profile("passive") == CapabilityProfile.PASSIVE
    assert "dns_lookup" in actions_for_profile("passive")
    assert "port_scan" not in actions_for_profile("passive")
    assert "tls_audit" in actions_for_profile("recon")


def test_passive_blocks_nmap_and_redteam():
    for action in ("port_scan", "advanced_verification"):
        decision = evaluate_capability_action(action, "passive", None, _scope())
        assert decision["allowed"] is False
        assert decision["matched_rule"] == "profile_passive"


def test_recon_allows_http_tls_and_version_disclosure():
    for action in ("http_probe", "tls_audit", "version_disclosure"):
        decision = evaluate_capability_action(
            {"name": action, "target": "https://example.com"},
            "recon",
            None,
            _scope(),
        )
        assert decision["allowed"] is True


def test_advanced_without_roe_is_blocked_by_default():
    with (
        patch("utils.roe.ENABLE_ADVANCED_VERIFICATION", True),
        patch("utils.roe.REQUIRE_ROE_FOR_ADVANCED", True),
    ):
        decision = evaluate_capability_action(
            {"name": "advanced_verification", "target": "https://example.com"},
            "advanced",
            None,
            _scope(),
        )
    assert decision["allowed"] is False
    assert decision["matched_rule"] == "advanced_requires_roe"


def test_advanced_with_roe_allows_verification():
    with (
        patch("utils.roe.ENABLE_ADVANCED_VERIFICATION", True),
        patch("utils.roe.REQUIRE_ROE_FOR_ADVANCED", True),
    ):
        decision = evaluate_capability_action(
            {"name": "open_redirect_verification", "target": "https://example.com/login"},
            "advanced",
            _advanced_roe(),
            _scope(),
        )
    assert decision["allowed"] is True
    assert decision["operator_confirmation_required"] is True


def test_lab_profile_blocks_public_target():
    roe = parse_roe_policy({
        "engagement": {
            "allowed_profiles": ["lab"],
            "allowed_methods": ["GET"],
            "lab_targets": ["127.0.0.1"],
        }
    })
    with (
        patch("utils.roe.ENABLE_LAB_EXPLOIT_SIMULATION", True),
        patch("utils.roe.REQUIRE_LOCAL_TARGET_FOR_LAB_EXPLOIT_SIM", True),
    ):
        decision = evaluate_capability_action(
            {"name": "lab_exploit_simulation", "target": "https://example.com"},
            "lab",
            roe,
            _scope(),
        )
    assert decision["allowed"] is False
    assert decision["matched_rule"] == "lab_target_required"


def test_risky_method_requires_profile_flag_roe_method_and_path():
    roe = _advanced_roe(
        risky_methods_allowed=["PUT"],
        explicitly_allowed_risky_paths=["/allowed"],
    )
    with (
        patch("utils.roe.ENABLE_ADVANCED_VERIFICATION", True),
        patch("utils.roe.REQUIRE_ROE_FOR_ADVANCED", True),
        patch("utils.roe.ENABLE_RISKY_METHOD_CHECKS", True),
    ):
        denied = evaluate_capability_action(
            {"name": "risky_method_check", "target": "https://example.com/blocked", "method": "PUT"},
            "advanced",
            roe,
            _scope(),
        )
        allowed = evaluate_capability_action(
            {"name": "risky_method_check", "target": "https://example.com/allowed", "method": "PUT"},
            "advanced",
            roe,
            _scope(),
        )

    assert denied["allowed"] is False
    assert denied["matched_rule"] == "roe_risky_path_allowlist"
    assert allowed["allowed"] is True
    assert "zero-body-required" in allowed["safety_flags"]


def test_out_of_scope_target_is_denied_before_profile_capability():
    decision = evaluate_capability_action(
        {"name": "http_probe", "target": "https://evil.test"},
        "recon",
        None,
        _scope(),
    )
    assert decision["allowed"] is False
    assert decision["matched_rule"] == "scope_denied"
