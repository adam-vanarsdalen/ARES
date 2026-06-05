from unittest.mock import patch

import pytest

import pipeline
import tools.redteam_verification as rv
from utils.capability_profiles import CapabilityProfile
from utils.roe import evaluate_capability_action, parse_roe_policy
from utils.scope_validator import Scope, ScopeValidator


class _Graph:
    nodes = ["target"]

    def get_critical_paths(self):
        return []

    def to_dict(self):
        return {"nodes": []}


async def _fast_sleep(*args, **kwargs):
    return None


def _scope():
    return Scope(domains=["example.com", "*.example.com"])


def _roe(**overrides):
    engagement = {
        "name": "advanced-test",
        "allowed_domains": ["example.com"],
        "allowed_methods": ["GET", "HEAD", "OPTIONS", "TRACE"],
        "risky_methods_allowed": [],
        "explicitly_allowed_risky_paths": [],
        "allowed_profiles": ["advanced"],
        "advanced_verification": True,
    }
    engagement.update(overrides)
    return parse_roe_policy({"engagement": engagement})


def _pipeline():
    instance = pipeline.ARESPipeline(
        target="example.com",
        scope=_scope(),
        mode="full",
        session={},
        log_fn=lambda *args: None,
        phase_fn=lambda *args: None,
        emit_fn=lambda *args: None,
        profile="advanced",
    )
    instance.profile = CapabilityProfile.ADVANCED
    return instance


@pytest.mark.asyncio
async def test_advanced_with_roe_verifies_high_finding():
    instance = _pipeline()
    instance.roe = _roe()
    captured = {}

    async def fake_synthesis(self, target, vulns, test_results, kill_chain_data):
        captured["results"] = test_results
        return pipeline._ground_redteam_report(target, vulns, test_results, kill_chain_data, {})

    vuln_data = {
        "critical_findings": [],
        "high_findings": [{
            "title": "Exposed path /admin",
            "description": "Observed HTTP 403",
            "affected": "/admin",
            "cvss_score": 7.5,
            "evidence_refs": ["http-1"],
        }],
        "medium_findings": [],
    }
    with (
        patch("utils.roe.ENABLE_ADVANCED_VERIFICATION", True),
        patch("pipeline._test_exposed_path", return_value=rv.verification_result(
            rv.VerificationStatus.CONFIRMED,
            "Confirm access control with an authorized test account.",
            confirmed=True,
            path="/admin",
            url="https://example.com/admin",
            status_code=403,
        )),
        patch("pipeline.build_attack_graph", return_value=_Graph()),
        patch("pipeline.generate_kill_chains", return_value={"kill_chains": []}),
        patch.object(pipeline.ARESPipeline, "_ai_redteam_synthesis", new=fake_synthesis),
        patch("pipeline.asyncio.sleep", new=_fast_sleep),
    ):
        report = await instance._run_redteam(vuln_data, {"_ct_data": {}, "_js_data": {}})

    assert captured["results"][0]["result"]["status"] == "confirmed"
    assert captured["results"][0]["result"]["next_best_manual_test"]
    assert report["profile_badge"] == "ADVANCED"


@pytest.mark.asyncio
async def test_advanced_without_roe_records_blocked_verification():
    instance = _pipeline()
    instance.roe = None
    vuln_data = {
        "critical_findings": [],
        "high_findings": [{"title": "Open redirect", "description": "Candidate redirect", "cvss_score": 7.0}],
        "medium_findings": [],
    }
    with (
        patch("utils.roe.ENABLE_ADVANCED_VERIFICATION", True),
        patch("pipeline.test_open_redirect") as verifier,
        patch("pipeline.build_attack_graph", return_value=_Graph()),
        patch("pipeline.generate_kill_chains", return_value={"kill_chains": []}),
        patch("pipeline.asyncio.sleep", new=_fast_sleep),
    ):
        report = await instance._run_redteam(vuln_data, {"_ct_data": {}, "_js_data": {}})

    verifier.assert_not_called()
    assert report["verification_results"][0]["result"]["status"] == "blocked_by_roe"
    assert report["verification_results"][0]["result"]["matched_rule"] == "advanced_requires_roe"


def test_put_delete_require_explicit_method_path_and_non_file_target():
    validator = ScopeValidator(_scope())
    with (
        patch("utils.roe.ENABLE_ADVANCED_VERIFICATION", True),
        patch("utils.roe.ENABLE_RISKY_METHOD_CHECKS", True),
    ):
        no_path = evaluate_capability_action(
            {"name": "risky_method_check", "target": "https://example.com/probe", "method": "PUT"},
            "advanced",
            _roe(risky_methods_allowed=["PUT"]),
            validator,
        )
        file_path = evaluate_capability_action(
            {"name": "risky_method_check", "target": "https://example.com/probe.txt", "method": "PUT"},
            "advanced",
            _roe(risky_methods_allowed=["PUT"], explicitly_allowed_risky_paths=["/probe.txt"]),
            validator,
        )
        allowed = evaluate_capability_action(
            {"name": "risky_method_check", "target": "https://example.com/probe", "method": "PUT"},
            "advanced",
            _roe(risky_methods_allowed=["PUT"], explicitly_allowed_risky_paths=["/probe"]),
            validator,
        )

    assert no_path["matched_rule"] == "roe_risky_path_allowlist"
    assert file_path["matched_rule"] == "risky_file_creation_path"
    assert allowed["allowed"] is True


def test_risky_method_request_uses_zero_body():
    captured = {}

    class _Response:
        status = 204
        headers = {}

        def read(self, size):
            return b""

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    class _Opener:
        def open(self, request, timeout):
            captured["method"] = request.get_method()
            captured["data"] = request.data
            return _Response()

    with patch("tools.redteam_verification.urllib.request.build_opener", return_value=_Opener()):
        result = rv._request("https://example.com/probe", method="PUT")

    assert result["status_code"] == 204
    assert captured == {"method": "PUT", "data": b""}


def test_manual_followup_is_present_on_verification_results():
    validator = ScopeValidator(_scope())
    with patch.object(rv, "_request", return_value={"status_code": 404, "headers": {}, "body_preview": ""}):
        result = rv.test_open_redirect("https://example.com/login", validator)

    assert result["status"] == "not_reproduced"
    assert result["next_best_manual_test"]
