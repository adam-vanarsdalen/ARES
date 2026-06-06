import json
from unittest.mock import patch

from agents import redteam_agent
from utils.scope_validator import Scope, ScopeValidator


EXPECTED_TOOLS = {
    "test_open_redirect",
    "test_http_methods",
    "test_clickjacking",
    "test_host_header_injection",
    "enumerate_api_endpoints",
    "discover_auth_panels",
    "discover_admin_panels",
    "test_cors_misconfiguration",
    "verify_operator_secret",
    "compile_redteam_report",
}


def _scope():
    return ScopeValidator(Scope(domains=["example.com"]))


def test_redteam_tools_expose_all_shared_verifiers():
    names = {tool["name"] for tool in redteam_agent.REDTEAM_TOOLS}
    assert EXPECTED_TOOLS <= names


def test_execute_tool_dispatches_shared_verifiers_with_scope():
    cases = [
        ("test_open_redirect", {"url": "https://example.com/login"}, "test_open_redirect"),
        ("test_http_methods", {"url": "https://example.com"}, "test_http_methods"),
        ("test_clickjacking", {"url": "https://example.com"}, "test_clickjacking"),
        ("test_host_header_injection", {"url": "https://example.com"}, "test_host_header_injection"),
        ("enumerate_api_endpoints", {"base_url": "https://example.com"}, "enumerate_api_endpoints"),
        ("discover_auth_panels", {"base_url": "https://example.com"}, "discover_auth_panels"),
        ("discover_admin_panels", {"base_url": "https://example.com"}, "discover_auth_panels"),
    ]
    validator = _scope()
    for tool_name, tool_input, patched_name in cases:
        with patch.object(redteam_agent, patched_name, return_value={"status": "confirmed"}) as verifier:
            result = json.loads(redteam_agent.execute_tool(tool_name, tool_input, validator))
        assert result["status"] == "confirmed"
        verifier.assert_called_once()
        assert verifier.call_args.args[-1] is validator


def test_http_method_agent_dispatch_does_not_enable_risky_methods():
    validator = _scope()
    with patch.object(redteam_agent, "test_http_methods", return_value={"status": "not_reproduced"}) as verifier:
        redteam_agent.execute_tool("test_http_methods", {"url": "https://example.com"}, validator)
    verifier.assert_called_once_with("https://example.com", validator)


def test_unknown_tool_returns_safe_structured_error():
    result = json.loads(redteam_agent.execute_tool("does_not_exist", {}, _scope()))
    assert result["status"] == "skipped"
    assert result["blocked"] is True
    assert "Unknown tool" in result["error"]


def test_scope_denial_is_returned_as_blocked_error():
    result = json.loads(redteam_agent.execute_tool(
        "test_open_redirect",
        {"url": "https://out-of-scope.invalid"},
        _scope(),
    ))
    assert result["blocked"] is True
    assert "scope" in result["error"].lower()


def test_redacted_secret_does_not_trigger_workbench_verification():
    with (
        patch.object(redteam_agent, "ENABLE_MANUAL_SECRET_VERIFY", True),
        patch.object(redteam_agent, "verify_operator_secret") as verifier,
    ):
        result = json.loads(redteam_agent.execute_tool(
            "verify_operator_secret",
            {"provider": "github"},
            _scope(),
            {"provider": "github", "value_preview": "ghp_...1234"},
        ))

    verifier.assert_not_called()
    assert result["status"] == "needs_manual_verification"
    assert result["raw_secret_stored"] is False


def test_operator_supplied_volatile_secret_can_use_mocked_workbench():
    raw_value = "operator-supplied-only"
    workbench_result = {
        "verification_source": "operator_supplied",
        "raw_secret_stored": False,
        "rotation_recommended": True,
    }
    with (
        patch.object(redteam_agent, "ENABLE_MANUAL_SECRET_VERIFY", True),
        patch.object(
            redteam_agent,
            "verify_operator_secret",
            return_value=workbench_result,
        ) as verifier,
    ):
        result = json.loads(redteam_agent.execute_tool(
            "verify_operator_secret",
            {"provider": "generic", "perform_metadata_check": False},
            _scope(),
            {"provider": "generic", "secret_value": raw_value},
        ))

    verifier.assert_called_once_with(
        "generic",
        raw_value,
        perform_metadata_check=False,
        secret_access_key="",
        session_token="",
    )
    assert raw_value not in json.dumps(result)
    assert result["verification_source"] == "operator_supplied"


def test_agent_prompt_sanitizer_removes_raw_secret_fields():
    raw_value = "ghp_operator_supplied_value_must_not_leave_process"
    sanitized = redteam_agent._sanitize_report_secrets({
        "title": "Exposed token",
        "secret_value": raw_value,
        "nested": {"token": raw_value, "value_preview": "ghp_...cess"},
    })

    rendered = json.dumps(sanitized)
    assert raw_value not in rendered
    assert sanitized["nested"]["value_preview"] == "ghp_...cess"
