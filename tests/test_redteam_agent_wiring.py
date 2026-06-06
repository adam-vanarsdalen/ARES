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
