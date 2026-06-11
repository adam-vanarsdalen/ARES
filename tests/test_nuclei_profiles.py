import json
from unittest.mock import patch

import tools.nuclei_runner as nuclei
from utils.roe import parse_roe_policy
from utils.scope_validator import Scope, ScopeValidator


def _scope():
    return ScopeValidator(Scope(domains=["example.com"]))


def _roe(profiles=None, capabilities=None, template_ids=None, allow_uninspected=False):
    return parse_roe_policy({
        "engagement": {
            "allowed_domains": ["example.com"],
            "allowed_profiles": profiles or ["advanced"],
            "allowed_methods": ["GET", "HEAD"],
            "advanced_verification": True,
            "allowed_capabilities": capabilities or [],
            "allowed_nuclei_template_ids": template_ids or [],
            "allow_uninspected_nuclei_templates": allow_uninspected,
        }
    })


def test_disabled_returns_skipped():
    result = nuclei.run_nuclei("https://example.com", _scope(), "recon", enabled=False)
    assert result["status"] == "skipped"
    assert result["findings"] == []


def test_missing_binary_returns_skipped():
    with patch("tools.nuclei_runner.shutil.which", return_value=None):
        result = nuclei.run_nuclei("https://example.com", _scope(), "recon", enabled=True)
    assert result["status"] == "skipped"
    assert "binary" in result["reason"].lower()


def test_safe_profile_excludes_rce_and_dos_tags():
    policy = nuclei.resolve_nuclei_policy("safe", "recon", None)
    assert policy["allowed"] is True
    assert "rce" not in policy["tags"]
    assert "dos" not in policy["tags"]
    assert {"rce", "dos"}.issubset(set(policy["blocked_tags"]))


def test_moderate_requires_advanced_profile_and_roe():
    wrong_profile = nuclei.resolve_nuclei_policy("moderate", "recon", _roe())
    missing_roe = nuclei.resolve_nuclei_policy("moderate", "advanced", None)
    allowed = nuclei.resolve_nuclei_policy("moderate", "advanced", _roe())
    assert wrong_profile["status"] == "blocked_by_roe"
    assert missing_roe["status"] == "blocked_by_roe"
    assert allowed["allowed"] is True


def test_custom_requires_allowlist_and_blocks_dangerous_template_tags():
    missing = nuclei.resolve_nuclei_policy("custom", "custom", _roe(["custom"], ["nuclei_custom"]), [])
    dangerous = nuclei.resolve_nuclei_policy(
        "custom",
        "custom",
        _roe(["custom"], ["nuclei_custom"], ["dangerous-template"]),
        ["dangerous-template"],
        [{"id": "dangerous-template", "tags": ["rce", "cve"]}],
    )
    assert missing["status"] == "blocked_by_roe"
    assert dangerous["status"] == "blocked_by_roe"
    assert dangerous["blocked_templates"]["dangerous-template"] == ["rce"]


def test_custom_fails_closed_when_template_metadata_is_missing():
    policy = nuclei.resolve_nuclei_policy(
        "custom",
        "custom",
        _roe(["custom"], ["nuclei_custom"], ["unknown-template"]),
        ["unknown-template"],
        [],
    )
    assert policy["allowed"] is False
    assert policy["uninspected_templates"] == ["unknown-template"]


def test_custom_can_explicitly_allow_uninspected_template():
    policy = nuclei.resolve_nuclei_policy(
        "custom",
        "custom",
        _roe(["custom"], ["nuclei_custom"], ["known-exception"], allow_uninspected=True),
        ["known-exception"],
        [],
    )
    assert policy["allowed"] is True


def test_results_normalize_into_findings():
    raw = {
        "template-id": "missing-csp",
        "matched-at": "https://example.com/",
        "matcher-name": "header",
        "info": {
            "name": "Missing Content Security Policy",
            "severity": "medium",
            "description": "CSP was absent.",
            "tags": ["headers", "misconfig"],
        },
    }
    result = nuclei.normalize_nuclei_result(raw)
    assert result["title"] == "Missing Content Security Policy"
    assert result["severity"] == "MEDIUM"
    assert result["evidence"]["template_id"] == "missing-csp"
    assert result["exploitation_claimed"] is False


def test_runner_uses_jsonl_rate_limits_and_disables_interactsh():
    output = json.dumps({
        "template-id": "tech-detect",
        "matched-at": "https://example.com/",
        "info": {"name": "Technology Detect", "severity": "info", "tags": ["tech"]},
    })

    class _Process:
        stdout = output
        stderr = ""
        returncode = 0

    with (
        patch("tools.nuclei_runner.subprocess.run", return_value=_Process()) as run,
        patch("tools.nuclei_runner.ENABLE_NUCLEI", True),
    ):
        result = nuclei.run_nuclei(
            "https://example.com",
            _scope(),
            "recon",
            nuclei_profile="safe",
            binary="/usr/local/bin/nuclei",
        )

    command = run.call_args.args[0]
    assert "-jsonl" in command
    assert "-rl" in command
    assert command[command.index("-rl") + 1] == "60"
    assert command[command.index("-rld") + 1] == "60s"
    assert "-ni" in command
    assert result["status"] == "confirmed"
    assert len(result["findings"]) == 1


def test_runner_preserves_one_request_per_minute():
    class _Process:
        stdout = ""
        stderr = ""
        returncode = 0

    roe = _roe()
    roe.max_requests_per_minute = 1
    with (
        patch("tools.nuclei_runner.subprocess.run", return_value=_Process()) as run,
        patch("utils.roe.ENABLE_ADVANCED_VERIFICATION", True),
    ):
        nuclei.run_nuclei(
            "https://example.com",
            _scope(),
            "advanced",
            roe=roe,
            nuclei_profile="moderate",
            enabled=True,
            binary="/usr/local/bin/nuclei",
        )
    command = run.call_args.args[0]
    assert command[command.index("-rl") + 1] == "1"
    assert command[command.index("-rld") + 1] == "60s"
