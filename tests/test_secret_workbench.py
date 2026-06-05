import json
from unittest.mock import patch

from tools.secret_workbench import verify_operator_secret


GITHUB_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"
AWS_ACCESS_KEY = "AKIAABCDEFGHIJKLMNOP"
AWS_SECRET_KEY = "a" * 40
STRIPE_KEY = "sk_test_abcdefghijklmnopqrstuvwxyz"


def test_github_metadata_result_is_redacted_and_raw_value_absent():
    with patch("tools.secret_workbench._github_metadata", return_value={
        "metadata_status": "valid",
        "identity_redacted": "a******n",
        "scopes": ["repo:status"],
    }):
        result = verify_operator_secret("github", GITHUB_TOKEN, perform_metadata_check=True)

    rendered = json.dumps(result)
    assert result["metadata_result"] == "valid"
    assert result["account_identity_redacted"] == "a******n"
    assert GITHUB_TOKEN not in rendered
    assert result["not_persisted"] is True


def test_aws_metadata_check_uses_only_operator_supplied_volatile_values():
    with patch("tools.secret_workbench._aws_metadata", return_value={
        "metadata_status": "valid",
        "identity_redacted": "a********t",
        "scopes": ["sts:GetCallerIdentity"],
    }) as metadata:
        result = verify_operator_secret(
            "aws",
            AWS_ACCESS_KEY,
            perform_metadata_check=True,
            secret_access_key=AWS_SECRET_KEY,
        )

    metadata.assert_called_once_with(AWS_ACCESS_KEY, AWS_SECRET_KEY, "")
    rendered = json.dumps(result)
    assert AWS_ACCESS_KEY not in rendered
    assert AWS_SECRET_KEY not in rendered
    assert result["scopes"] == ["sts:GetCallerIdentity"]


def test_aws_access_key_id_alone_cannot_verify_access():
    result = verify_operator_secret(
        "aws",
        AWS_ACCESS_KEY,
        perform_metadata_check=True,
    )
    assert result["metadata_result"] == "insufficient_input"
    assert "alone cannot verify" in result["reason"]


def test_stripe_is_format_only_and_never_enumerates_objects():
    result = verify_operator_secret("stripe", STRIPE_KEY, perform_metadata_check=True)
    assert result["token_format_valid"] is True
    assert result["metadata_result"] == "format_only"
    assert result["scopes"] == []
    assert STRIPE_KEY not in json.dumps(result)


def test_generic_format_validation_returns_rotation_guidance():
    result = verify_operator_secret("generic", "operator-supplied-value")
    assert result["token_format_valid"] is True
    assert result["rotation_recommendation"]
    assert result["raw_value_stored"] is False
