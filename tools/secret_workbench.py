"""Volatile operator-supplied secret verification with no raw persistence."""

from __future__ import annotations

import json
import re
import urllib.request

from utils.config import SECRET_VERIFY_ALLOWED_PROVIDERS


def _redact_identity(value: str) -> str:
    value = str(value or "")
    if not value:
        return ""
    if len(value) <= 2:
        return "*" * len(value)
    return value[0] + ("*" * min(len(value) - 2, 8)) + value[-1]


def _github_metadata(secret_value: str) -> dict:
    request = urllib.request.Request(
        "https://api.github.com/user",
        headers={
            "Authorization": f"Bearer {secret_value}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "ARES secret workbench/1.0",
        },
    )
    with urllib.request.urlopen(request, timeout=8) as response:
        body = json.loads(response.read(4096).decode("utf-8"))
        scopes = [item.strip() for item in response.headers.get("X-OAuth-Scopes", "").split(",") if item.strip()]
    return {
        "metadata_status": "valid",
        "identity_redacted": _redact_identity(body.get("login", "")),
        "scopes": scopes,
    }


def _aws_metadata(access_key_id: str, secret_access_key: str, session_token: str = "") -> dict:
    try:
        import boto3
    except ImportError:
        return {"metadata_status": "unavailable", "reason": "boto3 is not installed."}
    client = boto3.client(
        "sts",
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key,
        aws_session_token=session_token or None,
    )
    identity = client.get_caller_identity()
    return {
        "metadata_status": "valid",
        "identity_redacted": _redact_identity(identity.get("Arn", "") or identity.get("Account", "")),
        "scopes": ["sts:GetCallerIdentity"],
    }


def verify_operator_secret(
    provider: str,
    secret_value: str,
    *,
    perform_metadata_check: bool = False,
    secret_access_key: str = "",
    session_token: str = "",
) -> dict:
    selected = str(provider or "generic").lower().strip()
    allowed = {item.lower() for item in SECRET_VERIFY_ALLOWED_PROVIDERS}
    if selected not in allowed:
        raise ValueError("Provider is not enabled for manual secret verification.")

    value = str(secret_value or "")
    if not value:
        raise ValueError("A volatile secret value is required.")
    metadata = {"metadata_status": "not_requested", "identity_redacted": "", "scopes": []}

    if selected == "github":
        format_valid = bool(re.fullmatch(r"(gh[pousr]_[A-Za-z0-9_]{20,255}|github_pat_[A-Za-z0-9_]{20,255})", value))
        if perform_metadata_check and format_valid:
            try:
                metadata = _github_metadata(value)
            except Exception:
                metadata = {"metadata_status": "not_verified", "identity_redacted": "", "scopes": []}
        recommendation = "Rotate the token, review granted scopes, and remove it from client-side or shared storage."
    elif selected == "aws":
        format_valid = bool(re.fullmatch(r"(AKIA|ASIA)[A-Z0-9]{16}", value))
        if perform_metadata_check and format_valid and secret_access_key:
            try:
                metadata = _aws_metadata(value, secret_access_key, session_token)
            except Exception:
                metadata = {"metadata_status": "not_verified", "identity_redacted": "", "scopes": []}
        elif perform_metadata_check and not secret_access_key:
            metadata = {
                "metadata_status": "insufficient_input",
                "reason": "An access key ID alone cannot verify AWS access.",
                "identity_redacted": "",
                "scopes": [],
            }
        recommendation = "Deactivate and rotate exposed AWS credentials, then review CloudTrail and IAM usage."
    elif selected == "stripe":
        format_valid = bool(re.fullmatch(r"(sk|rk)_(test|live)_[A-Za-z0-9]{16,255}", value))
        metadata = {"metadata_status": "format_only", "identity_redacted": "", "scopes": []}
        recommendation = "Rotate the Stripe key and review restricted-key permissions; ARES does not enumerate Stripe objects."
    else:
        format_valid = len(value) >= 12 and not any(char.isspace() for char in value)
        metadata = {"metadata_status": "format_only", "identity_redacted": "", "scopes": []}
        recommendation = "Validate with the provider's approved operator workflow, rotate if exposed, and review access logs."

    return {
        "provider": selected,
        "token_format_valid": format_valid,
        "metadata_result": metadata.get("metadata_status", "not_requested"),
        "scopes": list(metadata.get("scopes", [])),
        "account_identity_redacted": metadata.get("identity_redacted", ""),
        "reason": metadata.get("reason", ""),
        "rotation_recommendation": recommendation,
        "rotation_recommended": True,
        "manual_verification_required": False,
        "verification_source": "operator_supplied",
        "not_persisted": True,
        "raw_secret_stored": False,
        "raw_value_stored": False,
        "automatic_discovered_secret_use": False,
    }
