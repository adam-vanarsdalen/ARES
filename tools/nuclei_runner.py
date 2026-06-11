"""Policy-controlled Nuclei adapter with normalized ARES output."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import yaml

from utils.config import (
    ENABLE_NUCLEI,
    NUCLEI_ALLOWED_TAGS,
    NUCLEI_ALLOWED_TEMPLATE_IDS,
    NUCLEI_BLOCKED_TAGS,
    NUCLEI_MAX_TEMPLATES,
    NUCLEI_MODERATE_TAGS,
    NUCLEI_PROFILE,
    NUCLEI_REQUIRE_ALLOWLIST_FOR_CUSTOM,
    NUCLEI_REQUIRE_ROE_FOR_MODERATE,
    NUCLEI_TEMPLATE_DIR,
    NUCLEI_TIMEOUT,
)
from utils.roe import evaluate_capability_action
from utils.scope_validator import ScopeValidator


VALID_NUCLEI_PROFILES = {"safe", "moderate", "custom"}


def load_template_metadata(template_dir: str, allowed_ids: list[str] | None = None) -> list[dict]:
    root = Path(template_dir).expanduser() if template_dir else None
    if not root or not root.is_dir():
        return []
    allowed = set(allowed_ids or [])
    metadata = []
    for path in sorted(root.rglob("*.yaml")) + sorted(root.rglob("*.yml")):
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError):
            continue
        template_id = str(raw.get("id", "")).strip()
        if not template_id or (allowed and template_id not in allowed):
            continue
        info = raw.get("info") or {}
        tags = info.get("tags") or []
        if isinstance(tags, str):
            tags = [item.strip() for item in tags.split(",") if item.strip()]
        metadata.append({
            "id": template_id,
            "path": str(path),
            "name": str(info.get("name", template_id)),
            "severity": str(info.get("severity", "info")).lower(),
            "tags": [str(tag).lower() for tag in tags],
        })
    return metadata


def resolve_nuclei_policy(
    nuclei_profile: str,
    capability_profile: str,
    roe,
    allowed_template_ids: list[str] | None = None,
    template_metadata: list[dict] | None = None,
) -> dict:
    selected = str(nuclei_profile or "safe").lower()
    if selected not in VALID_NUCLEI_PROFILES:
        return {"allowed": False, "status": "skipped", "reason": f"Unknown Nuclei profile: {selected}"}
    blocked_tags = {tag.lower() for tag in NUCLEI_BLOCKED_TAGS}
    if selected == "safe":
        return {
            "allowed": True,
            "status": "ready",
            "profile": selected,
            "tags": [tag for tag in NUCLEI_ALLOWED_TAGS if tag.lower() not in blocked_tags],
            "template_ids": [],
            "blocked_tags": sorted(blocked_tags),
        }
    if selected == "moderate":
        if capability_profile not in {"advanced", "custom"}:
            return {"allowed": False, "status": "blocked_by_roe", "reason": "Moderate Nuclei requires advanced or custom profile."}
        if NUCLEI_REQUIRE_ROE_FOR_MODERATE and roe is None:
            return {"allowed": False, "status": "blocked_by_roe", "reason": "Moderate Nuclei requires a loaded RoE policy."}
        tags = list(dict.fromkeys(NUCLEI_ALLOWED_TAGS + NUCLEI_MODERATE_TAGS))
        return {
            "allowed": True,
            "status": "ready",
            "profile": selected,
            "tags": [tag for tag in tags if tag.lower() not in blocked_tags],
            "template_ids": [],
            "blocked_tags": sorted(blocked_tags),
        }

    template_ids = list(dict.fromkeys(allowed_template_ids or []))[:NUCLEI_MAX_TEMPLATES]
    if roe is None:
        return {"allowed": False, "status": "blocked_by_roe", "reason": "Custom Nuclei requires a loaded RoE policy."}
    if NUCLEI_REQUIRE_ALLOWLIST_FOR_CUSTOM and not template_ids:
        return {"allowed": False, "status": "blocked_by_roe", "reason": "Custom Nuclei requires explicit template IDs."}
    roe_template_ids = set(getattr(roe, "allowed_nuclei_template_ids", []) or [])
    if not roe_template_ids or any(template_id not in roe_template_ids for template_id in template_ids):
        return {
            "allowed": False,
            "status": "blocked_by_roe",
            "reason": "Custom template IDs must be explicitly allowlisted by the RoE.",
        }
    metadata_by_id = {item.get("id"): item for item in (template_metadata or [])}
    missing_metadata = sorted(template_id for template_id in template_ids if template_id not in metadata_by_id)
    if missing_metadata and not getattr(roe, "allow_uninspected_nuclei_templates", False):
        return {
            "allowed": False,
            "status": "blocked_by_roe",
            "reason": "Custom template metadata is unavailable; governance fails closed.",
            "uninspected_templates": missing_metadata,
        }
    dangerous = {
        template_id: sorted(set(metadata_by_id.get(template_id, {}).get("tags", [])) & blocked_tags)
        for template_id in template_ids
    }
    dangerous = {template_id: tags for template_id, tags in dangerous.items() if tags}
    if dangerous:
        return {
            "allowed": False,
            "status": "blocked_by_roe",
            "reason": "Custom template allowlist contains blocked destructive tags.",
            "blocked_templates": dangerous,
        }
    return {
        "allowed": True,
        "status": "ready",
        "profile": selected,
        "tags": [],
        "template_ids": template_ids,
        "blocked_tags": sorted(blocked_tags),
    }


def normalize_nuclei_result(raw: dict) -> dict:
    info = raw.get("info") or {}
    template_id = raw.get("template-id") or raw.get("templateID") or raw.get("template") or "unknown"
    matched = raw.get("matched-at") or raw.get("host") or raw.get("url") or ""
    return {
        "title": info.get("name") or template_id,
        "severity": str(info.get("severity", "info")).upper(),
        "template_id": template_id,
        "affected": matched,
        "description": info.get("description") or f"Nuclei template {template_id} matched the target.",
        "tags": info.get("tags") or [],
        "matcher_name": raw.get("matcher-name", ""),
        "evidence": {
            "type": "nuclei_jsonl",
            "matched_at": matched,
            "template_id": template_id,
            "extracted_results": raw.get("extracted-results") or [],
        },
        "source": "nuclei",
        "exploitation_claimed": False,
    }


def run_nuclei(
    target: str,
    scope: ScopeValidator,
    capability_profile: str,
    roe=None,
    nuclei_profile: str = "",
    enabled: bool | None = None,
    binary: str = "",
    allowed_template_ids: list[str] | None = None,
    template_dir: str = "",
) -> dict:
    if enabled is False or (enabled is None and not ENABLE_NUCLEI):
        return {"status": "skipped", "reason": "Nuclei integration is disabled.", "findings": [], "evidence": []}
    scope.assert_in_scope(target)
    executable = binary or shutil.which("nuclei")
    if not executable:
        return {"status": "skipped", "reason": "Nuclei binary was not found.", "findings": [], "evidence": []}

    selected = nuclei_profile or NUCLEI_PROFILE
    template_ids = allowed_template_ids if allowed_template_ids is not None else NUCLEI_ALLOWED_TEMPLATE_IDS
    directory = template_dir or NUCLEI_TEMPLATE_DIR
    metadata = load_template_metadata(directory, template_ids)
    policy = resolve_nuclei_policy(selected, capability_profile, roe, template_ids, metadata)
    if not policy.get("allowed"):
        return {**policy, "findings": [], "evidence": []}

    action = {"safe": "nuclei_safe", "moderate": "nuclei_moderate", "custom": "nuclei_custom"}[selected]
    decision = evaluate_capability_action(
        {"name": action, "target": target, "method": "GET"},
        capability_profile,
        roe,
        scope,
    )
    if not decision["allowed"]:
        return {
            "status": "blocked_by_roe",
            "reason": decision["reason"],
            "authorization": decision,
            "findings": [],
            "evidence": [],
        }

    rate_limit_per_minute = max(1, int(getattr(roe, "max_requests_per_minute", 60)))
    command = [
        executable,
        "-u", target,
        "-jsonl",
        "-silent",
        "-ni",
        "-rl", str(rate_limit_per_minute),
        "-rld", "60s",
        "-timeout", str(max(1, min(NUCLEI_TIMEOUT, 30))),
        "-etags", ",".join(NUCLEI_BLOCKED_TAGS),
    ]
    if policy.get("tags"):
        command.extend(["-tags", ",".join(policy["tags"])])
    if policy.get("template_ids"):
        command.extend(["-id", ",".join(policy["template_ids"][:NUCLEI_MAX_TEMPLATES])])
    if directory:
        command.extend(["-t", directory])

    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=NUCLEI_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"status": "needs_manual_followup", "reason": "Nuclei timed out.", "findings": [], "evidence": [], "command": command[1:]}

    findings = []
    for line in process.stdout.splitlines():
        try:
            findings.append(normalize_nuclei_result(json.loads(line)))
        except (json.JSONDecodeError, TypeError):
            continue
    return {
        "status": "confirmed" if findings else "not_reproduced",
        "profile": selected,
        "findings": findings,
        "evidence": [finding["evidence"] for finding in findings],
        "return_code": process.returncode,
        "stderr": process.stderr[:500],
        "command": command[1:],
        "interactsh_enabled": False,
        "authorization": decision,
    }
