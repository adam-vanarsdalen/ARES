"""Rules of Engagement loading and capability authorization decisions."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import yaml

from utils.capability_profiles import (
    ADVANCED_ACTIONS,
    PASSIVE_ACTIONS,
    RECON_ACTIONS,
    RISKY_ACTIONS,
    CapabilityProfile,
    actions_for_profile,
    resolve_profile,
)
from utils.config import (
    ENABLE_ADVANCED_VERIFICATION,
    ENABLE_LAB_EXPLOIT_SIMULATION,
    ENABLE_RISKY_METHOD_CHECKS,
    REQUIRE_LOCAL_TARGET_FOR_LAB_EXPLOIT_SIM,
    REQUIRE_ROE_FOR_ADVANCED,
    ROE_POLICY_DIR,
)
from utils.scope_validator import Scope, ScopeValidator


DEFAULT_ALLOWED_METHODS = ["GET", "HEAD", "OPTIONS"]


@dataclass
class RoEPolicy:
    name: str = ""
    allowed_domains: list[str] = field(default_factory=list)
    allowed_ips: list[str] = field(default_factory=list)
    allowed_cidrs: list[str] = field(default_factory=list)
    forbidden_domains: list[str] = field(default_factory=list)
    forbidden_paths: list[str] = field(default_factory=list)
    allowed_methods: list[str] = field(default_factory=lambda: list(DEFAULT_ALLOWED_METHODS))
    risky_methods_allowed: list[str] = field(default_factory=list)
    explicitly_allowed_risky_paths: list[str] = field(default_factory=list)
    max_requests_per_minute: int = 30
    allowed_profiles: list[str] = field(default_factory=lambda: ["passive", "recon"])
    advanced_verification: bool = False
    lab_targets: list[str] = field(default_factory=list)
    scan_windows: list[dict | str] = field(default_factory=list)
    notes: str = ""
    allowed_capabilities: list[str] = field(default_factory=list)
    allowed_nuclei_template_ids: list[str] = field(default_factory=list)
    allow_uninspected_nuclei_templates: bool = False
    source_path: str = ""

    def to_dict(self) -> dict:
        return {
            "engagement": {
                "name": self.name,
                "allowed_domains": self.allowed_domains,
                "allowed_ips": self.allowed_ips,
                "allowed_cidrs": self.allowed_cidrs,
                "forbidden_domains": self.forbidden_domains,
                "forbidden_paths": self.forbidden_paths,
                "allowed_methods": self.allowed_methods,
                "risky_methods_allowed": self.risky_methods_allowed,
                "explicitly_allowed_risky_paths": self.explicitly_allowed_risky_paths,
                "max_requests_per_minute": self.max_requests_per_minute,
                "allowed_profiles": self.allowed_profiles,
                "advanced_verification": self.advanced_verification,
                "lab_targets": self.lab_targets,
                "scan_windows": self.scan_windows,
                "notes": self.notes,
                "allowed_capabilities": self.allowed_capabilities,
                "allowed_nuclei_template_ids": self.allowed_nuclei_template_ids,
                "allow_uninspected_nuclei_templates": self.allow_uninspected_nuclei_templates,
            },
            "source_path": self.source_path,
        }


def _string_list(value, default=None) -> list[str]:
    if value is None:
        return list(default or [])
    if not isinstance(value, list):
        raise ValueError("RoE list fields must be YAML lists")
    return [str(item).strip() for item in value if str(item).strip()]


def parse_roe_policy(data: dict, source_path: str = "") -> RoEPolicy:
    if not isinstance(data, dict):
        raise ValueError("RoE policy must be a mapping")
    engagement = data.get("engagement", data)
    if not isinstance(engagement, dict):
        raise ValueError("RoE engagement must be a mapping")
    try:
        max_rpm = int(engagement.get("max_requests_per_minute", 30))
    except (TypeError, ValueError) as exc:
        raise ValueError("RoE max_requests_per_minute must be an integer") from exc
    return RoEPolicy(
        name=str(engagement.get("name", "")).strip(),
        allowed_domains=_string_list(engagement.get("allowed_domains")),
        allowed_ips=_string_list(engagement.get("allowed_ips")),
        allowed_cidrs=_string_list(engagement.get("allowed_cidrs")),
        forbidden_domains=_string_list(engagement.get("forbidden_domains")),
        forbidden_paths=_string_list(engagement.get("forbidden_paths")),
        allowed_methods=[method.upper() for method in _string_list(engagement.get("allowed_methods"), DEFAULT_ALLOWED_METHODS)],
        risky_methods_allowed=[method.upper() for method in _string_list(engagement.get("risky_methods_allowed"))],
        explicitly_allowed_risky_paths=_string_list(engagement.get("explicitly_allowed_risky_paths")),
        max_requests_per_minute=max(1, max_rpm),
        allowed_profiles=[item.lower() for item in _string_list(engagement.get("allowed_profiles"), ["passive", "recon"])],
        advanced_verification=bool(engagement.get("advanced_verification", False)),
        lab_targets=_string_list(engagement.get("lab_targets")),
        scan_windows=list(engagement.get("scan_windows") or []),
        notes=str(engagement.get("notes", "")).strip(),
        allowed_capabilities=_string_list(engagement.get("allowed_capabilities")),
        allowed_nuclei_template_ids=_string_list(engagement.get("allowed_nuclei_template_ids")),
        allow_uninspected_nuclei_templates=bool(
            engagement.get("allow_uninspected_nuclei_templates", False)
        ),
        source_path=source_path,
    )


_POLICY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


def resolve_roe_policy_path(policy_id: str, policy_dir: str = "") -> Path:
    raw_id = str(policy_id or "").strip()
    if not raw_id:
        raise ValueError("RoE policy ID is required")
    if not _POLICY_ID.fullmatch(raw_id) or "/" in raw_id or "\\" in raw_id or raw_id in {".", ".."}:
        raise ValueError("Invalid RoE policy ID")
    root = Path(policy_dir or ROE_POLICY_DIR)
    if not root.is_absolute():
        root = Path(__file__).resolve().parents[1] / root
    root = root.resolve()
    filename = raw_id if raw_id.endswith((".yaml", ".yml")) else f"{raw_id}.yaml"
    candidate = root / filename
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ValueError(f"Unknown RoE policy ID: {raw_id}") from exc
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("RoE policy resolves outside the approved policy directory") from exc
    if not resolved.is_file():
        raise ValueError(f"Unknown RoE policy ID: {raw_id}")
    return resolved


def load_roe_policy(policy_id: str, policy_dir: str = "") -> RoEPolicy | None:
    raw_id = str(policy_id or "").strip()
    if not raw_id:
        return None
    policy_path = resolve_roe_policy_path(raw_id, policy_dir)
    with policy_path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    return parse_roe_policy(data, source_path=str(policy_path))


def _target_parts(target: str) -> tuple[str, str]:
    raw = str(target or "").strip()
    if not raw:
        return "", "/"
    parsed = urlsplit(raw if "://" in raw else f"//{raw}")
    return (parsed.hostname or raw).lower().rstrip("."), parsed.path or "/"


def is_local_or_lab_target(target: str, roe: RoEPolicy | None = None) -> bool:
    host, _ = _target_parts(target)
    if host in {"localhost", "127.0.0.1", "::1"} or host.endswith(".local"):
        return True
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback:
            return True
    except ValueError:
        pass
    if roe:
        for declared in roe.lab_targets:
            declared_host, _ = _target_parts(declared)
            if host == declared_host or host.endswith("." + declared_host):
                return True
            try:
                if ipaddress.ip_address(host) in ipaddress.ip_network(declared, strict=False):
                    return True
            except ValueError:
                continue
    from utils.lab_targets import is_lab_target

    return is_lab_target(target)


def _scope_validator(scope) -> ScopeValidator | None:
    if isinstance(scope, ScopeValidator):
        return scope
    if isinstance(scope, Scope):
        return ScopeValidator(scope)
    return None


def _decision(allowed: bool, reason: str, profile: CapabilityProfile, matched_rule: str,
              confirmation: bool = False, safety_flags: list[str] | None = None) -> dict:
    return {
        "allowed": allowed,
        "reason": reason,
        "profile": profile.value,
        "matched_rule": matched_rule,
        "operator_confirmation_required": confirmation,
        "audit_required": True,
        "safety_flags": safety_flags or [],
    }


def evaluate_capability_action(action, profile, roe: RoEPolicy | dict | None, scope) -> dict:
    """Evaluate profile, RoE, scope, method, path, and target for one action."""
    resolved = resolve_profile(profile)
    if isinstance(roe, dict):
        roe = parse_roe_policy(roe)
    if isinstance(action, str):
        action = {"name": action}
    action = dict(action or {})
    name = str(action.get("name") or action.get("action") or "").strip()
    target = str(action.get("target") or "")
    method = str(action.get("method") or "GET").upper()
    _, target_path = _target_parts(target)
    path = str(action.get("path") or target_path or "/")
    flags = ["scope-enforced", "audit-required"]

    validator = _scope_validator(scope)
    if target and validator:
        valid, reason = validator.validate(target)
        if not valid:
            return _decision(False, reason, resolved, "scope_denied", safety_flags=flags)

    if resolved == CapabilityProfile.ADVANCED:
        if not ENABLE_ADVANCED_VERIFICATION:
            return _decision(False, "Advanced verification is disabled by configuration.", resolved, "advanced_feature_flag", safety_flags=flags)
        if REQUIRE_ROE_FOR_ADVANCED and roe is None:
            return _decision(False, "Advanced profile requires a loaded RoE policy.", resolved, "advanced_requires_roe", safety_flags=flags)
    if resolved == CapabilityProfile.CUSTOM and roe is None:
        return _decision(False, "Custom profile requires a loaded RoE policy.", resolved, "custom_requires_roe", safety_flags=flags)
    if resolved == CapabilityProfile.LAB:
        if not ENABLE_LAB_EXPLOIT_SIMULATION:
            return _decision(False, "Lab exploit simulation is disabled by configuration.", resolved, "lab_feature_flag", safety_flags=flags)
        if REQUIRE_LOCAL_TARGET_FOR_LAB_EXPLOIT_SIM and target and not is_local_or_lab_target(target, roe):
            return _decision(False, "Lab profile requires a localhost or explicitly declared lab target.", resolved, "lab_target_required", safety_flags=flags)

    if roe:
        if roe.allowed_profiles and resolved.value not in roe.allowed_profiles:
            return _decision(False, f"Profile {resolved.value} is not allowed by the RoE.", resolved, "roe_allowed_profiles", safety_flags=flags)
        host, _ = _target_parts(target)
        if host and any(host == item or host.endswith("." + item.lstrip("*.")) for item in roe.forbidden_domains):
            return _decision(False, f"Target {host} is forbidden by the RoE.", resolved, "roe_forbidden_domain", safety_flags=flags)
        if path and any(path == item or path.startswith(item.rstrip("/") + "/") for item in roe.forbidden_paths):
            return _decision(False, f"Path {path} is forbidden by the RoE.", resolved, "roe_forbidden_path", safety_flags=flags)

    if resolved == CapabilityProfile.PASSIVE and name not in PASSIVE_ACTIONS:
        return _decision(False, f"Passive profile does not permit active capability {name}.", resolved, "profile_passive", safety_flags=flags)
    if resolved == CapabilityProfile.RECON and name not in RECON_ACTIONS:
        return _decision(False, f"Recon profile does not permit advanced capability {name}.", resolved, "profile_recon", safety_flags=flags)
    if resolved == CapabilityProfile.ADVANCED and name not in ADVANCED_ACTIONS and name not in RISKY_ACTIONS:
        return _decision(False, f"Capability {name} is not defined for the advanced profile.", resolved, "profile_advanced", safety_flags=flags)
    if resolved == CapabilityProfile.LAB and name not in actions_for_profile(resolved):
        return _decision(False, f"Capability {name} is not defined for the lab profile.", resolved, "profile_lab", safety_flags=flags)
    if resolved == CapabilityProfile.CUSTOM:
        allowed_custom = set(roe.allowed_capabilities if roe else [])
        if name not in allowed_custom:
            return _decision(False, f"Custom RoE does not allow capability {name}.", resolved, "roe_allowed_capabilities", safety_flags=flags)

    risky_method = method in {"PUT", "DELETE", "PATCH"} or name in {"risky_method_check", "put_method_check", "delete_method_check"}
    if risky_method:
        if resolved not in {CapabilityProfile.ADVANCED, CapabilityProfile.CUSTOM}:
            return _decision(False, "Risky methods require advanced or custom profile.", resolved, "risky_profile_required", safety_flags=flags)
        if not ENABLE_RISKY_METHOD_CHECKS:
            return _decision(False, "Risky method checks are disabled by configuration.", resolved, "risky_feature_flag", safety_flags=flags)
        if roe is None or method not in roe.risky_methods_allowed:
            return _decision(False, f"Method {method} is not explicitly allowed by the RoE.", resolved, "roe_risky_method_allowlist", safety_flags=flags)
        if not roe.explicitly_allowed_risky_paths or path not in roe.explicitly_allowed_risky_paths:
            return _decision(False, f"Path {path} is not explicitly allowed for risky methods.", resolved, "roe_risky_path_allowlist", safety_flags=flags)
        leaf = path.rstrip("/").rsplit("/", 1)[-1]
        if leaf and ("." in leaf or leaf.startswith(".")):
            return _decision(False, f"Path {path} could create or overwrite a file.", resolved, "risky_file_creation_path", safety_flags=flags)
        flags.extend(["zero-body-required", "roe-risky-method-authorized"])
        return _decision(True, "Risky method is explicitly authorized by profile and RoE.", resolved, "roe_risky_method_allowlist", True, flags)

    if roe and method not in roe.allowed_methods and method not in roe.risky_methods_allowed:
        return _decision(False, f"Method {method} is not allowed by the RoE.", resolved, "roe_allowed_methods", safety_flags=flags)
    if resolved == CapabilityProfile.ADVANCED and name in ADVANCED_ACTIONS - RECON_ACTIONS:
        if not roe or not roe.advanced_verification:
            return _decision(False, "RoE does not enable advanced verification.", resolved, "roe_advanced_verification", safety_flags=flags)
        return _decision(True, "Advanced verification permitted by profile and RoE.", resolved, "roe_advanced_verification", True, flags)

    return _decision(True, "Capability permitted by profile, RoE, and scope.", resolved, "profile_capability", False, flags)
