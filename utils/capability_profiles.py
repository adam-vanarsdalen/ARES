"""Canonical ARES capability profiles and action taxonomy."""

from __future__ import annotations

from enum import StrEnum


class CapabilityProfile(StrEnum):
    PASSIVE = "passive"
    RECON = "recon"
    ADVANCED = "advanced"
    LAB = "lab"
    CUSTOM = "custom"


PROFILE_DESCRIPTIONS = {
    CapabilityProfile.PASSIVE: "External intelligence collection with minimal direct interaction.",
    CapabilityProfile.RECON: "Standard authorized recon and vulnerability enrichment.",
    CapabilityProfile.ADVANCED: "RoE-governed, non-destructive verification.",
    CapabilityProfile.LAB: "Local or declared lab exploit simulation.",
    CapabilityProfile.CUSTOM: "Operator-defined capabilities governed by RoE.",
}

PASSIVE_ACTIONS = {
    "dns_lookup",
    "whois_lookup",
    "cert_transparency",
    "internetdb_lookup",
    "reverse_ip_lookup",
    "suggested_dorks",
    "asset_inventory",
    "report_generation",
}

RECON_ACTIONS = PASSIVE_ACTIONS | {
    "http_probe",
    "passive_url_discovery",
    "js_intelligence",
    "subdomain_enumerate",
    "misconfig_check",
    "port_scan",
    "tls_audit",
    "version_disclosure",
    "cve_lookup",
    "epss_scoring",
    "attack_graph",
    "nuclei_safe",
}

ADVANCED_ACTIONS = RECON_ACTIONS | {
    "advanced_verification",
    "open_redirect_verification",
    "host_header_verification",
    "http_method_verification",
    "clickjacking_verification",
    "cors_verification",
    "api_endpoint_discovery",
    "auth_panel_discovery",
    "nuclei_moderate",
}

LAB_ACTIONS = ADVANCED_ACTIONS | {
    "lab_exploit_simulation",
    "lab_ssrf_simulation",
    "lab_upload_simulation",
    "lab_secret_exposure_simulation",
}

RISKY_ACTIONS = {
    "risky_method_check",
    "put_method_check",
    "delete_method_check",
    "nuclei_custom",
    "lab_exploit_simulation",
    "lab_ssrf_simulation",
    "lab_upload_simulation",
    "lab_secret_exposure_simulation",
}

LEGACY_MODE_PROFILE_MAP = {
    "passive_only": CapabilityProfile.PASSIVE,
    "osint_only": CapabilityProfile.RECON,
    "light_active": CapabilityProfile.RECON,
    "recon_only": CapabilityProfile.RECON,
    "full": CapabilityProfile.RECON,
}


def resolve_profile(value: str | CapabilityProfile | None, legacy_mode: str = "") -> CapabilityProfile:
    raw = str(value or "").strip().lower()
    if not raw and legacy_mode:
        return LEGACY_MODE_PROFILE_MAP.get(legacy_mode.strip().lower(), CapabilityProfile.RECON)
    try:
        return CapabilityProfile(raw or CapabilityProfile.RECON.value)
    except ValueError as exc:
        valid = ", ".join(profile.value for profile in CapabilityProfile)
        raise ValueError(f"Invalid ARES profile {raw!r}; expected one of: {valid}") from exc


def actions_for_profile(profile: str | CapabilityProfile) -> set[str]:
    resolved = resolve_profile(profile)
    if resolved == CapabilityProfile.PASSIVE:
        return set(PASSIVE_ACTIONS)
    if resolved == CapabilityProfile.RECON:
        return set(RECON_ACTIONS)
    if resolved == CapabilityProfile.ADVANCED:
        return set(ADVANCED_ACTIONS)
    if resolved == CapabilityProfile.LAB:
        return set(LAB_ACTIONS)
    return set()


def profile_summary(profile: str | CapabilityProfile) -> dict:
    resolved = resolve_profile(profile)
    return {
        "profile": resolved.value,
        "description": PROFILE_DESCRIPTIONS[resolved],
        "capabilities": sorted(actions_for_profile(resolved)),
        "custom_capabilities_from_roe": resolved == CapabilityProfile.CUSTOM,
    }
