"""Deterministic, lab-only exploit-chain simulations with no exploit execution."""

from __future__ import annotations

import hashlib
from pathlib import Path

import yaml

from utils.lab_targets import LabManifest, is_lab_target, load_lab_manifest


SCENARIOS = {
    "exposed_actuator_secret_chain": {
        "steps": [
            "Observe the mock /actuator/env exposure on the lab application.",
            "Identify the deliberately fake LAB_ONLY credential marker.",
            "Map the simulated credential exposure to unauthorized service access risk.",
        ],
        "impact": "A production actuator exposure could disclose credentials and configuration that enable unauthorized access.",
        "controls": ["Disable public actuator endpoints", "Apply endpoint authentication", "Redact sensitive configuration values"],
        "reproduction": "Open the lab-only /actuator/env route and verify the response contains only documented fake LAB_ONLY values.",
    },
    "weak_cors_data_read_chain": {
        "steps": [
            "Observe the lab response reflecting an untrusted Origin.",
            "Confirm the simulation marks fake local account data as browser-readable.",
            "Map the condition to cross-origin data disclosure risk.",
        ],
        "impact": "A credentialed origin reflection flaw could let an attacker-controlled site read sensitive browser-accessible data.",
        "controls": ["Use an explicit trusted-origin allowlist", "Reject credentialed wildcard/reflected origins", "Test preflight behavior"],
        "reproduction": "Use the bundled local lab origin to request the fake data endpoint and inspect only synthetic response data.",
    },
    "open_redirect_phishing_chain": {
        "steps": [
            "Supply the documented lab redirect marker.",
            "Observe navigation to the non-routable example.invalid marker.",
            "Map trusted-domain link abuse to phishing risk.",
        ],
        "impact": "An open redirect can make a trusted hostname appear in a phishing link before forwarding a user elsewhere.",
        "controls": ["Allowlist redirect destinations", "Use relative post-login routes", "Reject absolute external URLs"],
        "reproduction": "Use the lab redirect parameter with https://example.invalid/ares-lab and observe the simulated Location header.",
    },
    "api_docs_to_endpoint_chain": {
        "steps": [
            "Read the lab OpenAPI document.",
            "Identify a documented hidden demo route.",
            "Confirm the route existence without authentication attempts or state changes.",
        ],
        "impact": "Public API documentation can reveal sensitive operational endpoints and reduce attacker discovery cost.",
        "controls": ["Restrict production API documentation", "Remove internal routes from public schemas", "Enforce authorization on every route"],
        "reproduction": "Open the local lab OpenAPI document and compare its synthetic paths with the lab route inventory.",
    },
    "upload_flow_risk_chain": {
        "steps": [
            "Inspect the harmless mock upload form.",
            "Submit only the bundled inert text fixture.",
            "Observe the simulated validation decision without storing or executing content.",
        ],
        "impact": "Weak upload validation can expose applications to unsafe content handling and storage abuse.",
        "controls": ["Allowlist content types", "Store uploads outside the web root", "Rename files and scan content"],
        "reproduction": "Use only the bundled inert lab fixture; the simulation does not create files or execute uploaded content.",
    },
}


def simulate_lab_scenario(
    target: str,
    scenario: str,
    manifest: LabManifest | None = None,
    observed_evidence_refs: list[str] | None = None,
) -> dict:
    manifest = manifest or load_lab_manifest()
    if not is_lab_target(target, manifest):
        raise PermissionError("Lab simulation target is not localhost or listed in the lab manifest.")
    if scenario not in SCENARIOS:
        raise ValueError(f"Unknown lab simulation scenario: {scenario}")
    definition = SCENARIOS[scenario]
    simulation_id = "lab-" + hashlib.sha256(f"{target}|{scenario}".encode()).hexdigest()[:12]
    evidence_refs = list(observed_evidence_refs or [])
    evidence_refs.append(f"simulation:{simulation_id}")
    return {
        "simulation_id": simulation_id,
        "lab_only": True,
        "target": target,
        "scenario": scenario,
        "steps": list(definition["steps"]),
        "evidence_refs": evidence_refs,
        "impact_narrative": definition["impact"],
        "controls_that_would_block": list(definition["controls"]),
        "safe_reproduction": definition["reproduction"],
        "real_target_execution_allowed": False,
    }


def run_lab_simulations(
    target: str,
    scenarios: list[str] | None = None,
    manifest_path: str = "",
    observed_evidence_refs: list[str] | None = None,
) -> list[dict]:
    manifest = load_lab_manifest(manifest_path)
    selected = scenarios or manifest.scenarios or list(SCENARIOS)
    return [
        simulate_lab_scenario(target, scenario, manifest, observed_evidence_refs)
        for scenario in selected
        if scenario in SCENARIOS
    ]


def load_apt_scenarios(scenarios_dir: str | Path | None = None) -> dict[str, dict]:
    """
    Load APT scenario YAML files and map each actor name to its definition.

    Missing directories and malformed files are ignored so lab documentation
    remains optional and non-fatal.
    """
    root = (
        Path(scenarios_dir)
        if scenarios_dir is not None
        else Path(__file__).resolve().parent.parent / "labs" / "apt_scenarios"
    )
    if not root.is_dir():
        return {}
    scenarios = {}
    for path in sorted([*root.glob("*.yaml"), *root.glob("*.yml")]):
        try:
            with path.open("r", encoding="utf-8") as handle:
                scenario = yaml.safe_load(handle) or {}
            if isinstance(scenario, dict) and scenario.get("actor"):
                scenarios[str(scenario["actor"])] = scenario
        except (OSError, yaml.YAMLError):
            continue
    return scenarios


def run_apt_scenario(actor_name: str, lab_url: str) -> dict:
    """
    Build a documentation-only APT scenario result for a declared lab target.

    The function performs no network request and refuses non-lab targets before
    loading or interpreting a scenario.
    """
    base = {
        "actor": actor_name,
        "lab_url": lab_url,
        "phases_simulated": [],
        "expected_findings": [],
        "controls": [],
        "status": "failed",
        "error": "",
    }
    try:
        if not is_lab_target(lab_url):
            return {**base, "status": "not_lab_target", "error": "target_not_declared_lab"}
        scenarios = load_apt_scenarios()
        scenario = next(
            (
                definition
                for actor, definition in scenarios.items()
                if actor.lower() == str(actor_name or "").lower()
            ),
            None,
        )
        if scenario is None:
            return {**base, "status": "unknown_actor", "error": "unknown_actor"}
        phases = [
            {
                "technique_id": str(phase.get("technique_id") or ""),
                "technique_name": str(phase.get("technique_name") or ""),
                "simulation_note": str(phase.get("lab_simulation") or "").strip(),
            }
            for phase in scenario.get("attack_lifecycle", [])
            if isinstance(phase, dict)
        ]
        return {
            "actor": str(scenario.get("actor") or actor_name),
            "lab_url": lab_url,
            "phases_simulated": phases,
            "expected_findings": list(scenario.get("expected_findings") or []),
            "controls": list(scenario.get("controls") or []),
            "status": "success",
            "error": "",
        }
    except Exception as exc:
        return {**base, "error": type(exc).__name__}
