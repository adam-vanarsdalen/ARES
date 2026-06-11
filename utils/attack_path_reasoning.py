"""Deterministic defensive reasoning over ARES attack graph node pairs."""

from __future__ import annotations

from tools.attack_graph import _stable_id


_SEVERITY_ORDER = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def _kind(node: dict) -> str:
    """Infer a normalized node kind from explicit fields and labels."""
    explicit = str(node.get("kind") or "").lower()
    if explicit:
        return explicit
    text = " ".join([
        str(node.get("type") or ""),
        str(node.get("label") or ""),
        str(node.get("title") or ""),
        str((node.get("data") or {}).get("title") if isinstance(node.get("data"), dict) else ""),
    ]).lower()
    aliases = (
        ("admin panel", "exposed_admin_panel"),
        ("actuator", "exposed_actuator"),
        ("secret", "exposed_secret"),
        ("cors", "cors_misconfiguration"),
        ("vulnerable service", "vulnerable_service"),
        ("cve-", "vulnerable_service"),
    )
    for marker, kind in aliases:
        if marker in text:
            return kind
    return str(node.get("type") or "unknown").lower()


def _node_id(node: dict) -> str:
    """Return a stable identifier for a possibly malformed graph node."""
    return str(node.get("id") or _stable_id("node", node.get("label", ""), _kind(node)))


def _severity(node: dict) -> str:
    """Normalize a node severity to a known label."""
    value = str(node.get("severity") or "INFO").upper()
    return value if value in _SEVERITY_ORDER else "INFO"


def _combined_severity(first: dict, second: dict) -> str:
    """Return the higher severity of two nodes."""
    values = (_severity(first), _severity(second))
    return max(values, key=lambda value: _SEVERITY_ORDER[value])


def _technique(node: dict, fallback: str) -> str:
    """Extract a node ATT&CK technique ID with a rule-specific fallback."""
    return str(
        node.get("technique_id")
        or (node.get("data") or {}).get("technique_id")
        or fallback
    )


def _path(
    first: dict,
    second: dict,
    name: str,
    steps: list[str],
    fallbacks: tuple[str, str],
    confidence: str,
) -> dict:
    """Build one normalized lateral-movement path result."""
    first_id = _node_id(first)
    second_id = _node_id(second)
    return {
        "path_id": _stable_id("path", first_id, second_id),
        "path_name": name,
        "steps": steps,
        "entry_node_id": first_id,
        "pivot_node_id": second_id,
        "technique_chain": [
            _technique(first, fallbacks[0]),
            _technique(second, fallbacks[1]),
        ],
        "combined_severity": _combined_severity(first, second),
        "confidence": confidence,
    }


def compute_lateral_movement_paths(graph_nodes: list[dict]) -> list[dict]:
    """
    Identify deterministic two-node paths where one exposure enables a pivot.

    Malformed nodes are skipped independently so one bad graph entry never
    prevents other valid paths from being returned.
    """
    if isinstance(graph_nodes, dict):
        graph_nodes = list(graph_nodes.values())
    if not isinstance(graph_nodes, list):
        return []
    nodes = [node for node in graph_nodes if isinstance(node, dict)]
    paths = []
    seen = set()

    def add(candidate: dict) -> None:
        """Append a path once while isolating malformed candidate failures."""
        try:
            if candidate["path_id"] not in seen:
                seen.add(candidate["path_id"])
                paths.append(candidate)
        except Exception:
            pass

    for first in nodes:
        try:
            first_kind = _kind(first)
            for second in nodes:
                if first is second:
                    continue
                second_kind = _kind(second)
                if first_kind == "identity" and not bool(first.get("mfa_present")) and second_kind == "exposed_admin_panel":
                    add(_path(
                        first,
                        second,
                        "Credential Stuffing to Admin Access",
                        ["Use a non-MFA identity in a credential stuffing attempt.", "Access the exposed administrative interface."],
                        ("T1078", "T1133"),
                        "high",
                    ))
                elif first_kind == "exposed_actuator" and second_kind == "exposed_secret":
                    add(_path(
                        first,
                        second,
                        "Actuator Credential Disclosure to Service Account Pivot",
                        ["Enumerate exposed actuator configuration.", "Use disclosed service credentials to assess adjacent access."],
                        ("T1190", "T1552.001"),
                        "high",
                    ))
                elif first_kind == "cors_misconfiguration" and second_kind == "identity":
                    add(_path(
                        first,
                        second,
                        "CORS Data Theft to Session Token Harvest",
                        ["Abuse cross-origin access to read browser data.", "Harvest an identity session token for a pivot."],
                        ("T1185", "T1539"),
                        "moderate",
                    ))
                elif first_kind == "vulnerable_service" and float(
                    first.get("cvss_score")
                    or (first.get("data") or {}).get("cvss_score")
                    or 0
                ) >= 7.0:
                    add(_path(
                        first,
                        second,
                        "RCE Foothold to Adjacent Service",
                        ["Establish a foothold through the high-severity vulnerable service.", "Pivot to the adjacent graph node."],
                        ("T1190", "T1021"),
                        "low",
                    ))
                elif (
                    first_kind == "cloud_resource"
                    and first.get("permission_level") == "public_read"
                    and second_kind == "exposed_secret"
                ):
                    add(_path(
                        first,
                        second,
                        "Cloud Storage Enumeration to Secret Extraction",
                        ["Enumerate the public-read cloud resource.", "Extract exposed secret material for further access."],
                        ("T1530", "T1552.001"),
                        "moderate",
                    ))
        except Exception:
            continue
    return paths
