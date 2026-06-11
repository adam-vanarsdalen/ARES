"""Tests for deterministic enterprise attack path reasoning."""

from tools.attack_graph import build_identity_node
from utils.attack_path_reasoning import compute_lateral_movement_paths


def test_identity_without_mfa_and_admin_panel_produces_path():
    identity = build_identity_node("admin", "form_auth", False)
    admin_panel = {
        "id": "finding:admin",
        "kind": "exposed_admin_panel",
        "label": "Exposed admin panel",
        "severity": "HIGH",
        "technique_id": "T1133",
    }
    paths = compute_lateral_movement_paths([identity, admin_panel])
    assert paths
    assert paths[0]["path_name"] == "Credential Stuffing to Admin Access"


def test_empty_node_list_returns_empty_paths():
    assert compute_lateral_movement_paths([]) == []


def test_malformed_input_never_raises():
    assert compute_lateral_movement_paths([None, "bad", {}, {"data": "bad"}]) == []
