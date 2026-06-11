"""Tests for documentation-only APT lab scenarios."""

from tools.lab_simulation import load_apt_scenarios, run_apt_scenario


def test_loads_both_apt_scenarios():
    scenarios = load_apt_scenarios()
    assert {"APT29", "APT41"} <= scenarios.keys()
    assert scenarios["APT29"]["also_known_as"] == "Cozy Bear"


def test_non_lab_target_is_refused():
    result = run_apt_scenario("APT29", "https://example.com")
    assert result["status"] == "not_lab_target"


def test_unknown_actor_is_reported():
    result = run_apt_scenario("Unknown Actor", "http://127.0.0.1:8080")
    assert result["status"] == "unknown_actor"
