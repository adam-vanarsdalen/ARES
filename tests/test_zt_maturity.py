"""Tests for DoD Zero Trust maturity scoring."""

from utils.scorecard import build_executive_scorecard
from utils.zt_maturity import ZT_PILLARS, _maturity_level, compute_zt_maturity


def test_exposed_secret_increases_data_pillar():
    result = compute_zt_maturity(
        [{"title": "Exposed secret in JavaScript"}],
        [],
    )
    assert result["pillar_scores"]["data"] >= 35


def test_no_findings_produce_zero_scores():
    result = compute_zt_maturity([], [])
    assert result["pillar_scores"] == {pillar: 0 for pillar in ZT_PILLARS}
    assert result["overall_zt_risk"] == 0


def test_maturity_level_ranges():
    assert _maturity_level(25) == "target"
    assert _maturity_level(50) == "advanced"
    assert _maturity_level(75) == "basic"
    assert _maturity_level(100) == "traditional"


def test_scorecard_contains_zt_maturity():
    scorecard = build_executive_scorecard(
        {},
        {
            "critical_findings": [],
            "high_findings": [],
            "medium_findings": [],
            "asset_inventory": [],
        },
        {},
        {},
    )
    assert "zt_maturity" in scorecard
    assert scorecard["metrics"]["zt_overall_risk"] == 0
