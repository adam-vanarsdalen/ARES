from utils.scorecard import build_executive_scorecard


def _recon(findings):
    return {
        "critical_findings": [],
        "high_findings": findings,
        "medium_findings": [],
        "asset_inventory": [{"asset_id": "asset:1", "notable_findings_count": len(findings)}],
    }


def test_empty_run_is_handled():
    scorecard = build_executive_scorecard({}, _recon([]), {}, {})
    assert set(scorecard["metrics"]) == {
        "exposure_score",
        "evidence_quality_score",
        "exploitability_score",
        "control_coverage_score",
        "remediation_urgency",
        "vdp_reportability_score",
        "scope_confidence_score",
        "false_positive_risk",
    }
    assert scorecard["asset_exposure_summary"]["active_findings"] == 0


def test_confirmed_findings_increase_exposure_score():
    base = {
        "title": "High finding",
        "severity": "HIGH",
        "lifecycle_state": "new",
        "confidence_class": "strong_indicator",
        "reportability_score": 70,
    }
    unconfirmed = build_executive_scorecard({}, _recon([dict(base)]), {}, {})
    confirmed = build_executive_scorecard({}, _recon([{
        **base,
        "lifecycle_state": "confirmed",
        "confidence_class": "confirmed",
    }]), {}, {})
    assert confirmed["metrics"]["exposure_score"] > unconfirmed["metrics"]["exposure_score"]


def test_strong_evidence_increases_evidence_quality():
    weak = {"title": "Finding", "severity": "MEDIUM", "lifecycle_state": "new"}
    strong = {
        **weak,
        "evidence_refs": ["evidence:1"],
        "reproduction_steps": ["Repeat request."],
    }
    weak_score = build_executive_scorecard({}, _recon([weak]), {}, {})["metrics"]["evidence_quality_score"]
    strong_score = build_executive_scorecard(
        {},
        _recon([strong]),
        {"evidence_ledger": [{"evidence_id": "evidence:1"}]},
        {},
    )["metrics"]["evidence_quality_score"]
    assert strong_score > weak_score


def test_false_positives_lower_active_risk_counts():
    finding = {
        "title": "High finding",
        "severity": "HIGH",
        "lifecycle_state": "confirmed",
        "confidence_class": "confirmed",
        "reportability_score": 90,
    }
    active = build_executive_scorecard({}, _recon([dict(finding)]), {}, {})
    false_positive = build_executive_scorecard({}, _recon([{
        **finding,
        "lifecycle_state": "false_positive",
    }]), {}, {})
    assert false_positive["metrics"]["exposure_score"] < active["metrics"]["exposure_score"]
    assert false_positive["asset_exposure_summary"]["active_findings"] == 0
