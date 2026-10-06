"""Unit tests for CyberSentry severity ranking, adjustment, and compound risk scoring."""

from datetime import datetime, timezone
import pytest

from libs.sentry_domain.models import Detection
from libs.sentry_domain.severity import (
    CorrelationError,
    adjust_severity,
    max_severity,
    risk_score,
    severity_rank,
)

T0 = datetime(2026, 9, 11, 10, 0, 0, tzinfo=timezone.utc)


def _make_det(
    det_id: str = "D1", rule: str = "DR001", sev: str = "medium", host: str = "HOST-001"
) -> Detection:
    return Detection(
        detection_id=det_id,
        rule_code=rule,
        detected_at=T0,
        severity=sev,
        host_id=host,
    )


def test_severity_ordering():
    assert severity_rank("info") < severity_rank("low") < severity_rank("medium")
    assert severity_rank("medium") < severity_rank("high") < severity_rank("critical")


def test_unknown_severity_rank_raises():
    with pytest.raises(CorrelationError, match="Unknown severity level"):
        severity_rank("urgent")


def test_max_severity_selection():
    assert max_severity(["info", "high", "medium"]) == "high"
    assert max_severity(["critical", "low"]) == "critical"


def test_max_severity_empty_sequence_raises():
    with pytest.raises(CorrelationError, match="empty sequence"):
        max_severity([])


def test_adjust_severity_crown_jewel():
    # medium (rank 2) + 2 -> critical (rank 4)
    assert adjust_severity("medium", asset_criticality="crown_jewel") == "critical"
    # low (rank 1) + 2 -> high (rank 3)
    assert adjust_severity("low", asset_criticality="crown_jewel") == "high"


def test_adjust_severity_high_criticality():
    # low (rank 1) + 1 -> medium (rank 2)
    assert adjust_severity("low", asset_criticality="high") == "medium"
    # high (rank 3) + 1 -> critical (rank 4)
    assert adjust_severity("high", asset_criticality="high") == "critical"


def test_adjust_severity_internet_facing_bonus():
    # medium (rank 2) + internet-facing (+1) -> high (rank 3)
    assert adjust_severity("medium", asset_criticality="medium", is_internet_facing=True) == "high"
    # high (rank 3) + high (+1) + internet-facing (+1) -> critical (capped)
    assert adjust_severity("high", asset_criticality="high", is_internet_facing=True) == "critical"


def test_adjust_severity_clamped_at_critical():
    assert adjust_severity("critical", asset_criticality="crown_jewel", is_internet_facing=True) == "critical"


def test_adjust_severity_never_lowered():
    # low criticality multiplier (0.8) should never lower base severity level
    assert adjust_severity("high", asset_criticality="low") == "high"
    assert adjust_severity("critical", asset_criticality="low") == "critical"


def test_adjust_severity_invalid_criticality():
    with pytest.raises(CorrelationError, match="Unknown asset criticality"):
        adjust_severity("medium", asset_criticality="unranked")


def test_risk_score_max_not_sum():
    # 20 low detections: base=20, distinct_rules=1 -> corroboration=0, score=20
    many_low = [_make_det(f"D{i}", "DR001", "low") for i in range(20)]
    # 1 critical detection: base=90, score=90
    one_critical = [_make_det("DC", "DR003", "critical")]

    assert risk_score(one_critical) > risk_score(many_low)


def test_risk_score_corroboration_increases():
    # Single high rule: base 70
    single = [_make_det("D1", "DR001", "high")]
    # Two distinct high rules: base 70 + 5 = 75
    two_rules = [_make_det("D1", "DR001", "high"), _make_det("D2", "DR002", "high")]
    # Three distinct high rules: base 70 + 10 = 80
    three_rules = two_rules + [_make_det("D3", "DR003", "high")]

    score_1 = risk_score(single)
    score_2 = risk_score(two_rules)
    score_3 = risk_score(three_rules)

    assert score_1 == 70
    assert score_2 == 75
    assert score_3 == 80


def test_risk_score_corroboration_caps_at_15():
    # 6 distinct rules: corroboration = min(15, (6 - 1) * 5) = 15
    dets = [_make_det(f"D{i}", f"DR00{i}", "medium") for i in range(1, 7)]
    # base=45, corroboration=15 -> 60
    assert risk_score(dets, asset_criticality="medium") == 60


def test_risk_score_asset_criticality_multipliers():
    dets = [_make_det("D1", "DR001", "medium")]  # base 45
    assert risk_score(dets, "low") == round(45 * 0.8)     # 36
    assert risk_score(dets, "medium") == 45               # 45
    assert risk_score(dets, "high") == round(45 * 1.2)    # 54
    assert risk_score(dets, "crown_jewel") == round(45 * 1.5)  # 68


def test_risk_score_clamped_to_100():
    # critical (90) + max corroboration (15) = 105 * 1.5 (crown_jewel) = 157.5 -> clamp to 100
    dets = [_make_det(f"D{i}", f"DR00{i}", "critical") for i in range(1, 5)]
    assert risk_score(dets, "crown_jewel") == 100


def test_risk_score_empty_raises():
    with pytest.raises(CorrelationError, match="empty incident"):
        risk_score([])


def test_risk_score_invalid_criticality_raises():
    dets = [_make_det("D1", "DR001", "medium")]
    with pytest.raises(CorrelationError, match="Unknown asset criticality"):
        risk_score(dets, asset_criticality="extreme")
