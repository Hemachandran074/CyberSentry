"""Unit tests for CyberSentry deduplication keys and temporal entity correlation."""

from datetime import datetime, timedelta, timezone
import random
import pytest

from libs.sentry_domain.correlation import (
    CorrelationError,
    Correlator,
    Detection,
    dedup_key,
    primary_entity,
)

BASE_TIME = datetime(2026, 9, 11, 12, 0, 0, tzinfo=timezone.utc)


def _d(
    det_id: str,
    minutes_offset: int,
    rule: str = "DR001",
    sev: str = "medium",
    host: str | None = "HOST-001",
    user: str | None = None,
    ip: str | None = None,
) -> Detection:
    return Detection(
        detection_id=det_id,
        rule_code=rule,
        detected_at=BASE_TIME + timedelta(minutes=minutes_offset),
        severity=sev,
        host_id=host,
        user_name=user,
        source_ip=ip,
    )


def test_dedup_key_collapses_within_window():
    k1 = dedup_key("DR001", "HOST-001", BASE_TIME, window_minutes=15)
    k2 = dedup_key("DR001", "HOST-001", BASE_TIME + timedelta(minutes=10), window_minutes=15)
    assert k1 == k2


def test_dedup_key_separates_across_windows():
    k1 = dedup_key("DR001", "HOST-001", BASE_TIME, window_minutes=15)
    k2 = dedup_key("DR001", "HOST-001", BASE_TIME + timedelta(minutes=20), window_minutes=15)
    assert k1 != k2


def test_dedup_key_zero_or_negative_window_raises():
    with pytest.raises(CorrelationError, match="positive"):
        dedup_key("DR001", "HOST-001", BASE_TIME, window_minutes=0)
    with pytest.raises(CorrelationError, match="positive"):
        dedup_key("DR001", "HOST-001", BASE_TIME, window_minutes=-5)


def test_primary_entity_precedence():
    # host_id has top priority
    d_all = Detection("D1", "DR001", BASE_TIME, "low", host_id="H1", user_name="U1", source_ip="10.0.0.1")
    assert primary_entity(d_all) == ("H1", "host")

    # identity has second priority
    d_user_ip = Detection("D2", "DR001", BASE_TIME, "low", user_name="U1", source_ip="10.0.0.1")
    assert primary_entity(d_user_ip) == ("U1", "identity")

    # source_ip has third priority
    d_ip = Detection("D3", "DR001", BASE_TIME, "low", source_ip="10.0.0.1")
    assert primary_entity(d_ip) == ("10.0.0.1", "source_ip")


def test_primary_entity_missing_entity_raises():
    d_none = Detection("D0", "DR001", BASE_TIME, "low")
    with pytest.raises(CorrelationError, match="does not specify any correlatable entity"):
        primary_entity(d_none)


def test_correlator_within_window_merges_single_incident():
    correlator = Correlator(window=timedelta(minutes=60))
    detections = [
        _d("D1", 0, "DR001", "low"),
        _d("D2", 25, "DR002", "medium"),
        _d("D3", 50, "DR003", "high"),
    ]
    incidents = correlator.correlate(detections)

    assert len(incidents) == 1
    inc = incidents[0]
    assert inc.primary_entity == "HOST-001"
    assert len(inc.detections) == 3
    assert inc.window_start == detections[0].detected_at
    assert inc.window_end == detections[2].detected_at


def test_correlator_boundary_gap_exactly_equal_window():
    # Gap exactly 60 minutes should remain in the same incident (gap <= window)
    correlator = Correlator(window=timedelta(minutes=60))
    detections = [_d("D1", 0), _d("D2", 60)]
    incidents = correlator.correlate(detections)

    assert len(incidents) == 1
    assert len(incidents[0].detections) == 2


def test_correlator_gap_split():
    # Gap of 75 minutes exceeds window of 60 minutes -> splits into 2 incidents
    correlator = Correlator(window=timedelta(minutes=60))
    detections = [_d("D1", 0), _d("D2", 75)]
    incidents = correlator.correlate(detections)

    assert len(incidents) == 2
    assert len(incidents[0].detections) == 1
    assert len(incidents[1].detections) == 1


def test_correlator_different_entities_never_merge():
    correlator = Correlator(window=timedelta(minutes=60))
    detections = [
        _d("D1", 0, host="HOST-001"),
        _d("D2", 10, host="HOST-002"),
    ]
    incidents = correlator.correlate(detections)

    assert len(incidents) == 2
    entities = {inc.primary_entity for inc in incidents}
    assert entities == {"HOST-001", "HOST-002"}


def test_correlator_risk_ordered_output():
    correlator = Correlator(
        window=timedelta(minutes=60),
        asset_criticality={"HOST-CRIT": "crown_jewel", "HOST-LOW": "low"},
    )
    detections = [
        _d("D1", 0, sev="low", host="HOST-LOW"),
        _d("D2", 5, sev="critical", host="HOST-CRIT"),
    ]
    incidents = correlator.correlate(detections)

    # Higher risk must come first
    assert len(incidents) == 2
    assert incidents[0].primary_entity == "HOST-CRIT"
    assert incidents[1].primary_entity == "HOST-LOW"
    assert incidents[0].risk_score > incidents[1].risk_score


def test_correlator_input_order_independence():
    correlator = Correlator(window=timedelta(minutes=60))
    detections = [
        _d("D1", 0, "DR001"),
        _d("D2", 15, "DR002"),
        _d("D3", 30, "DR003"),
        _d("D4", 100, "DR001"),
    ]

    shuffled = list(detections)
    random.Random(42).shuffle(shuffled)

    res_in_order = correlator.correlate(detections)
    res_shuffled = correlator.correlate(shuffled)

    assert len(res_in_order) == len(res_shuffled)
    for inc_a, inc_b in zip(res_in_order, res_shuffled):
        assert inc_a.primary_entity == inc_b.primary_entity
        assert inc_a.risk_score == inc_b.risk_score
        assert [d.detection_id for d in inc_a.detections] == [d.detection_id for d in inc_b.detections]


def test_correlator_zero_window_raises():
    with pytest.raises(CorrelationError, match="positive"):
        Correlator(window=timedelta(0)).correlate([_d("D1", 0)])


def test_correlator_single_detection_incident():
    correlator = Correlator(window=timedelta(minutes=60))
    d = _d("D1", 0, "DR001", "high")
    incidents = correlator.correlate([d])

    assert len(incidents) == 1
    assert incidents[0].window_start == d.detected_at
    assert incidents[0].window_end == d.detected_at
    assert len(incidents[0].detections) == 1