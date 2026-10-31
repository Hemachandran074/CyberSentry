"""Unit tests for per-entity behavioural profiles (FR-6)."""
import numpy as np
import pytest
from cybersentry_ml.baselines import profile


def events_for(n=200, hour=9, host="host-a", action="logon"):
    return [
        {
            "ts": 1_700_000_000 + i * 600,
            "hour": hour,
            "dst_host": host,
            "action": action,
            "object": "svc",
        }
        for i in range(n)
    ]


def test_an_entity_with_too_little_history_gets_no_baseline():
    p = profile.build(events_for(10))
    assert p["sufficient"] is False
    assert "too little history" in p["reason"]
    with pytest.raises(ValueError, match="cannot vectorise an insufficient profile"):
        profile.vector(p)


def test_a_never_seen_value_is_rare_not_impossible():
    p = profile.build(events_for(200))
    assert p["sufficient"] is True
    seen = profile.surprisal("host-a", p["hosts"])
    unseen = profile.surprisal("host-zzz", p["hosts"])
    assert unseen > seen
    assert np.isfinite(unseen)  # Laplace smoothing ensures finite surprisal


def test_the_behaviour_vector_compares_shape_not_volume():
    quiet = profile.build(events_for(60))
    busy = profile.build(events_for(600))
    # same behavioural distribution across hours, hosts, actions:
    # vectors should be very close despite 10x event volume
    vec_quiet = profile.vector(quiet)
    vec_busy = profile.vector(busy)
    assert len(vec_quiet) == 32
    assert len(vec_busy) == 32
    assert np.linalg.norm(vec_quiet - vec_busy) < 0.3


def test_profile_field_extraction_with_dst_fallback():
    events = [
        {"ts": 1_700_000_000 + i * 100, "hour": 14, "dst": "192.168.1.10", "action": "connect", "object": "port_443"}
        for i in range(60)
    ]
    p = profile.build(events)
    assert p["sufficient"] is True
    assert "192.168.1.10" in p["hosts"]
    assert p["hours"]["14"] == 60
    assert profile.vector(p).shape == (32,)
