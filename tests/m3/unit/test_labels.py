"""Unit tests for label isolation and entity-wise splitting (FR-1, FR-7)."""
import pytest
from cybersentry_ml import labels as L


def test_a_detection_query_cannot_touch_the_label_table():
    safe = "SELECT entity_id, ts, action FROM events WHERE ts > now() - '1h'"
    assert L.detection_query(safe) == safe
    for bad in (
        "SELECT e.* FROM events e JOIN ground_truth_labels g ON g.event_id = e.id",
        "SELECT is_attack FROM events",
        "select scenario from events",
        "SELECT * FROM events WHERE technique_truth IS NOT NULL",
    ):
        with pytest.raises(L.LabelLeak):
            L.detection_query(bad)


def test_attack_free_training_data_is_an_explicit_named_step():
    events = [{"id": i, "action": f"act_{i}"} for i in range(5)]
    clean = L.attack_free(events, [1, 3])
    assert [e["id"] for e in clean] == [0, 2, 4]


def test_entity_split_is_hash_stable():
    ids = [f"user-{i}" for i in range(200)]
    a = L.split_entities(ids)
    assert a == L.split_entities(ids)
    share = sum(v == "val" for v in a.values()) / len(ids)
    assert 0.12 < share < 0.28


def test_entity_split_with_salt():
    ids = [f"user-{i}" for i in range(50)]
    split1 = L.split_entities(ids, salt="experiment-1")
    split2 = L.split_entities(ids, salt="experiment-2")
    # Same inputs with different salts yield deterministic mappings for each salt
    assert split1 == L.split_entities(ids, salt="experiment-1")
    assert split2 == L.split_entities(ids, salt="experiment-2")
