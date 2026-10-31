"""Baselines, peer models and alert fusion columns against the real database.

Skipped without DATABASE_URL.
"""
import json
import os
import uuid
import pytest

pytestmark = pytest.mark.skipif(not os.getenv("DATABASE_URL"), reason="needs the stack")

import sqlalchemy as sa  # noqa: E402
from cybersentry_ml.labels import LabelLeak, detection_query  # noqa: E402


@pytest.fixture()
def entity():
    eng = sa.create_engine(os.environ["DATABASE_URL"])
    eid = uuid.uuid4()
    with eng.begin() as c:
        c.execute(
            sa.text(
                "INSERT INTO entities (id, kind, name, attrs, first_seen, last_seen) "
                "VALUES (:i, 'user', :n, :a, now(), now())"
            ),
            {
                "i": eid,
                "n": f"u{eid.hex[:8]}",
                "a": json.dumps({"criticality_tier": "high"}),
            },
        )
    yield eng, eid
    with eng.begin() as c:
        c.execute(sa.text("DELETE FROM baselines WHERE entity_id = :i"), {"i": eid})
        c.execute(sa.text("DELETE FROM entities WHERE id = :i"), {"i": eid})


def test_a_thin_entity_is_stored_as_insufficient_not_omitted(entity):
    eng, eid = entity
    with eng.begin() as c:
        c.execute(
            sa.text(
                """
                INSERT INTO baselines (entity_id, version, profile, behaviour_vector,
                                       peer_cluster, sufficient, window_start, window_end)
                VALUES (:i, 1, :p, :v, -1, false, now() - interval '30 days', now())
                """
            ),
            {
                "i": eid,
                "p": json.dumps({"sufficient": False, "n_events": 8}),
                "v": [0.0] * 32,
            },
        )
        row = c.execute(
            sa.text(
                "SELECT sufficient, peer_cluster FROM baselines WHERE entity_id = :i"
            ),
            {"i": eid},
        ).one()
    assert row.sufficient is False and row.peer_cluster == -1


def test_baselines_are_versioned_not_overwritten(entity):
    eng, eid = entity
    with eng.begin() as c:
        for v in (1, 2):
            c.execute(
                sa.text(
                    """
                    INSERT INTO baselines (entity_id, version, profile,
                                           behaviour_vector, peer_cluster, sufficient,
                                           window_start, window_end)
                    VALUES (:i, :v, '{}', :vec, 3, true,
                            now() - interval '30 days', now())
                    """
                ),
                {"i": eid, "v": v, "vec": [0.1] * 32},
            )
        n = c.execute(
            sa.text("SELECT count(*) FROM baselines WHERE entity_id = :i"),
            {"i": eid},
        ).scalar()
    assert n == 2


def test_the_leak_guard_is_wired_into_the_query_helper():
    assert detection_query("SELECT * FROM events LIMIT 1")
    with pytest.raises(LabelLeak):
        detection_query("SELECT * FROM events JOIN ground_truth_labels USING (id)")
