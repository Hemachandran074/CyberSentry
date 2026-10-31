"""Unit tests for behaviour-based peer clustering (FR-6)."""
import numpy as np
from cybersentry_ml.baselines import peers


def test_peer_clusters_below_the_minimum_size_are_dissolved():
    rng = np.random.default_rng(0)
    big = rng.normal(0, 0.01, (40, 6))
    odd = rng.normal(5, 0.01, (2, 6))
    ids = [f"e{i}" for i in range(42)]
    model = peers.fit(np.vstack([big, odd]), ids, k=3, min_cluster_size=8)
    assert model["assignments"]["e40"] == -1 and model["assignments"]["e41"] == -1
    assert model["singletons"] == 2


def test_a_singleton_scores_none_rather_than_zero():
    model = {"centroids": {"0": [0.0, 0.0]}, "assignments": {}}
    out = peers.deviation([5.0, 5.0], -1, model)
    assert out["peer_z"] is None and "no peer group" in out["reason"]
    scored = peers.deviation([5.0, 5.0], 0, model)
    assert scored["peer_z"] is not None and scored["peer_z"] > 0


def test_peer_deviation_is_comparable_across_tight_and_loose_clusters():
    rng = np.random.default_rng(1)
    tight = rng.normal(0, 0.05, (20, 4))
    loose = rng.normal(10, 2.0, (20, 4))
    X = np.vstack([tight, loose])
    ids = [f"e{i}" for i in range(40)]
    model = peers.with_spreads(peers.fit(X, ids, k=2, min_cluster_size=5), X, ids)
    assert set(model["spreads"]) == set(model["centroids"])
    c_tight = model["assignments"]["e0"]
    c_loose = model["assignments"]["e39"]
    # a point one cluster-spread away scores about the same z in either cluster
    z_t = peers.deviation(
        np.asarray(model["centroids"][str(c_tight)]) + model["spreads"][str(c_tight)],
        c_tight,
        model,
    )["peer_z"]
    z_l = peers.deviation(
        np.asarray(model["centroids"][str(c_loose)]) + model["spreads"][str(c_loose)],
        c_loose,
        model,
    )["peer_z"]
    assert 0.3 < z_t / z_l < 3.0


def test_fewer_than_k_entities_yields_no_clusters():
    vectors = [[1.0, 2.0], [3.0, 4.0]]
    ids = ["ent1", "ent2"]
    model = peers.fit(vectors, ids, k=5)
    assert model["k"] == 0
    assert model["assignments"]["ent1"] == -1
    assert model["assignments"]["ent2"] == -1
    assert model["singletons"] == 2
