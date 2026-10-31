"""Peer groups (FR-6).

Self-history alone cannot catch a compromised account that was ALWAYS odd, nor
a brand-new one. Peers answer the complementary question: is this normal for
entities that behave like this one? Clustering is on behaviour, never on the
directory - two "finance analysts" can do entirely different jobs, and an
attacker who compromises one is not caught by comparing them to a job title.
"""
from __future__ import annotations

from typing import Any, Mapping, Sequence
import numpy as np

MIN_CLUSTER_SIZE = 8
DEFAULT_K = 8


def fit(
    vectors: Sequence[Sequence[float]] | np.ndarray,
    entity_ids: Sequence[Any],
    k: int = DEFAULT_K,
    seed: int = 42,
    min_cluster_size: int = MIN_CLUSTER_SIZE,
) -> dict[str, Any]:
    """k-means on behaviour vectors. Clusters smaller than min_cluster_size are
    dissolved into a reserved 'singleton' group (-1): comparing an entity to two
    peers is not a peer comparison, it is noise with a cluster id.
    """
    from sklearn.cluster import KMeans

    X = np.asarray(vectors, dtype=float)
    if len(X) < k:
        return {
            "assignments": {str(e): -1 for e in entity_ids},
            "centroids": {},
            "k": 0,
            "singletons": len(entity_ids),
            "sizes": {},
            "note": f"{len(X)} entities (< k={k}) - no peer groups",
        }

    km = KMeans(n_clusters=k, random_state=seed, n_init=10).fit(X)
    labels = km.labels_.tolist()
    sizes = {c: labels.count(c) for c in set(labels)}

    # Dissolve clusters smaller than min_cluster_size into -1 (singletons)
    final = [c if sizes[c] >= min_cluster_size else -1 for c in labels]

    centroids = {
        str(c): X[np.array(final) == c].mean(axis=0).tolist()
        for c in set(final)
        if c != -1
    }

    return {
        "assignments": {str(e): int(c) for e, c in zip(entity_ids, final)},
        "centroids": centroids,
        "k": len(centroids),
        "singletons": sum(1 for c in final if c == -1),
        "sizes": {str(c): final.count(c) for c in set(final)},
    }


def _fallback_spread(v: np.ndarray, centroid: np.ndarray) -> float:
    """Fallback spread estimation if within-cluster spread is zero or missing."""
    return float(max(np.linalg.norm(centroid), 1e-3))


def with_spreads(
    model: Mapping[str, Any],
    vectors: Sequence[Sequence[float]] | np.ndarray,
    entity_ids: Sequence[Any],
) -> dict[str, Any]:
    """Second pass: per-cluster distance spread, so deviation() is comparable
    across clusters. Computed once at fit time and stored with the model.
    """
    X = np.asarray(vectors, dtype=float)
    spreads: dict[str, float] = {}

    centroids = model.get("centroids", {})
    assignments = model.get("assignments", {})

    for key, centroid in centroids.items():
        cluster_id = int(key)
        members = [
            X[i]
            for i, e in enumerate(entity_ids)
            if assignments.get(str(e)) == cluster_id
        ]
        if members:
            d = np.linalg.norm(np.asarray(members) - np.asarray(centroid), axis=1)
            spread_val = float(np.std(d) or np.mean(d) or 1e-3)
            spreads[key] = spread_val

    return {**model, "spreads": spreads}


def deviation(
    vector: Sequence[float] | np.ndarray,
    cluster_id: int,
    model: Mapping[str, Any],
) -> dict[str, Any]:
    """Distance from the peer centroid, scaled by the cluster's own spread so a
    tight cluster and a loose one are comparable. A singleton returns None, not
    zero - no peer evidence is not evidence of normality.
    """
    key = str(int(cluster_id))
    centroids = model.get("centroids", {})

    if cluster_id == -1 or key not in centroids:
        return {
            "peer_z": None,
            "cluster": int(cluster_id),
            "reason": "no peer group - scored on self-history only",
        }

    centroid = np.asarray(centroids[key], dtype=float)
    v = np.asarray(vector, dtype=float)
    distance = float(np.linalg.norm(v - centroid))

    spread = float(model.get("spreads", {}).get(key, 0.0)) or _fallback_spread(v, centroid)
    peer_z = distance / max(spread, 1e-6)

    return {
        "peer_z": peer_z,
        "cluster": int(cluster_id),
        "distance": distance,
        "reason": "scored against peer group",
    }
