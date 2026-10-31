"""Scheduled job to fit and version per-entity behavioural profiles and peer groups (FR-6).

Reads the rolling window of events through label-isolated queries, builds individual
profiles, clusters sufficient behaviour vectors into peer models with spread-scaled
deviation metrics, and appends new immutable versioned rows to baselines and peer_models.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
from typing import Any, Mapping, Sequence
import uuid
import numpy as np
import yaml

from cybersentry_ml import labels
from cybersentry_ml.baselines import peers, profile


def load_params(config_path: str | Path = "params.yaml") -> dict[str, Any]:
    """Load baseline fitting parameters from params.yaml."""
    p = Path(config_path)
    if not p.exists():
        return {
            "window_days": 30,
            "min_events": 50,
            "laplace": 1.0,
            "peer_k": 8,
            "min_cluster_size": 8,
            "seed": 42,
        }
    with open(p, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
        return data.get("baselines", {})


def run_fit(
    events_by_entity: Mapping[str, Sequence[Mapping[str, Any]]],
    params: Mapping[str, Any] | None = None,
    window_start: datetime | None = None,
    window_end: datetime | None = None,
) -> dict[str, Any]:
    """Fit profiles and peer models from a dictionary of entity events.

    Pure functional pipeline independent of database state for deterministic testing.
    """
    if params is None:
        params = load_params()

    min_events = int(params.get("min_events", 50))
    peer_k = int(params.get("peer_k", 8))
    min_cluster_size = int(params.get("min_cluster_size", 8))
    seed = int(params.get("seed", 42))

    if window_end is None:
        window_end = datetime.now(timezone.utc)
    if window_start is None:
        window_days = int(params.get("window_days", 30))
        window_start = window_end - timedelta(days=window_days)

    entity_ids = list(events_by_entity.keys())
    profiles: dict[str, dict[str, Any]] = {}
    vectors: dict[str, np.ndarray] = {}

    sufficient_ids: list[str] = []
    sufficient_vectors: list[np.ndarray] = []

    for eid, evts in events_by_entity.items():
        p = profile.build(evts, min_events=min_events)
        profiles[eid] = p
        if p["sufficient"]:
            v = profile.vector(p)
            vectors[eid] = v
            sufficient_ids.append(eid)
            sufficient_vectors.append(v)
        else:
            vectors[eid] = np.zeros(32, dtype=float)

    # Fit peer clusters over sufficient entities
    if len(sufficient_ids) >= peer_k:
        peer_model = peers.fit(
            sufficient_vectors,
            sufficient_ids,
            k=peer_k,
            seed=seed,
            min_cluster_size=min_cluster_size,
        )
        peer_model = peers.with_spreads(peer_model, sufficient_vectors, sufficient_ids)
    else:
        peer_model = {
            "assignments": {str(e): -1 for e in sufficient_ids},
            "centroids": {},
            "spreads": {},
            "k": 0,
            "singletons": len(sufficient_ids),
            "sizes": {},
        }

    # Assign peer clusters to all entities
    assignments = peer_model.get("assignments", {})
    entity_records: list[dict[str, Any]] = []

    for eid in entity_ids:
        p = profiles[eid]
        c = assignments.get(str(eid), -1) if p["sufficient"] else -1
        entity_records.append(
            {
                "entity_id": eid,
                "profile": p,
                "behaviour_vector": vectors[eid].tolist(),
                "peer_cluster": int(c),
                "sufficient": bool(p["sufficient"]),
                "window_start": window_start,
                "window_end": window_end,
            }
        )

    n_total = len(entity_ids)
    n_suff = len(sufficient_ids)
    n_insuff = n_total - n_suff

    return {
        "entity_records": entity_records,
        "peer_model": peer_model,
        "n_total": n_total,
        "n_sufficient": n_suff,
        "n_insufficient": n_insuff,
        "window_start": window_start,
        "window_end": window_end,
    }


def main() -> None:
    """Execute baseline fitting from PostgreSQL or generate local artifacts."""
    params = load_params()
    window_days = int(params.get("window_days", 30))
    window_end = datetime.now(timezone.utc)
    window_start = window_end - timedelta(days=window_days)

    db_url = os.getenv("DATABASE_URL")
    events_by_entity: dict[str, list[dict[str, Any]]] = {}

    if db_url:
        import sqlalchemy as sa

        eng = sa.create_engine(db_url)
        # Verify query safety against evaluation label tables
        entities_sql = labels.detection_query("SELECT id FROM entities")
        events_sql = labels.detection_query(
            """
            SELECT entity_id, ts, action, object, dst, dst_host, hour
            FROM events
            WHERE ts >= :window_start AND ts <= :window_end
            ORDER BY ts ASC
            """
        )

        try:
            with eng.connect() as conn:
                for row in conn.execute(sa.text(entities_sql)):
                    events_by_entity[str(row[0])] = []
                for row in conn.execute(
                    sa.text(events_sql),
                    {"window_start": window_start, "window_end": window_end},
                ):
                    m = dict(row._mapping)
                    eid = str(m["entity_id"])
                    events_by_entity.setdefault(eid, []).append(m)
        except Exception as e:
            print(f"[fit_baselines] Database access failed ({e}); proceeding with local state")

    fit_res = run_fit(
        events_by_entity,
        params=params,
        window_start=window_start,
        window_end=window_end,
    )

    n_total = fit_res["n_total"]
    n_suff = fit_res["n_sufficient"]
    n_insuff = fit_res["n_insufficient"]
    pm = fit_res["peer_model"]
    k = pm.get("k", 0)
    singletons = pm.get("singletons", 0)

    print(f"# {n_total:,} entities | {n_suff:,} sufficient | {n_insuff:,} insufficient (< {params.get('min_events', 50)} events)")
    print(f"# peer model v1: k={k} clusters, {singletons} singletons")

    # Persist summary to report directory
    os.makedirs("reports", exist_ok=True)
    summary_path = Path("reports/m3_baselines_summary.json")
    summary_path.write_text(
        json.dumps(
            {
                "n_entities": n_total,
                "sufficient": n_suff,
                "insufficient": n_insuff,
                "k": k,
                "singletons": singletons,
                "window_days": window_days,
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    # Persist to PostgreSQL if connected
    if db_url and fit_res["entity_records"]:
        import sqlalchemy as sa

        eng = sa.create_engine(db_url)
        with eng.begin() as conn:
            max_p_ver = conn.execute(
                sa.text("SELECT COALESCE(MAX(version), 0) FROM peer_models")
            ).scalar()
            peer_ver = (max_p_ver or 0) + 1

            conn.execute(
                sa.text(
                    """
                    INSERT INTO peer_models (id, version, centroids, spreads, k, singletons, created_at)
                    VALUES (:id, :version, :centroids, :spreads, :k, :singletons, now())
                    """
                ),
                {
                    "id": uuid.uuid4(),
                    "version": peer_ver,
                    "centroids": json.dumps(pm.get("centroids", {})),
                    "spreads": json.dumps(pm.get("spreads", {})),
                    "k": pm.get("k", 0),
                    "singletons": pm.get("singletons", 0),
                },
            )

            max_b_ver = conn.execute(
                sa.text("SELECT COALESCE(MAX(version), 0) FROM baselines")
            ).scalar()
            base_ver = (max_b_ver or 0) + 1

            for rec in fit_res["entity_records"]:
                conn.execute(
                    sa.text(
                        """
                        INSERT INTO baselines (
                            entity_id, version, profile, behaviour_vector,
                            peer_cluster, sufficient, window_start, window_end, created_at
                        )
                        VALUES (
                            :entity_id, :version, :profile, :behaviour_vector,
                            :peer_cluster, :sufficient, :window_start, :window_end, now()
                        )
                        """
                    ),
                    {
                        "entity_id": rec["entity_id"],
                        "version": base_ver,
                        "profile": json.dumps(rec["profile"]),
                        "behaviour_vector": rec["behaviour_vector"],
                        "peer_cluster": rec["peer_cluster"],
                        "sufficient": rec["sufficient"],
                        "window_start": rec["window_start"],
                        "window_end": rec["window_end"],
                    },
                )


if __name__ == "__main__":
    main()
