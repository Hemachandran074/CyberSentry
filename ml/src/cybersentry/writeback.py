"""Champion model inference writeback into Milestone 1 database schema.

Scores test partition authentication events using the active production 'champion'
model, stores predictions in the auditable ml_predictions table, backfills the
risk_score and model_version columns in auth_events, and creates alerts entries
for events flagged within the tier-1 triage budget.
"""

from __future__ import annotations

import json
from typing import Any
import joblib
import mlflow
import numpy as np
import pandas as pd
from sqlalchemy import text

from . import db, tracking
from .baseline import RuleEngine
from .config import ARTIFACTS, MLFLOW_URI, MODEL_NAME, PROCESSED, load_cfg
from .evaluate import budget_mask
from .features import build_features

ENTITY = "CS-E-{}"

FILL_SQL = """
UPDATE auth_events e
SET risk_score    = p.score,
    model_version = p.model_version
FROM ml_predictions p
WHERE p.model_name = :model AND e.event_ref = p.entity_id
"""

ALERT_SQL = """
INSERT INTO alerts (event_ref, layer, score, techniques, evidence, model_version)
SELECT p.entity_id, 'model', p.score,
       ARRAY['T1110','T1021'], CAST(:evidence AS JSONB), p.model_version
FROM ml_predictions p
WHERE p.model_name = :model AND p.entity_id = :ref AND p.label = 'alert'
ON CONFLICT DO NOTHING
"""

ENSURE_TABLES_SQL = """
CREATE TABLE IF NOT EXISTS auth_events (
    event_ref     TEXT PRIMARY KEY,
    step          TEXT,
    src_user      TEXT,
    src_comp      TEXT,
    dst_comp      TEXT,
    auth_type     TEXT,
    outcome       TEXT,
    risk_score    DOUBLE PRECISION,
    model_version TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id      BIGSERIAL PRIMARY KEY,
    event_ref     TEXT,
    layer         TEXT,
    score         DOUBLE PRECISION,
    techniques    TEXT[],
    evidence      JSONB,
    model_version TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"""


def main() -> None:
    """Execute prediction writeback for champion model over the test partition."""
    cfg = load_cfg()
    triage_budget = float(cfg.get("triage_budget", 0.01))

    try:
        label, run_id = tracking.champion()
    except Exception:
        label = f"{MODEL_NAME}:v1"
        run_id = tracking.load_run_id()

    try:
        mlflow.set_tracking_uri(MLFLOW_URI)
        artifact_local_path = mlflow.artifacts.download_artifacts(
            run_id=run_id, artifact_path="bundle/model.joblib"
        )
        bundle = joblib.load(artifact_local_path)
    except Exception:
        bundle = joblib.load(ARTIFACTS / "model.joblib")

    clf = bundle["clf"]
    feature_cols = bundle["features"]

    dataset_file = PROCESSED / "dataset.parquet"
    raw_df = pd.read_parquet(dataset_file)
    df = build_features(raw_df)

    test_data = df[df.split == "test"].reset_index(drop=True)
    scores = clf.predict_proba(test_data[feature_cols])[:, 1]
    flagged = budget_mask(scores, triage_budget)

    # Evaluate co-firing rules to attach as contextual evidence
    rules = RuleEngine.fired(test_data)
    rule_names = np.array(rules.columns)

    predictions_df = pd.DataFrame({
        "entity_id": test_data.event_id.map(ENTITY.format),
        "step": test_data.step.astype(str),
        "score": scores,
        "label": np.where(flagged, "alert", "ok"),
    })
    predictions_df["extra"] = [
        {"rules": rule_names[row_mask].tolist()} for row_mask in rules.values
    ]

    # Ensure schema prerequisites exist
    try:
        db.run_sql(ENSURE_TABLES_SQL)
    except Exception as exc:
        print(f"Notice: schema ensure skipped ({exc})")

    # If auth_events is empty, seed it with the test partition's unlabelled events
    try:
        existing_count = db.scalar(
            "SELECT count(*) FROM auth_events WHERE event_ref LIKE 'CS-E-%'"
        )
        if not existing_count or existing_count == 0:
            seed_records = [
                {
                    "event_ref": ENTITY.format(r.event_id),
                    "step": str(r.step),
                    "src_user": str(r.src_user),
                    "src_comp": str(r.src_comp),
                    "dst_comp": str(r.dst_comp),
                    "auth_type": str(r.auth_type),
                    "outcome": str(r.outcome),
                }
                for r in test_data.itertuples()
            ]
            insert_auth_stmt = text("""
                INSERT INTO auth_events (event_ref, step, src_user, src_comp, dst_comp, auth_type, outcome)
                VALUES (:event_ref, :step, :src_user, :src_comp, :dst_comp, :auth_type, :outcome)
                ON CONFLICT (event_ref) DO NOTHING
            """)
            with db.engine().begin() as cx:
                for idx in range(0, len(seed_records), 1000):
                    cx.execute(insert_auth_stmt, seed_records[idx : idx + 1000])
    except Exception as exc:
        print(f"Notice: auth_events seeding skipped ({exc})")

    stored_predictions_count = db.upsert_predictions(predictions_df, MODEL_NAME, label)
    filled_events_count = db.run_sql(FILL_SQL, model=MODEL_NAME)

    opened_alerts_count = 0
    flagged_entities = predictions_df.loc[flagged, "entity_id"]
    flagged_extras = predictions_df.loc[flagged, "extra"]

    for ref, extra in zip(flagged_entities, flagged_extras):
        opened_alerts_count += db.run_sql(
            ALERT_SQL,
            model=MODEL_NAME,
            ref=ref,
            evidence=json.dumps(extra),
        )

    print(
        f"{stored_predictions_count} scores stored as {label}; "
        f"{filled_events_count} auth_events filled; "
        f"{opened_alerts_count} alerts opened"
    )


if __name__ == "__main__":
    main()
