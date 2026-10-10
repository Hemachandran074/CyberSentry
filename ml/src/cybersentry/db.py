"""Database persistence and query helpers for Milestone 2 predictions writeback."""

from __future__ import annotations

import json
from typing import Any
import pandas as pd
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from .config import DATABASE_URL

_engine: Engine | None = None

UPSERT_PREDICTIONS_STMT = text(
    """
    INSERT INTO ml_predictions (entity_id, step, model_name, model_version, score, label, extra)
    VALUES (:entity_id, :step, :model_name, :model_version, :score, :label, CAST(:extra AS JSONB))
    ON CONFLICT (entity_id, step, model_name) DO UPDATE SET
        model_version = EXCLUDED.model_version,
        score = EXCLUDED.score,
        label = EXCLUDED.label,
        extra = EXCLUDED.extra,
        created_at = NOW()
    """
)


def get_engine() -> Engine:
    """Return singleton SQLAlchemy engine configured for PostgreSQL."""
    global _engine
    if _engine is None:
        _engine = create_engine(DATABASE_URL, pool_pre_ping=True)
    return _engine


def engine() -> Engine:
    """Alias for get_engine to satisfy M2 public contract."""
    return get_engine()


def upsert_predictions(df: pd.DataFrame, model_name: str, model_version: str) -> int:
    """Persist prediction score records into ml_predictions in 1000-row chunks."""
    records = []
    for r in df.itertuples():
        records.append({
            "entity_id": str(r.entity_id),
            "step": str(r.step),
            "model_name": model_name,
            "model_version": model_version,
            "score": None if pd.isna(r.score) else float(r.score),
            "label": None if pd.isna(r.label) else str(r.label),
            "extra": json.dumps(getattr(r, "extra", {}), default=float),
        })

    with get_engine().begin() as conn:
        for idx in range(0, len(records), 1000):
            batch = records[idx : idx + 1000]
            conn.execute(UPSERT_PREDICTIONS_STMT, batch)

    return len(records)


def run_sql(sql: str, **params: Any) -> int:
    """Execute raw SQL statement inside an autocommit transaction block."""
    with get_engine().begin() as conn:
        result = conn.execute(text(sql), params)
        return result.rowcount


def scalar(sql: str, **params: Any) -> Any:
    """Execute SQL query and return the first scalar value."""
    with get_engine().connect() as conn:
        return conn.execute(text(sql), params).scalar()
