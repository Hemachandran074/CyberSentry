-- ============================================================
-- CyberSentry — Milestone 2 Schema Migration
-- 002_m2_predictions.sql: Model Predictions Storage
-- ============================================================

CREATE TABLE IF NOT EXISTS ml_predictions (
    entity_id      TEXT        NOT NULL,
    step           TEXT        NOT NULL,
    model_name     TEXT        NOT NULL,
    model_version  TEXT        NOT NULL,
    score          DOUBLE PRECISION,
    label          TEXT,
    extra          JSONB       NOT NULL DEFAULT '{}'::jsonb,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (entity_id, step, model_name)
);

CREATE INDEX IF NOT EXISTS ix_ml_predictions_model ON ml_predictions (model_name, model_version);
