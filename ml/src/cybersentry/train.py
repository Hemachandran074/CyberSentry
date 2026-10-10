"""Supervised behavioral risk scorer training pipeline using LightGBM and MLflow.

Trains a gradient boosted decision tree classifier over causal behavioral counters.
Training events precede validation events chronologically with an embargo buffer,
and training early-stops on validation average precision (PR-AUC) to prevent overfitting.

Logs hyperparameters, metrics, gain-based feature importance, model bundles, and
active run IDs to the MLflow tracking registry.
"""

from __future__ import annotations

import json
from typing import Any
import joblib
import lightgbm as lgb
import mlflow
import pandas as pd
from sklearn.metrics import average_precision_score

from . import tracking
from .config import ARTIFACTS, PROCESSED, SEED, load_cfg
from .features import build_features, feature_columns

DEFAULT_TRAIN_CONFIG: dict[str, Any] = {
    "experiment": "cybersentry-m2",
    "run_name": "lgbm-default",
    "triage_budget": 0.01,
    "model": {
        "n_estimators": 2000,
        "learning_rate": 0.05,
        "num_leaves": 63,
        "min_child_samples": 50,
        "subsample": 0.8,
        "colsample_bytree": 0.8,
        "reg_lambda": 1.0,
        "scale_pos_weight": 5,
    },
}


def frames() -> tuple[dict[str, pd.DataFrame], list[str]]:
    """Load dataset, extract causal behavioral features, and group partitions by split.

    Returns:
        Tuple of (split_name_to_dataframe_map, feature_column_names_list).
    """
    dataset_file = PROCESSED / "dataset.parquet"
    if not dataset_file.exists():
        from .split import main as run_split
        run_split()

    raw_df = pd.read_parquet(dataset_file)
    featured_df = build_features(raw_df)
    partitions = {str(split_name): subset for split_name, subset in featured_df.groupby("split")}
    return partitions, feature_columns(featured_df)


def run(cfg: dict[str, Any] | None = None, log: bool = True) -> dict[str, Any]:
    """Train the supervised LightGBM model with early stopping on validation split.

    Args:
        cfg: Configuration dictionary declaring experiment, run_name, and model params.
        log: Whether to log hyperparameters, artifacts, and metrics to MLflow.

    Returns:
        Dictionary of evaluation metrics (and run_id if logged).
    """
    effective_cfg = dict(DEFAULT_TRAIN_CONFIG)
    if cfg:
        effective_cfg.update(cfg)
        if "model" in cfg:
            effective_cfg["model"] = {**DEFAULT_TRAIN_CONFIG["model"], **cfg["model"]}

    partitions, cols = frames()
    train_data = partitions["train"]
    val_data = partitions["val"]
    m = effective_cfg["model"]

    clf = lgb.LGBMClassifier(
        n_estimators=int(m["n_estimators"]),
        learning_rate=float(m["learning_rate"]),
        num_leaves=int(m["num_leaves"]),
        min_child_samples=int(m["min_child_samples"]),
        subsample=float(m["subsample"]),
        subsample_freq=1,
        colsample_bytree=float(m["colsample_bytree"]),
        reg_lambda=float(m["reg_lambda"]),
        scale_pos_weight=float(m["scale_pos_weight"]),
        random_state=SEED,
        verbose=-1,
    )

    clf.fit(
        train_data[cols],
        train_data.malicious,
        eval_set=[(val_data[cols], val_data.malicious)],
        eval_metric="average_precision",
        callbacks=[lgb.early_stopping(stopping_rounds=50, verbose=False)],
    )

    val_preds = clf.predict_proba(val_data[cols])[:, 1]
    val_pr_auc = float(average_precision_score(val_data.malicious, val_preds))
    metrics: dict[str, Any] = {"val_pr_auc": val_pr_auc}

    if not log:
        return metrics

    with tracking.start(effective_cfg) as active_run:
        run_id = active_run.info.run_id

        # 1. Log model hyperparameters and dataset properties
        mlflow.log_params({f"model.{k}": v for k, v in m.items()})
        mlflow.log_params({
            "n_features": len(cols),
            "best_iter": int(clf.best_iteration_),
            "train_attack_rate": round(float(train_data.malicious.mean()), 5),
        })

        # 2. Log validation metrics
        mlflow.log_metrics(metrics)

        # 3. Log gain-based feature importance breakdown
        importance_series = pd.Series(
            clf.booster_.feature_importance(importance_type="gain"),
            index=cols,
        ).sort_values(ascending=False)
        mlflow.log_text(importance_series.to_string(), "feature_importance_gain.txt")

        # 4. Save and log model artifacts
        ARTIFACTS.mkdir(parents=True, exist_ok=True)
        bundle_path = ARTIFACTS / "model.joblib"
        joblib.dump({"clf": clf, "features": cols}, bundle_path)

        mlflow.sklearn.log_model(clf, artifact_path="model")
        mlflow.log_artifact(str(bundle_path), artifact_path="bundle")

        tracking.save_run_id(run_id)
        metrics["run_id"] = run_id

    return metrics


def main() -> None:
    """Execute training run using active configuration and display logged metrics."""
    cfg = load_cfg()
    result = run(cfg if cfg else None)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
