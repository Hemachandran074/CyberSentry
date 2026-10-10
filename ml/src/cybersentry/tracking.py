"""MLflow tracking helpers for CyberSentry model experiments and registry lifecycle."""

from __future__ import annotations

import json
from typing import Any
import mlflow
from mlflow.tracking import MlflowClient

from .config import ARTIFACTS, MLFLOW_URI, MODEL_NAME, REPORTS


def start(cfg: dict[str, Any]):
    """Initialize MLflow tracking URI, configure active experiment, and start training run."""
    mlflow.set_tracking_uri(MLFLOW_URI)
    mlflow.set_experiment(cfg.get("experiment", "cybersentry-m2"))
    return mlflow.start_run(run_name=cfg.get("run_name", "train"))


def save_run_id(run_id: str) -> None:
    """Persist active MLflow run ID to disk for downstream pipeline stages."""
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    payload = json.dumps({"run_id": run_id}, indent=2)
    (ARTIFACTS / "last_run.json").write_text(payload, encoding="utf-8")


def load_run_id() -> str:
    """Retrieve run ID from disk persisted by the most recent training run."""
    run_file = ARTIFACTS / "last_run.json"
    if not run_file.exists():
        raise FileNotFoundError(f"Missing run pointer file: {run_file}")
    data = json.loads(run_file.read_text(encoding="utf-8"))
    return data["run_id"]


def flatten(d: dict[str, Any], prefix: str = "") -> dict[str, float]:
    """Recursively flatten nested dictionary keys for MLflow metric logging."""
    flattened: dict[str, float] = {}
    for key, value in d.items():
        composite_key = f"{prefix}{key}"
        if isinstance(value, dict):
            flattened.update(flatten(value, prefix=f"{composite_key}."))
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            flattened[composite_key] = float(value)
    return flattened


def write_report(report: dict[str, Any]) -> None:
    """Persist evaluation metrics to reports/eval.json and attach to MLflow run."""
    REPORTS.mkdir(parents=True, exist_ok=True)
    report_file = REPORTS / "eval.json"
    report_file.write_text(json.dumps(report, indent=2, default=float), encoding="utf-8")

    mlflow.set_tracking_uri(MLFLOW_URI)
    with mlflow.start_run(run_id=report["run_id"]):
        numeric_metrics = flatten(report)
        mlflow.log_metrics({f"test.{k}": v for k, v in numeric_metrics.items()})
        mlflow.log_artifact(str(report_file), artifact_path="evaluation")


def champion() -> tuple[str, str]:
    """Retrieve model version tag and run ID currently marked with the 'champion' alias."""
    mlflow.set_tracking_uri(MLFLOW_URI)
    client = MlflowClient()
    model_version = client.get_model_version_by_alias(MODEL_NAME, "champion")
    return f"{MODEL_NAME}:v{model_version.version}", model_version.run_id
