"""CyberSentry Milestone 2 Configuration and Paths.

Centralized registry for file system directories, database connections,
MLflow tracking endpoints, and seed parameters.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any
import yaml

ROOT = Path(__file__).resolve().parents[3]
RAW = ROOT / "data" / "raw"
PROCESSED = ROOT / "data" / "processed"
ARTIFACTS = ROOT / "artifacts"
REPORTS = ROOT / "reports"
CONFIGS = ROOT / "configs"

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+psycopg2://sentry:sentry_dev_2026@localhost:5432/cybersentry",
)

MLFLOW_URI = os.getenv("MLFLOW_TRACKING_URI", "http://localhost:5000")
MODEL_NAME = "cybersentry-auth-risk"
SEED = 42


def load_cfg(path: Path | str | None = None) -> dict[str, Any]:
    """Load and parse YAML configuration from the given path or default configs/train.yaml."""
    cfg_file = Path(path) if path else (CONFIGS / "train.yaml")
    if not cfg_file.exists():
        return {}
    with open(cfg_file, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}
