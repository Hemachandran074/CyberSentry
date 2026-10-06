"""CyberSentry Log Collector Service (M1 Scaffold).

Ingests incoming security telemetry over HTTP endpoints, validates event payloads,
and produces messages to Kafka topic sec.raw.
"""

from __future__ import annotations

import logging
from fastapi import FastAPI

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("log_collector")

app = FastAPI(title="CyberSentry Log Collector", version="0.1.0-M1")


@app.get("/health")
def health_check() -> dict[str, str]:
    """Return service health status."""
    return {"service": "log-collector", "status": "M1-scaffold"}


@app.get("/")
def root() -> dict[str, str]:
    return {"service": "log-collector", "status": "running"}
