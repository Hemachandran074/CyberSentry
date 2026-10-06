"""CyberSentry Domain Logic Library.

Pure functional models, severity ranking, risk scoring, and temporal correlation algorithms.
"""

from libs.sentry_domain.correlation import (
    CRITICALITY_MULTIPLIERS,
    SEVERITY_LEVELS,
    SEVERITY_SCORES,
    CorrelationError,
    Correlator,
    Detection,
    Event,
    Incident,
    adjust_severity,
    dedup_key,
    max_severity,
    primary_entity,
    risk_score,
    severity_rank,
)

__all__ = [
    "Event",
    "Detection",
    "Incident",
    "CorrelationError",
    "SEVERITY_LEVELS",
    "SEVERITY_SCORES",
    "CRITICALITY_MULTIPLIERS",
    "severity_rank",
    "max_severity",
    "adjust_severity",
    "risk_score",
    "dedup_key",
    "primary_entity",
    "Correlator",
]
