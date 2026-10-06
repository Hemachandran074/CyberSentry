"""CyberSentry Domain Correlation Engine.

Implements temporal and entity-based clustering of detections into incident chains.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Sequence

from libs.sentry_domain.models import Detection, Event, Incident
from libs.sentry_domain.severity import (
    CRITICALITY_MULTIPLIERS,
    SEVERITY_LEVELS,
    SEVERITY_SCORES,
    CorrelationError,
    adjust_severity,
    max_severity,
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


def dedup_key(
    rule_code: str, entity: str, detected_at: datetime, window_minutes: int = 15
) -> str:
    """Generate a deterministic deduplication token for a detection within a time bucket."""
    if window_minutes <= 0:
        raise CorrelationError("Deduplication window must be positive")

    epoch_seconds = detected_at.timestamp()
    epoch_minutes = int(epoch_seconds // 60)
    bucket = epoch_minutes // window_minutes
    return f"{rule_code}|{entity}|{bucket}"


def primary_entity(detection: Detection) -> tuple[str, str]:
    """Resolve the primary entity and its type for a detection based on strict precedence: host > identity > source_ip."""
    if detection.host_id:
        return detection.host_id, "host"
    if detection.user_name:
        return detection.user_name, "identity"
    if detection.source_ip:
        return detection.source_ip, "source_ip"
    raise CorrelationError(
        f"Detection '{detection.detection_id}' does not specify any correlatable entity"
    )


@dataclass
class Correlator:
    """Groups detections by shared entity and temporal proximity into incidents."""

    window: timedelta = field(default_factory=lambda: timedelta(minutes=60))
    asset_criticality: dict[str, str] = field(default_factory=dict)

    def correlate(self, detections: Sequence[Detection]) -> list[Incident]:
        """Aggregate detections into incidents by entity and temporal gaps."""
        if self.window <= timedelta(0):
            raise CorrelationError("Correlation window must be positive")

        if not detections:
            return []

        # Group detections by resolved primary entity
        grouped: dict[tuple[str, str], list[Detection]] = {}
        for det in detections:
            entity_key = primary_entity(det)
            grouped.setdefault(entity_key, []).append(det)

        incidents: list[Incident] = []

        # Sort keys to ensure deterministic processing across Python runs
        for (entity_val, entity_type) in sorted(grouped.keys()):
            entity_detections = sorted(grouped[(entity_val, entity_type)], key=lambda d: d.detected_at)

            current_chain: list[Detection] = [entity_detections[0]]
            for next_det in entity_detections[1:]:
                gap = next_det.detected_at - current_chain[-1].detected_at
                if gap <= self.window:
                    current_chain.append(next_det)
                else:
                    incidents.append(self._build_incident(entity_val, entity_type, current_chain))
                    current_chain = [next_det]

            if current_chain:
                incidents.append(self._build_incident(entity_val, entity_type, current_chain))

        # Order incidents: highest risk descending, then earliest window_start ascending
        incidents.sort(key=lambda inc: (-inc.risk_score, inc.window_start, inc.primary_entity))
        return incidents

    def _build_incident(
        self, entity: str, entity_type: str, chain: Sequence[Detection]
    ) -> Incident:
        criticality = self.asset_criticality.get(entity, "medium")
        max_sev = max_severity([d.severity for d in chain])
        incident_sev = adjust_severity(max_sev, asset_criticality=criticality)
        score = risk_score(chain, asset_criticality=criticality)

        return Incident(
            primary_entity=entity,
            entity_type=entity_type,
            detections=tuple(chain),
            severity=incident_sev,
            risk_score=score,
            window_start=chain[0].detected_at,
            window_end=chain[-1].detected_at,
        )