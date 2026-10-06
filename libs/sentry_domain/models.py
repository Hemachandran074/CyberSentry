"""CyberSentry Domain Data Models.

Frozen, immutable value representations for security telemetry events, detections, and correlated incidents.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class Event:
    """Normalized security telemetry log event."""

    event_id: str
    timestamp: datetime
    source_type: str
    host_id: str | None = None
    user_name: str | None = None
    source_ip: str | None = None
    process_name: str | None = None
    action: str | None = None


@dataclass(frozen=True)
class Detection:
    """Detection rule match mapped to MITRE ATT&CK technique."""

    detection_id: str
    rule_code: str
    detected_at: datetime
    severity: str
    host_id: str | None = None
    user_name: str | None = None
    source_ip: str | None = None
    process_guid: str | None = None


@dataclass(frozen=True)
class Incident:
    """Aggregated incident representing an entity-grouped chain of detections."""

    primary_entity: str
    entity_type: str
    detections: tuple[Detection, ...]
    severity: str
    risk_score: int
    window_start: datetime
    window_end: datetime
