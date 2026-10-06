"""CyberSentry Domain Severity and Risk Scoring Engine.

Pure deterministic scoring algorithms mapping severities, asset criticality multipliers,
and corroboration factors into incident metrics.
"""

from __future__ import annotations

from typing import Sequence
from libs.sentry_domain.models import Detection

SEVERITY_LEVELS: tuple[str, ...] = ("info", "low", "medium", "high", "critical")

SEVERITY_SCORES: dict[str, int] = {
    "info": 5,
    "low": 20,
    "medium": 45,
    "high": 70,
    "critical": 90,
}

CRITICALITY_MULTIPLIERS: dict[str, float] = {
    "low": 0.8,
    "medium": 1.0,
    "high": 1.2,
    "crown_jewel": 1.5,
}


class CorrelationError(ValueError):
    """Raised when domain validation or correlation invariants are violated."""

    pass


def severity_rank(severity: str) -> int:
    """Return the zero-indexed ordinal ranking of a severity level."""
    if severity not in SEVERITY_LEVELS:
        raise CorrelationError(f"Unknown severity level: '{severity}'")
    return SEVERITY_LEVELS.index(severity)


def max_severity(severities: Sequence[str]) -> str:
    """Return the highest severity from a sequence of severity names."""
    if not severities:
        raise CorrelationError("Cannot compute max severity of an empty sequence")
    return max(severities, key=severity_rank)


def adjust_severity(
    base: str, asset_criticality: str = "medium", is_internet_facing: bool = False
) -> str:
    """Adjust base severity considering asset criticality and network exposure."""
    base_idx = severity_rank(base)
    rank_lift = 0

    if asset_criticality == "crown_jewel":
        rank_lift += 2
    elif asset_criticality == "high":
        rank_lift += 1
    elif asset_criticality in ("medium", "low"):
        pass
    else:
        raise CorrelationError(f"Unknown asset criticality: '{asset_criticality}'")

    if is_internet_facing:
        rank_lift += 1

    target_idx = min(base_idx + rank_lift, len(SEVERITY_LEVELS) - 1)
    target_idx = max(target_idx, base_idx)
    return SEVERITY_LEVELS[target_idx]


def risk_score(detections: Sequence[Detection], asset_criticality: str = "medium") -> int:
    """Calculate compound incident risk score from detection severities and rule corroboration."""
    if not detections:
        raise CorrelationError("Cannot calculate risk score for an empty incident")

    if asset_criticality not in CRITICALITY_MULTIPLIERS:
        raise CorrelationError(f"Unknown asset criticality: '{asset_criticality}'")

    # Base severity score is the maximum of any detection in the chain (never the sum)
    base_score = max(SEVERITY_SCORES[d.severity] for d in detections)

    # Corroboration bonus: +5 points per additional distinct detection rule, capped at 15
    distinct_rules = len({d.rule_code for d in detections})
    corroboration = min(15, max(0, (distinct_rules - 1) * 5))

    raw_score = (base_score + corroboration) * CRITICALITY_MULTIPLIERS[asset_criticality]
    clamped_score = min(100, round(raw_score))
    return int(clamped_score)
