"""Per-entity behavioural baselines (FR-6).

A baseline answers one question: is this normal FOR THIS ENTITY? A service
account authenticating at 03:00 is routine; a finance user doing it is not, and
a global threshold cannot tell them apart.

Everything is computed over a rolling window and versioned, because "normal"
moves - a user changes team, a host changes role - and a baseline frozen at
onboarding generates a month of false positives and then gets ignored.
"""
from __future__ import annotations

import math
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence
import numpy as np

MIN_EVENTS = 50  # below this an entity has no baseline, and says so
LAPLACE = 1.0  # smoothing: an unseen value is rare, never impossible


def _extract_hour(event: Mapping[str, Any]) -> int:
    """Extract integer hour (0-23) from event dict."""
    if "hour" in event and event["hour"] is not None:
        return int(event["hour"]) % 24
    ts = event.get("ts")
    if isinstance(ts, datetime):
        return ts.hour
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).hour
    return 0


def _extract_host(event: Mapping[str, Any]) -> str:
    """Extract destination host identifier from event dict."""
    return str(event.get("dst_host") or event.get("dst") or "unknown")


def _span_days(events: Sequence[Mapping[str, Any]]) -> float:
    """Compute the span in days across timestamps in events."""
    raw_ts = [e.get("ts") for e in events if e.get("ts") is not None]
    if len(raw_ts) < 2:
        return 1.0
    floats = []
    for t in raw_ts:
        if isinstance(t, datetime):
            floats.append(t.timestamp())
        else:
            try:
                floats.append(float(t))
            except (ValueError, TypeError):
                continue
    if len(floats) < 2:
        return 1.0
    floats.sort()
    return max((floats[-1] - floats[0]) / 86400.0, 1.0)


def build(events: Sequence[Mapping[str, Any]], min_events: int = MIN_EVENTS) -> dict:
    """Build a behavioural profile for ONE entity over the rolling window.

    events: [{'ts','action','object','dst_host','hour'}]
    Returns the profile, or a profile marked insufficient - which downstream
    means 'score nothing', not 'score everything as anomalous'.
    """
    events_list = list(events)
    n = len(events_list)
    if n < min_events:
        return {
            "sufficient": False,
            "n_events": n,
            "reason": (
                f"{n} events (< {min_events}) - too little history to call "
                f"anything unusual"
            ),
        }

    hours = Counter(_extract_hour(e) for e in events_list)
    hosts = Counter(_extract_host(e) for e in events_list)
    actions = Counter(str(e.get("action")) for e in events_list)
    objects = Counter(str(e.get("object")) for e in events_list)
    distinct_hosts = len(hosts)
    span = _span_days(events_list)

    return {
        "sufficient": True,
        "n_events": n,
        "hours": {str(h): hours[h] for h in range(24)},
        "hosts": dict(hosts),
        "actions": dict(actions),
        "objects": dict(objects),
        "distinct_hosts": distinct_hosts,
        "events_per_day": n / max(span, 1.0),
    }


def surprisal(value: Any, distribution: Mapping[str, int | float], laplace: float = LAPLACE) -> float:
    """Compute Laplace-smoothed -log p(value) under the entity's history.

    Smoothing matters: without it, the first time an entity touches a new host,
    probability is zero and surprisal is infinite, turning one legitimate new
    laptop into an unbounded anomaly score. With Laplace smoothing, an unseen
    value is rare, not impossible.
    """
    total = sum(distribution.values()) + laplace * (len(distribution) + 1)
    count = distribution.get(str(value), 0) + laplace
    return float(-math.log(count / total))


def _entropy(counts: Mapping[str, int | float]) -> float:
    """Normalized Shannon entropy of categorical count dictionary."""
    total = sum(counts.values())
    if total <= 0:
        return 0.0
    p = np.array(list(counts.values()), dtype=float) / total
    return float(-(p * np.log(p + 1e-12)).sum() / math.log(max(len(p), 2)))


def vector(profile: Mapping[str, Any]) -> np.ndarray:
    """Generate the fixed-size behaviour vector for peer clustering.

    Uses normalized shares rather than raw counts so that busy entities and
    quiet entities with identical behavioural shapes land in the same peer group.
    """
    if not profile.get("sufficient"):
        raise ValueError("cannot vectorise an insufficient profile")

    # 24 hourly activity proportions
    hours_dict = profile.get("hours", {})
    hours = np.array([hours_dict.get(str(h), 0) for h in range(24)], dtype=float)
    hours = hours / max(hours.sum(), 1.0)

    # Top 5 destination host proportions
    hosts_dict = profile.get("hosts", {})
    hosts_counts = np.array(sorted(hosts_dict.values(), reverse=True), dtype=float)
    top_hosts = np.zeros(5, dtype=float)
    if len(hosts_counts) > 0:
        top_hosts[: min(5, len(hosts_counts))] = hosts_counts[:5] / max(hosts_counts.sum(), 1.0)

    distinct_hosts = profile.get("distinct_hosts", 0)
    events_per_day = profile.get("events_per_day", 0.0)
    actions_dict = profile.get("actions", {})

    return np.concatenate(
        [
            hours,
            top_hosts,
            np.array(
                [
                    min(distinct_hosts / 50.0, 1.0),
                    min(events_per_day / 500.0, 1.0),
                    _entropy(actions_dict),
                ],
                dtype=float,
            ),
        ]
    )
