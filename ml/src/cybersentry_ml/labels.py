"""Label isolation (FR-1). The one rule the whole evaluation depends on.
ground_truth_labels exists so the platform can be MEASURED. If any detection
path reads it, every number in this milestone is a lie - and the failure is
invisible, because a model that peeks scores beautifully and the code that let
it peek is usually one innocent-looking join.
So the rule is enforced in code rather than trusted: detection reads events
through load_events(), which cannot return a label column, and the unit test
asserts that a SQL string touching the label table raises.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Iterable, List, Mapping, Sequence

LABEL_TABLE = "ground_truth_labels"
FORBIDDEN = re.compile(
    r"\b(ground_truth_labels|is_attack|scenario|technique_truth)\b",
    re.IGNORECASE,
)


class LabelLeak(RuntimeError):
    """Raised when a detection-path query references evaluation-only data."""


def assert_detection_safe(sql: str) -> None:
    """Called by every detection-path query helper. Cheap, blunt and effective:
    a substring check cannot be argued with at review time, and the cost of a
    false positive (rename your column) is far below the cost of a silent leak.
    """
    hit = FORBIDDEN.search(str(sql))
    if hit:
        raise LabelLeak(
            f"detection query references evaluation-only data ({hit.group(0)!r}). "
            f"Labels may be read by ml/evaluation and by nothing else."
        )


def detection_query(sql: str) -> str:
    """Validate query against label leakage and return string."""
    assert_detection_safe(sql)
    return sql


def attack_free(
    events: Iterable[Mapping[str, Any]],
    labelled_event_ids: Iterable[Any],
) -> List[Mapping[str, Any]]:
    """The sequence model trains on attack-free segments only (FR-7). This is
    the ONE place labels legitimately touch training data - choosing what to
    exclude - and it is explicit, named and tested rather than buried in a
    dataset builder.
    """
    bad = set(labelled_event_ids)
    return [e for e in events if e.get("id") not in bad]


def split_entities(
    entity_ids: Sequence[str] | Iterable[str],
    val_fraction: float = 0.2,
    salt: str = "",
) -> dict[str, str]:
    """Entity-wise, hash-stable. A random event split puts the same user's
    Tuesday in train and their Wednesday in test; a sequence model then learns
    that user rather than the behaviour.
    """
    out: dict[str, str] = {}
    for e in dict.fromkeys(entity_ids):
        h = hashlib.sha1(f"{salt}{e}".encode()).hexdigest()
        out[e] = "val" if int(h[:8], 16) / 0xFFFFFFFF < val_fraction else "train"
    return out
