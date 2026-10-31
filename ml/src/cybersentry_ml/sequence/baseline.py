"""The frequency baseline the sequence model must beat by 20% PR-AUC (objective 5.3).

Implemented honestly: a per-entity bigram model over actions, which is what a
competent engineer would build in an afternoon before reaching for a GRU. If
the GRU cannot beat this by a fifth, the GRU is not worth its training cost or
its serving latency, and the project should say so.
"""
from __future__ import annotations

import math
from collections import Counter, defaultdict
from typing import Any, Iterable, Mapping, Sequence
import numpy as np

LAPLACE = 0.5


def fit(sequences: Iterable[Sequence[str]]) -> dict[str, Any]:
    """Fit unigram and bigram frequency distributions over action sequences.

    sequences: [[action, ...]] from attack-free segments only.
    """
    unigrams: Counter[str] = Counter()
    bigrams: defaultdict[str, Counter[str]] = defaultdict(Counter)

    for seq in sequences:
        for i, action in enumerate(seq):
            action_str = str(action)
            unigrams[action_str] += 1
            if i > 0:
                prev_action = str(seq[i - 1])
                bigrams[prev_action][action_str] += 1

    return {
        "unigrams": dict(unigrams),
        "bigrams": {k: dict(v) for k, v in bigrams.items()},
        "vocab": sorted(unigrams.keys()),
    }


def session_nll(
    sequence: Sequence[str],
    model: Mapping[str, Any],
    laplace: float = LAPLACE,
) -> float:
    """Mean negative log-likelihood per event.

    Mean, not sum: a sum makes every long session anomalous, which is the single
    most common way a baseline like this is accidentally rigged to lose.
    """
    if not sequence:
        return 0.0

    vocab_len = max(len(model.get("vocab", [])), 1)
    unigrams = model.get("unigrams", {})
    bigrams = model.get("bigrams", {})

    total_nll = 0.0
    n = 0

    for i, action in enumerate(sequence):
        action_str = str(action)
        if i == 0:
            counts = unigrams
        else:
            prev_action = str(sequence[i - 1])
            counts = bigrams.get(prev_action, {})

        denom = sum(counts.values()) + laplace * (vocab_len + 1)
        count = counts.get(action_str, 0) + laplace
        p = count / denom

        total_nll += -math.log(max(p, 1e-12))
        n += 1

    return float(total_nll / n) if n > 0 else 0.0


def score_sessions(
    sessions: Iterable[Sequence[str]],
    model: Mapping[str, Any],
) -> np.ndarray:
    """Score a collection of sessions, returning per-session mean NLL values."""
    return np.array([session_nll(s, model) for s in sessions], dtype=float)
