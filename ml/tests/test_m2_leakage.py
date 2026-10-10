"""Leakage prevention, counter causality, and scenario-window integrity test suite.

Validates that:
1. Split windows are strictly ordered in time with non-zero embargo intervals.
2. Boundary-spanning embargo events are dropped rather than leaking into evaluation splits.
3. Behavioral feature counters are strictly causal (retroactive tampering of t > T
   cannot alter features for events at t <= T).
4. Ground truth target labels and scenario metadata never leak into model feature columns.
5. Replay simulation is fully deterministic and malicious events reside strictly within
   declared attack scenario time windows.
"""

from __future__ import annotations

import pandas as pd
from cybersentry.features import build_features, feature_columns
from cybersentry.split import simulate, time_split

# Compact configuration for fast, isolated test execution
CFG = {"n_users": 40, "n_comps": 30, "n_steps": 200, "n_scenarios": 6}


def toy() -> tuple[pd.DataFrame, pd.DataFrame]:
    """Generate a reproducible toy dataset and partitioned splits for testing."""
    df, scen = simulate(CFG, seed=11)
    return time_split(df, 120, 160, 10), scen


def test_split_windows_are_ordered_with_embargo() -> None:
    """Verify train, validation, and test splits are temporally sequential with embargo gaps."""
    df, _ = toy()
    agg = df[df.split != "drop"].groupby("split")["step"].agg(["min", "max"])
    assert agg.loc["val", "min"] - agg.loc["train", "max"] > 10
    assert agg.loc["test", "min"] - agg.loc["val", "max"] > 10


def test_embargo_rows_are_dropped_not_reused() -> None:
    """Verify events within embargo intervals are marked 'drop' and not leaked into training or eval."""
    df, _ = toy()
    assert df.loc[df.step.between(121, 130), "split"].eq("drop").all()


def test_behavioural_counters_are_causal() -> None:
    """Verify rewriting future events after step T does not affect feature values at steps <= T."""
    df, _ = toy()
    poked = df.copy()
    late = poked.step > 100
    poked.loc[late, "outcome"] = "fail"
    poked.loc[late, "dst_comp"] = "C0001"

    a, b = build_features(df), build_features(poked)
    cols, past = feature_columns(a), a["step"] <= 100
    pd.testing.assert_frame_equal(a.loc[past, cols], b.loc[past, cols])


def test_label_and_scenario_never_enter_features() -> None:
    """Verify target labels and scenario identifiers are completely excluded from the feature space."""
    df, _ = toy()
    cols = set(feature_columns(build_features(df)))
    assert not {"malicious", "technique", "scenario", "split"} & cols


def test_simulation_is_deterministic_and_labels_sit_in_windows() -> None:
    """Verify simulations with identical seeds match bit-for-bit and attacks stay within declared bounds."""
    a, sa = toy()
    b, sb = toy()
    pd.testing.assert_frame_equal(a, b)

    win = {r.scenario: (r.start, r.end) for r in sa.itertuples()}
    mal = a[a.malicious]
    for r in mal.itertuples():
        lo, hi = win[r.scenario]
        assert lo <= r.step <= hi
