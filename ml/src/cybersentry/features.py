"""Causal behavioural feature engineering for authentication event telemetry.

Constructs streaming-compatible behavioural counters per event. Every statistic is
strictly causal and backward-looking (cumulative or rolling over an entity's own
prior history up to the current event). No forward-looking information or future
labels leak into the computed features.
"""

from __future__ import annotations

import pandas as pd

AUTH_CODES: dict[str, int] = {"kerberos": 0, "ntlm": 1, "logon": 2}


def build_features(df: pd.DataFrame) -> pd.DataFrame:
    """Compute per-event causal behavioural features across users and destinations.

    Args:
        df: Authentication events DataFrame with columns: step, event_id, outcome,
            src_user, dst_comp, src_comp, auth_type.

    Returns:
        DataFrame containing original attributes plus computed behavioural counter columns.
    """
    # Ensure deterministic ordering before computing rolling/cumulative statistics
    df = df.sort_values(["step", "event_id"], kind="stable").reset_index(drop=True).copy()
    df["_fail"] = (df["outcome"] == "fail").astype(int)

    gu = df.groupby("src_user", group_keys=False)
    f = pd.DataFrame(index=df.index)

    # 1. Current event status and user prior failure history
    f["is_fail"] = df["_fail"]
    f["user_prior_events"] = gu.cumcount()
    f["user_prior_fails"] = gu["_fail"].cumsum() - df["_fail"]
    f["user_fails_last10"] = gu["_fail"].apply(
        lambda x: x.rolling(10, min_periods=1).sum()
    )

    # 2. Pairwise destination novelty and rolling exploration counters
    pair = df["src_user"] + ">" + df["dst_comp"]
    f["pair_prior"] = df.groupby(pair).cumcount()
    f["new_dst"] = (f["pair_prior"] == 0).astype(int)
    df["_new"] = f["new_dst"]

    f["novel_dst_last20"] = gu["_new"].apply(
        lambda x: x.rolling(20, min_periods=1).sum()
    )
    f["novel_dst_last5"] = gu["_new"].apply(
        lambda x: x.rolling(5, min_periods=1).sum()
    )

    # 3. Destination host failure pile-up across all users
    gd = df.groupby("dst_comp", group_keys=False)
    f["dst_fails_last20"] = gd["_fail"].apply(
        lambda x: x.rolling(20, min_periods=1).sum()
    )

    # 4. Source machine novelty for user
    src_pair = df["src_user"] + ">" + df["src_comp"]
    f["src_comp_new_for_user"] = (df.groupby(src_pair).cumcount() == 0).astype(int)

    # 5. Temporal and protocol encodings
    f["hour"] = (df["step"] % 24).astype(int)
    f["off_hours"] = ((f["hour"] < 6) | (f["hour"] > 20)).astype(int)
    f["auth_c"] = df["auth_type"].map(AUTH_CODES).astype(int)

    # Concat while dropping temporary internal calculation columns
    cleaned_df = df.drop(columns=["_fail", "_new"])
    return pd.concat([cleaned_df, f], axis=1)


def feature_columns(df: pd.DataFrame | None = None) -> list[str]:
    """Return the canonical list of feature column names used for model scoring."""
    return [
        "is_fail",
        "user_prior_events",
        "user_prior_fails",
        "user_fails_last10",
        "pair_prior",
        "new_dst",
        "novel_dst_last20",
        "novel_dst_last5",
        "dst_fails_last20",
        "src_comp_new_for_user",
        "hour",
        "off_hours",
        "auth_c",
    ]
