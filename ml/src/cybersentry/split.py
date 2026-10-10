"""Authentication telemetry replay simulation and out-of-time dataset partitioning.

Generates synthetic enterprise authentication events with seeded attack scenarios
(T1110 brute force and T1021 lateral movement) and partitions them using an out-of-time
split with protective embargo gaps to prevent temporal and behavioral data leakage.
"""

from __future__ import annotations

from typing import Any
import numpy as np
import pandas as pd

from .config import PROCESSED, SEED, load_cfg

AUTH = ["kerberos", "ntlm", "logon"]

DEFAULT_SIMULATE_CONFIG: dict[str, Any] = {
    "n_users": 300,
    "n_comps": 150,
    "n_steps": 720,
    "n_scenarios": 30,
}

DEFAULT_SPLIT_CONFIG: dict[str, Any] = {
    "train_end_step": 480,
    "val_end_step": 576,
    "embargo_steps": 24,
}


def simulate(
    cfg: dict[str, Any], seed: int = SEED
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Generate benign authentication background traffic and injected attack scenarios.

    Args:
        cfg: Configuration dictionary with n_users, n_comps, n_steps, and n_scenarios.
        seed: Random seed for deterministic replay generation.

    Returns:
        A tuple of (events_dataframe, scenarios_dataframe).
    """
    rng = np.random.default_rng(seed)
    n_users = cfg["n_users"]
    n_comps = cfg["n_comps"]
    n_steps = cfg["n_steps"]
    n_scenarios = cfg.get("n_scenarios", 30)

    users = [f"U{i:04d}" for i in range(n_users)]
    comps = [f"C{i:04d}" for i in range(n_comps)]

    # Assign 1 to 3 primary workstations/servers per user
    home = {
        u: rng.choice(n_comps, size=int(rng.integers(1, 4)), replace=False)
        for u in users
    }

    rows: list[dict[str, Any]] = []
    scen_rows: list[dict[str, Any]] = []

    def emit(
        step: int,
        su: str,
        sc: str,
        dc: str,
        outcome: str,
        malicious: bool,
        technique: str | None = None,
        scenario: str | None = None,
    ) -> None:
        rows.append({
            "step": int(step),
            "src_user": su,
            "src_comp": sc,
            "dst_comp": dc,
            "auth_type": AUTH[int(rng.integers(0, 3))],
            "outcome": outcome,
            "malicious": malicious,
            "technique": technique or "",
            "scenario": scenario or "",
        })

    # 1. Simulate benign baseline traffic with diurnal office hour patterns
    for step in range(1, n_steps + 1):
        hour = step % 24
        activity = 0.35 if 7 <= hour <= 19 else 0.04
        active_user_count = int(rng.binomial(n_users, activity))
        active_users = rng.choice(n_users, size=active_user_count, replace=False)

        for ui in active_users:
            u = users[ui]
            num_attempts = int(rng.integers(1, 4))
            for _ in range(num_attempts):
                if rng.random() < 0.92:
                    dst = comps[rng.choice(home[u])]
                else:
                    dst = comps[int(rng.integers(0, n_comps))]

                src = comps[rng.choice(home[u])]
                outcome = "fail" if rng.random() < 0.02 else "success"
                emit(step, u, src, dst, outcome, False)

    # 2. Inject explicit attack scenarios (alternating T1110 and T1021)
    for k in range(n_scenarios):
        kind = "bruteforce" if k % 2 == 0 else "lateral"
        start = int(rng.integers(12, n_steps - 12))
        sid = f"{kind}-{k:02d}"
        victim = users[int(rng.integers(0, n_users))]

        if kind == "bruteforce":
            # ATT&CK T1110: rapid failure burst against victim workstation followed by success
            attacker = f"C9{int(rng.integers(0, 99)):03d}"
            burst_len = int(rng.integers(12, 18))
            for j in range(burst_len):
                emit(
                    start + (j // 10),
                    victim,
                    attacker,
                    comps[rng.choice(home[victim])],
                    "fail",
                    True,
                    "T1110",
                    sid,
                )
            emit(
                start + 2,
                victim,
                attacker,
                comps[rng.choice(home[victim])],
                "success",
                True,
                "T1110",
                sid,
            )
            scen_rows.append({
                "scenario": sid,
                "technique": "T1110",
                "start": start,
                "end": start + 2,
            })
        else:
            # ATT&CK T1021: lateral traversal pivoting across unfamiliar machines
            hop_count = int(rng.integers(5, 9))
            hops = rng.choice(n_comps, size=hop_count, replace=False)
            for j, h in enumerate(hops):
                target_comp = f"C{h:04d}"
                emit(
                    start + (j // 3),
                    victim,
                    comps[rng.choice(home[victim])],
                    target_comp,
                    "success",
                    True,
                    "T1021",
                    sid,
                )
                if rng.random() < 0.4:
                    emit(
                        start + (j // 3),
                        victim,
                        comps[rng.choice(home[victim])],
                        target_comp,
                        "fail",
                        True,
                        "T1021",
                        sid,
                    )
            scen_rows.append({
                "scenario": sid,
                "technique": "T1021",
                "start": start,
                "end": start + 3,
            })

    df = pd.DataFrame(rows).sort_values("step", kind="stable").reset_index(drop=True)
    df["event_id"] = np.arange(len(df))
    scenarios_df = pd.DataFrame(scen_rows)
    return df, scenarios_df


def time_split(
    df: pd.DataFrame, train_end: int, val_end: int, embargo: int
) -> pd.DataFrame:
    """Assign temporal split labels ('train', 'val', 'test', 'drop') with embargo gaps.

    Args:
        df: Authentication events DataFrame with 'step' column.
        train_end: Maximum step included in training split.
        val_end: Maximum step included in validation split.
        embargo: Number of steps to discard between adjacent splits.

    Returns:
        DataFrame augmented with a 'split' column.
    """
    s = df["step"]
    split = pd.Series("drop", index=df.index)
    split[s <= train_end] = "train"
    split[(s > train_end + embargo) & (s <= val_end)] = "val"
    split[s > val_end + embargo] = "test"
    return df.assign(split=split.values)


def main() -> None:
    """Execute simulation generation, split partitioning, and parquet persistence."""
    cfg = load_cfg()
    sim_cfg = cfg.get("simulate", DEFAULT_SIMULATE_CONFIG) if cfg else DEFAULT_SIMULATE_CONFIG
    split_cfg = cfg.get("split", DEFAULT_SPLIT_CONFIG) if cfg else DEFAULT_SPLIT_CONFIG

    df, scenarios = simulate(sim_cfg)
    df = time_split(
        df,
        split_cfg["train_end_step"],
        split_cfg["val_end_step"],
        split_cfg["embargo_steps"],
    )

    PROCESSED.mkdir(parents=True, exist_ok=True)

    # Persist the clean dataset (technique and scenario metadata stripped to prevent leakage)
    dataset_path = PROCESSED / "dataset.parquet"
    df.drop(columns=["technique", "scenario"]).to_parquet(dataset_path, index=False)

    # Persist scenario ground truth for evaluation only
    scenarios_path = PROCESSED / "scenarios.parquet"
    malicious_subset = df[df.malicious][["event_id", "step", "scenario"]]
    malicious_subset.merge(scenarios, on="scenario").to_parquet(scenarios_path, index=False)

    print("\nDataset split summary:")
    print(
        df.groupby("split")
        .agg(events=("step", "size"), attack_rate=("malicious", "mean"))
        .round(4)
    )
    t1110_count = int((scenarios.technique == "T1110").sum())
    t1021_count = int((scenarios.technique == "T1021").sum())
    print(f"\n{len(scenarios)} scenarios ({t1110_count} T1110, {t1021_count} T1021)")


if __name__ == "__main__":
    main()
