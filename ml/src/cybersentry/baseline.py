"""Incumbent rule-based detection engine baseline.

Re-expresses the Milestone 1 Sigma-style detection rule-pack as a weighted heuristic
scorer over identical causal behavioral counters. This enables an apples-to-apples,
airtight comparison between rule heuristics and machine learning models under
identical triage budgets.

Rules remain operational alongside the supervised model for explainability and
defense-in-depth, tagging each event with relevant MITRE ATT&CK technique IDs.
"""

from __future__ import annotations

from typing import Callable
import numpy as np
import pandas as pd

# Rule definitions: name -> (weight, MITRE ATT&CK technique, predicate function)
RULES: dict[str, tuple[float, str, Callable[[pd.DataFrame], pd.Series]]] = {
    "failed_auth_burst": (2.0, "T1110", lambda f: f["user_fails_last10"] >= 5),
    "target_fail_pileup": (1.5, "T1110", lambda f: f["dst_fails_last20"] >= 8),
    "novel_destination": (1.0, "T1021", lambda f: f["new_dst"] == 1),
    "dst_fanout": (2.0, "T1021", lambda f: f["novel_dst_last5"] >= 3),
    "offhours_new_src": (
        0.5,
        "T1078",
        lambda f: (f["off_hours"] == 1) & (f["src_comp_new_for_user"] == 1),
    ),
}


class RuleEngine:
    """Scikit-learn compatible heuristic scorer aggregating weighted rule evaluations."""

    total_weight: float = sum(weight for weight, _, _ in RULES.values())
    total: float = total_weight  # Attribute alias for compatibility with test harnesses

    def predict_proba(self, f: pd.DataFrame) -> np.ndarray:
        """Calculate normalized risk probabilities based on weighted rule activations.

        Args:
            f: DataFrame containing engineered behavioral feature columns.

        Returns:
            2D numpy array of shape (N, 2) where column 0 is [1 - score] and column 1 is [score].
        """
        raw_weighted_sum = sum(
            weight * predicate(f).astype(float).values
            for weight, _, predicate in RULES.values()
        )
        normalized_score = raw_weighted_sum / self.total_weight
        return np.c_[1.0 - normalized_score, normalized_score]

    @staticmethod
    def fired(f: pd.DataFrame) -> pd.DataFrame:
        """Evaluate and return individual boolean activation masks for each rule.

        Args:
            f: DataFrame containing engineered behavioral feature columns.

        Returns:
            DataFrame where each column corresponds to a rule name with boolean activations.
        """
        return pd.DataFrame({
            name: predicate(f) for name, (_, _, predicate) in RULES.items()
        })


def main() -> None:
    """Execute baseline evaluation over the training partition and report per-rule statistics."""
    from .config import PROCESSED
    from .features import build_features

    dataset_path = PROCESSED / "dataset.parquet"
    if not dataset_path.exists():
        from .split import main as run_split
        print("Processed dataset missing, generating via split...")
        run_split()

    raw_df = pd.read_parquet(dataset_path)
    df = build_features(raw_df)
    train_subset = df[df.split == "train"]
    fired_df = RuleEngine.fired(train_subset)

    print("\nRule hit-rate and precision on training partition:")
    for rule_name in fired_df.columns:
        hits = fired_df[rule_name]
        fire_rate = float(hits.mean())
        if fire_rate > 0:
            precision = float(train_subset.malicious[hits].mean())
        else:
            precision = 0.0
        print(f"  {rule_name:<20} fires {fire_rate:7.3%}  precision {precision:7.2%}")


if __name__ == "__main__":
    main()
