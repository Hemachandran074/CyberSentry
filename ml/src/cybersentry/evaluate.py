"""Evaluation harness for detection coverage and precision under a fixed triage budget.

Evaluates trained models and the incumbent rule baseline over the out-of-time test
partition. Scores events, selects the top tier-1 triage budget share (default 1%),
and computes:
1. Scenario coverage per MITRE ATT&CK technique (T1110, T1021).
2. Precision and alert volume inside the analyst budget.
3. Ranking discrimination via Average Precision (PR-AUC).
4. Derived incremental performance gains of the model over the rule pack.

Persists results to reports/eval.json and logs test metrics to the MLflow tracking run.
"""

from __future__ import annotations

from typing import Any
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score

from . import tracking
from .baseline import RuleEngine
from .config import ARTIFACTS, PROCESSED, load_cfg
from .features import build_features


def budget_mask(score: np.ndarray, budget: float) -> np.ndarray:
    """Identify the top budget-fraction of highest-scoring events.

    Args:
        score: 1D array of predicted malicious risk scores.
        budget: Fraction of total events to flag (e.g. 0.01 for 1%).

    Returns:
        Boolean mask array where True indicates events surfaced within the budget.
    """
    k = max(1, int(round(len(score) * budget)))
    cutoff = np.partition(score, -k)[-k]
    return score >= cutoff


def coverage(te: pd.DataFrame, flagged: np.ndarray, scen: pd.DataFrame) -> dict[str, Any]:
    """Calculate scenario detection coverage across ATT&CK techniques within flagged alerts.

    A scenario is considered covered if at least one of its component events is
    surfaced within the triage budget.

    Args:
        te: Test partition DataFrame containing event_id.
        flagged: Boolean mask of events selected by the budget cutoff.
        scen: Evaluation scenario mapping containing event_id, scenario, and technique.

    Returns:
        Dictionary reporting coverage ratios per technique and total scenarios detected.
    """
    flagged_malicious_events = te.loc[flagged & te.event_id.isin(scen.event_id), "event_id"]
    scenario_map = scen.set_index("event_id")["scenario"]
    hit_scenarios = set(flagged_malicious_events.map(scenario_map))

    coverage_metrics: dict[str, Any] = {}
    for tech, group in scen.groupby("technique"):
        total_scenarios_in_tech = group.scenario.nunique()
        tech_hits = len(set(group.scenario) & hit_scenarios)
        coverage_metrics[f"coverage_{tech}"] = tech_hits / max(total_scenarios_in_tech, 1)

    coverage_metrics["scenarios_detected"] = len(hit_scenarios)
    return coverage_metrics


def block(
    te: pd.DataFrame, score: np.ndarray, scen: pd.DataFrame, budget: float
) -> dict[str, Any]:
    """Compute performance metrics (PR-AUC, precision@budget, recall@budget, coverage).

    Args:
        te: Test partition DataFrame with boolean 'malicious' labels.
        score: Predicted probability scores.
        scen: Scenario ground truth for the test partition.
        budget: Analyst triage budget fraction.

    Returns:
        Dictionary of performance metrics.
    """
    flagged = budget_mask(score, budget)
    y_true = te.malicious.to_numpy()

    metrics: dict[str, Any] = {
        "pr_auc": float(average_precision_score(y_true, score)),
        "precision_at_budget": float(y_true[flagged].mean()),
        "recall_at_budget": float(y_true[flagged].sum() / max(y_true.sum(), 1)),
        "alerts_at_budget": int(flagged.sum()),
    }
    metrics.update(coverage(te, flagged, scen))
    return metrics


def main() -> None:
    """Run full evaluation suite over test split for model vs. rule baseline and persist report."""
    cfg = load_cfg()
    budget = float(cfg.get("triage_budget", 0.01))

    model_bundle_file = ARTIFACTS / "model.joblib"
    if not model_bundle_file.exists():
        raise FileNotFoundError(
            f"Trained model bundle not found at {model_bundle_file}. Run training first."
        )

    bundle = joblib.load(model_bundle_file)
    clf = bundle["clf"]
    feature_cols = bundle["features"]

    dataset_file = PROCESSED / "dataset.parquet"
    scenarios_file = PROCESSED / "scenarios.parquet"

    raw_df = pd.read_parquet(dataset_file)
    df = build_features(raw_df)
    scen = pd.read_parquet(scenarios_file)

    te = df[df.split == "test"].reset_index(drop=True)
    scen_te = scen[scen.event_id.isin(te.event_id)]
    n_scen = int(scen_te.scenario.nunique())

    model_scores = clf.predict_proba(te[feature_cols])[:, 1]
    rule_scores = RuleEngine().predict_proba(te)[:, 1]

    model_results = block(te, model_scores, scen_te, budget)
    base_results = block(te, rule_scores, scen_te, budget)

    try:
        run_id = tracking.load_run_id()
    except Exception:
        run_id = "eval-local"

    report = {
        "run_id": run_id,
        "test_events": int(len(te)),
        "test_scenarios": n_scen,
        "model": model_results,
        "baseline": base_results,
        "derived": {
            "pr_auc_gain": model_results["pr_auc"] - base_results["pr_auc"],
            "coverage_gain": (
                model_results["scenarios_detected"] - base_results["scenarios_detected"]
            )
            / max(n_scen, 1),
            "precision_gain_at_budget": (
                model_results["precision_at_budget"] - base_results["precision_at_budget"]
            ),
        },
    }

    tracking.write_report(report)

    t1110_cov = model_results.get("coverage_T1110", 0.0)
    t1021_cov = model_results.get("coverage_T1021", 0.0)
    model_prec = model_results["precision_at_budget"]
    base_prec = base_results["precision_at_budget"]

    print(
        f"\ncoverage T1110 {t1110_cov:.2f} / T1021 {t1021_cov:.2f} | "
        f"precision@budget model={model_prec:.2f} rules={base_prec:.2f}"
    )


if __name__ == "__main__":
    main()
