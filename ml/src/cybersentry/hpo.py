"""Hyperparameter optimization (HPO) harness using Optuna.

Explores the search space declared in configs/train.yaml using a Tree-structured
Parzen Estimator (TPE). Optimization evaluates validation PR-AUC with MLflow
logging disabled during trial iterations. Only the winning configuration is logged
as a tracked MLflow run ('hpo-best') and saved to configs/train.best.yaml.
"""

from __future__ import annotations

import argparse
import copy
from typing import Any
import optuna
import yaml

from .config import CONFIGS, SEED, load_cfg
from .train import run


def suggest(trial: optuna.Trial, space: dict[str, list[Any]]) -> dict[str, Any]:
    """Sample hyperparameter suggestions from the declared search space.

    Args:
        trial: Active Optuna trial instance.
        space: Mapping of parameter names to (type, lower_bound, upper_bound) specifications.

    Returns:
        Dictionary of sampled hyperparameter values.
    """
    suggestions: dict[str, Any] = {}
    for name, spec in space.items():
        kind, lo, hi = spec[0], spec[1], spec[2]
        if kind == "int":
            suggestions[name] = trial.suggest_int(name, int(lo), int(hi))
        elif kind == "log":
            suggestions[name] = trial.suggest_float(name, float(lo), float(hi), log=True)
        else:
            suggestions[name] = trial.suggest_float(name, float(lo), float(hi))
    return suggestions


def main() -> None:
    """Parse CLI arguments, execute Optuna optimization, and log winning configuration."""
    parser = argparse.ArgumentParser(description="Run Optuna HPO over LightGBM search space.")
    parser.add_argument("--trials", type=int, default=30, help="Number of search iterations to evaluate.")
    args = parser.parse_args()

    base_config = load_cfg()
    hpo_config = base_config["hpo"]
    metric_key = hpo_config["metric"]
    direction = hpo_config["direction"]
    search_space = hpo_config["space"]

    def objective(trial: optuna.Trial) -> float:
        trial_config = copy.deepcopy(base_config)
        trial_config["model"].update(suggest(trial, search_space))
        # Evaluate validation metric without MLflow logging
        result = run(trial_config, log=False)
        return float(result[metric_key])

    sampler = optuna.samplers.TPESampler(seed=SEED)
    study = optuna.create_study(direction=direction, sampler=sampler)
    study.optimize(objective, n_trials=args.trials)

    print(f"\nBest {metric_key}: {study.best_value:.5f}")
    print(f"Optimal parameters: {study.best_params}")

    best_config = copy.deepcopy(base_config)
    best_config["model"].update(study.best_params)
    best_config["run_name"] = "hpo-best"

    # Persist the optimized configuration
    best_config_file = CONFIGS / "train.best.yaml"
    best_config_file.write_text(yaml.safe_dump(best_config, sort_keys=False), encoding="utf-8")

    # Record the final winning model as a tracked MLflow run
    print("\nExecuting tracked MLflow run with winning parameters...")
    final_result = run(best_config, log=True)
    print(final_result)


if __name__ == "__main__":
    main()
