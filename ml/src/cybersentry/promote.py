"""Model registry promotion gate and champion lifecycle management.

Evaluates test report metrics from reports/eval.json against promotion gates
declared in configs/gates.yaml. If and only if all gates pass, registers the
model in MLflow Model Registry and assigns the production 'champion' alias.
"""

from __future__ import annotations

import json
import operator
import sys
from typing import Any, Callable
import mlflow
from mlflow.tracking import MlflowClient
import yaml

from .config import CONFIGS, MLFLOW_URI, MODEL_NAME, REPORTS

COMPARISON_OPERATORS: dict[str, Callable[[float, float], bool]] = {
    ">=": operator.ge,
    "<=": operator.le,
    ">": operator.gt,
    "<": operator.lt,
}


def lookup(report: dict[str, Any], path: str) -> float:
    """Retrieve nested numeric value from dictionary using dot-delimited path."""
    current_node: Any = report
    for component in path.split("."):
        current_node = current_node[component]
    return float(current_node)


def check(report: dict[str, Any]) -> list[tuple[str, float, str, float, bool]]:
    """Evaluate all configured promotion gates against the evaluation report.

    Args:
        report: Evaluation metrics dictionary loaded from reports/eval.json.

    Returns:
        List of tuples: (gate_path, metric_value, operator_symbol, threshold, passed_boolean).
    """
    gates_file = CONFIGS / "gates.yaml"
    gates_data = yaml.safe_load(gates_file.read_text(encoding="utf-8"))
    gate_definitions = gates_data.get("gates", [])

    results: list[tuple[str, float, str, float, bool]] = []
    for gate in gate_definitions:
        gate_path = gate["path"]
        op_symbol = gate["op"]
        threshold = float(gate["threshold"])

        metric_val = lookup(report, gate_path)
        op_func = COMPARISON_OPERATORS[op_symbol]
        passed = bool(op_func(metric_val, threshold))

        results.append((gate_path, metric_val, op_symbol, threshold, passed))

    return results


def main() -> None:
    """Evaluate gates, tag candidate model version, and assign 'champion' alias upon passing."""
    report_file = REPORTS / "eval.json"
    if not report_file.exists():
        raise FileNotFoundError(
            f"Evaluation report missing at {report_file}. Run evaluate first."
        )

    report = json.loads(report_file.read_text(encoding="utf-8"))
    gate_results = check(report)

    print("\n--- Model Promotion Gate Results ---")
    for path, val, op, thr, passed in gate_results:
        status_label = "PASS" if passed else "FAIL"
        print(f"[{status_label}]  {path:<38} {val:>8.4f} {op} {thr}")

    mlflow.set_tracking_uri(MLFLOW_URI)
    client = MlflowClient()

    # Register candidate model under the target registered model name
    run_id = report["run_id"]
    model_source_uri = f"runs:/{run_id}/model"
    model_version_meta = mlflow.register_model(model_source_uri, MODEL_NAME)
    version = model_version_meta.version

    all_passed = all(item[-1] for item in gate_results)
    client.set_model_version_tag(
        MODEL_NAME, version, "gates", "passed" if all_passed else "failed"
    )

    if not all_passed:
        print(f"\nModel version v{version} registered but NOT promoted — champion alias unchanged.")
        sys.exit(1)

    # Move production champion alias to the passing model version
    client.set_registered_model_alias(MODEL_NAME, "champion", version)
    print(f"\n{MODEL_NAME} v{version} promoted -> 'champion'")


if __name__ == "__main__":
    main()
