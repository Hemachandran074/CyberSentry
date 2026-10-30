"""CyberSentry Milestone 2 Verification Suite.

Definition-of-done checks validating:
1. Presence of all 16 required Milestone 2 files.
2. Leakage, causality, and embargo test suite passing green.
3. Test split evaluation report exists with all promotion gates passing.
4. Model champion registered and labeled in the MLflow Model Registry.
5. Predictions written to the database with M1 auth_events backfilled.

Exit code 0 indicates readiness to tag v0.2.0-M2.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import urllib.request

# Ensure ml/src is on the module search path
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "ml" / "src"))

from cybersentry.config import MODEL_NAME, REPORTS, ROOT  # noqa: E402
from cybersentry import db, tracking  # noqa: E402
from cybersentry.promote import check  # noqa: E402

FILES = [
    "ml/src/cybersentry/config.py",
    "ml/src/cybersentry/tracking.py",
    "ml/src/cybersentry/db.py",
    "ml/src/cybersentry/split.py",
    "ml/src/cybersentry/features.py",
    "ml/src/cybersentry/baseline.py",
    "ml/src/cybersentry/train.py",
    "ml/src/cybersentry/hpo.py",
    "ml/src/cybersentry/evaluate.py",
    "ml/src/cybersentry/promote.py",
    "ml/src/cybersentry/writeback.py",
    "configs/train.yaml",
    "configs/gates.yaml",
    "docs/model_card.md",
    "db/migrations/002_m2_predictions.sql",
    "ml/tests/test_m2_leakage.py",
]

FILLED_SQL = """SELECT count(*) FROM auth_events WHERE risk_score IS NOT NULL"""

results: list[bool] = []


def ok(name: str, cond: bool, detail: str = "") -> None:
    results.append(cond)
    status_label = "OK " if cond else "XX "
    detail_str = f" {detail}" if detail else ""
    print(f"[{status_label}] {name}{detail_str}")


def main() -> None:
    print("--- CyberSentry Milestone 2 Verification Suite ---")

    # 1. Verify existence of all required M2 files
    for f in FILES:
        ok(f"file {f}", (ROOT / f).exists())

    # 2. Run data leakage, causality, and split integrity tests
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT / "ml" / "src")
    r = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "ml/tests/test_m2_leakage.py"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
    )
    ok("leakage tests", r.returncode == 0)

    # 3. Verify evaluation report and promotion gates
    rep = REPORTS / "eval.json"
    ok("evaluation report", rep.exists())
    if rep.exists():
        try:
            report_data = json.loads(rep.read_text(encoding="utf-8"))
            for path, val, op, thr, passed in check(report_data):
                ok(f"gate {path}", passed, f"{val:.4f} {op} {thr}")
        except Exception as exc:
            ok("gate evaluations", False, str(exc)[:80])

    # 4. Verify MLflow champion alias exists
    try:
        if tracking.MLFLOW_URI.startswith("http"):
            urllib.request.urlopen(f"{tracking.MLFLOW_URI}/health", timeout=2)
        label, _ = tracking.champion()
        ok("registry champion", True, label)
    except Exception as exc:  # noqa: BLE001
        ok("registry champion", False, str(exc)[:80])

    # 5. Verify database predictions writeback and backfill
    try:
        n_pred = db.scalar(
            "SELECT count(*) FROM ml_predictions WHERE model_name = :m", m=MODEL_NAME
        )
        ok("ml_predictions rows", (n_pred or 0) > 0, str(n_pred))
        n_fill = db.scalar(FILLED_SQL)
        ok("M1 nullable column filled", (n_fill or 0) > 0, str(n_fill))
    except Exception as exc:  # noqa: BLE001
        ok("database writeback", False, str(exc)[:80])

    passed_count = sum(results)
    total_count = len(results)
    print(f"\n{passed_count}/{total_count} checks passed")
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
