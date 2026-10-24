# Model Card — cybersentry-auth-risk

## Purpose
Rank authentication events by attack likelihood so a 1% tier-1 triage budget surfaces brute-force and lateral-movement activity with evidence attached.

## Not for
Automated containment of any kind (the platform is recommendation-only by ADR-0002); techniques outside the replay's scenario set; network-flow or process telemetry until those sources land in M3.

## Data
- **Source**: Committed seeded simulator: 30 days of benign enterprise auth traffic plus 30 labelled attack scenarios in LANL-flavoured schema.
- **Split**: Out-of-time: train days 1–20, val days 21–24, test days 25–30, 24-hour embargo between each split.
- **Labels**: Per-event: part of an injected scenario; scenario-to-technique mapping isolated for evaluation only.

## Model
LightGBM classifier over causal per-entity behavioural counters; tuned class re-weighting; early-stopped on a strictly-later validation window.

## Incumbent Baseline
Milestone 1 Sigma-style rule pack (five weighted, ATT&CK-tagged rules) — the operational benchmark this model augments and outperforms under equal budget constraints.

## Evaluation (held-out test set; numbers filled from reports/eval.json)
Promotion gates (all must pass):
- `model.coverage_T1110` >= 0.85 — Platform objective: 85%+ of brute-force scenarios surfaced in budget.
- `model.coverage_T1021` >= 0.85 — ...and 85%+ of lateral-movement scenarios — per technique, not averaged.
- `model.precision_at_budget` >= 0.5 — At least half the queue is real attack activity.
- `model.pr_auc` >= 0.7 — Ranking quality on the unseen future window.
- `derived.precision_gain_at_budget` > 0.0 — Same analyst effort, cleaner queue than the rules alone.

Actual results: see `reports/eval.json` and the MLflow run tagged `champion`.

## Known Limitations
- **Simulated traffic**: Real enterprise environments include service accounts, VPN churn, and Kerberos ticket storms that the synthetic generator does not fully replicate.
- **Two techniques only**: Only T1110 (Brute Force) and T1021 (Lateral Movement) are explicitly modelled; novel attack types score according to how closely their behavioral counters resemble these two patterns.
- **Cold start**: Behavioral counters initialize at replay start; the initial 24 hours of any entity are comparatively feature-sparse.

## Ownership
- **Maintainers**: CyberSentry Engineering & Detection Engineering Teams.
- **Retrain Triggers**: Staging of real labelled authentication slices (e.g., LANL red-team slices), drift in baseline authentication patterns, or monthly ingestion of analyst dispositions once the M5 feedback loop is operational.
