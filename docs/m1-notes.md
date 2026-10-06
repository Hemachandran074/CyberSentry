# CyberSentry — Milestone 1 Engineering Notes

## 1. Clean-Room Audit & Implementation Log

In accordance with the clean-room protocol, all implementation files were audited, reviewed against the public contracts and functional requirements, and authored independently.

### Audited & Rewritten Components

1. **Database Schema (`scripts/init_db.sql`)**:
   - Audited pre-existing table definitions.
   - Added required append-only trigger on `audit_log` preventing UPDATE and DELETE operations.
   - Enforced referential integrity, check constraints, indexes, and pgcrypto UUID defaults.

2. **Detection Rules Catalogue (`config/detection_rules.yml`)**:
   - Replaced preliminary subset with the full 24 detection rules specified in Appendix B, mapping all rules to verified MITRE ATT&CK techniques, tactics, severities, and parameter dictionaries.

3. **Kafka Topics Configuration (`config/kafka_topics.yml` & `scripts/create_topics.sh`)**:
   - Penned topic definitions for `sec.raw`, `sec.normalized`, `sec.detections`, and `sec.dlq` with appropriate partition counts (3 partitions, dlq 1), replication factors (1), and retention days (7d, dlq 14d).
   - Created idempotent shell script using Kafka CLI utilities with `--if-not-exists`.

4. **OpenSearch Index Template & ISM (`config/opensearch_index.json` & `scripts/create_index.sh`)**:
   - Configured index patterns, settings (1 shard, 0 replicas, 5s refresh interval), and complete property mappings.
   - Updated `create_index.sh` to include `ism_template` auto-attachment for `sentry-events-*` and `--fail-with-body` error handling.

5. **Docker Compose Stack (`docker-compose.yml`)**:
   - Added robust healthchecks across all 6 core infrastructure containers (ZooKeeper, Kafka, OpenSearch, PostgreSQL, Redis, MLflow).
   - Configured Python-based HTTP health probe for MLflow and verified ZooKeeper `ruok` 4lw compatibility.
   - Pinned exact specified versions and configured container restart policies.

6. **Microservice Scaffolds (`services/*/src/`)**:
   - Replaced empty stubs with functional service scaffolds:
     - `log_collector`: FastAPI server exposing `GET /health` with `{"service": "log-collector", "status": "M1-scaffold"}`.
     - `normalizer`, `detection_engine`, `correlation_agent`: Background daemons emitting structured JSON startup banners and handling graceful SIGTERM.
     - `response_agent`: Non-executing stub implementing ADR-0003 constraints.

7. **Data & Reference Seeding (`scripts/seed_db.py`, `scripts/load_attack.py`, `scripts/generate_sample_telemetry.py`)**:
   - Refactored `seed_db.py` to dynamically load detection rules from `config/detection_rules.yml`.
   - Seeded 11 MITRE tactics, ATT&CK techniques (parents preceding children), 60 assets, 40 identities, 3 playbooks, and ~300 deterministic synthetic detections (RNG seed `20260911`).
   - Implemented `load_attack.py` for STIX CTI parsing and `generate_sample_telemetry.py` for offline Sysmon, Zeek, and CloudTrail sample synthesis.

8. **Pure Domain Library (`libs/sentry_domain/`)**:
   - Modularized into `models.py`, `severity.py`, and `correlation.py`, unified via `__init__.py`.
   - Fixed all typing, parameter names, and boundary bugs present in early drafts.
   - Verified pure functional determinism with zero external database or network dependencies.

9. **Unit Testing Suite (`tests/test_severity.py`, `tests/test_correlation.py`)**:
   - Authored comprehensive test suite (24 tests total) covering max-not-sum risk scoring, corroboration increments and capping, asset criticality adjustments, internet-facing lift, temporal window splitting, entity precedence, zero-window exceptions, and timezone resilience.

10. **Verification Suite (`scripts/verify_m1.py`)**:
    - Implemented comprehensive health, schema, constraint, data, and unit test verification suite terminating with `"M1 COMPLETE — safe to tag v0.1.0-M1"`.

## 2. Key Decisions & Rationale

- **Deterministic Correlation**: Detections are grouped strictly by shared primary entity (`host_id` > `user_name` > `source_ip`) within a configurable temporal window (`CORRELATION_WINDOW_MINUTES`). Grouping is never learned or stochastic.
- **Append-Only Auditing**: A database trigger on `audit_log` raises an exception on any UPDATE or DELETE attempt, guaranteeing tamper-evident traceability.
- **Cross-Platform Compatibility**: Enforced LF line endings via `.gitattributes` to prevent CRLF corruption when bash and SQL scripts are mounted into Linux containers on Windows hosts.
