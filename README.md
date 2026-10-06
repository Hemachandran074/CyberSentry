# CyberSentry — Autonomous SOC & Threat Detection Platform

CyberSentry is an agentic security operations and threat detection platform. It ingests multi-source security telemetry, normalises events into a unified schema, maps detections directly to MITRE ATT&CK techniques, and applies deterministic correlation to aggregate noisy alerts into actionable incidents.

## Problem Statement

Modern Security Operations Centers (SOCs) are overwhelmed with alert fatigue, processing tens of thousands of alerts each day with high false-positive rates. Detection alone is not the core issue: the primary bottleneck is **correlation**. A single intrusion campaign triggers alerts across endpoint logs, network firewalls, DNS queries, and identity providers. Analysts are forced to manually correlate these disconnected events under intense time pressure.

CyberSentry elevates correlation to a first-class, deterministic stage. By clustering detections around shared entities within sliding temporal windows, it turns disjointed alerts into coherent incident chains with unified risk scoring and forensic provenance.

## Architecture (M1 Baseline)

```text
[ Endpoint / Network / Cloud Telemetry ]
                    │
                    ▼
            [ log-collector ]
                    │ (sec.raw)
                    ▼
              [ normalizer ] ────────► OpenSearch (telemetry store)
                    │ (sec.normalized)
                    ▼
           [ detection-engine ]
         (rules catalogue & models)
                    │ (sec.detections)
                    ▼
          [ correlation-agent ]
         (entity & sliding window)
                    │
                    ▼
          PostgreSQL (case state) ───► [ response-agent ] ───► SOC Analyst
```

## Platform Milestones

| Milestone | Scope & Core Deliverables |
|---|---|
| **M1** | Core architecture, streaming & search infrastructure, case database schema, deterministic domain correlation library |
| **M2** | Unsupervised anomaly detection and baseline behavioral models trained on normalized telemetry |
| **M3** | Hybrid detection engine combining detection-as-code rules, ML scores, and MITRE ATT&CK mapping |
| **M4** | Agentic triage and autonomous investigation copilot with playbook planning and forensic reasoning |
| **M5** | SOC analyst console featuring interactive incident timelines and dynamic entity graph visualization |
| **M6** | Production deployment pipelines, detection-as-code CI/CD, and real-time model drift monitoring |

## Quick Start

### Prerequisites
- Docker Engine 24+ & Docker Compose v2.20+
- Python 3.11+
- Bash / WSL2 / PowerShell

### Lifecycle Commands
```bash
# 1. Prepare environment variables
cp .env.example .env

# 2. Boot infrastructure stack (Kafka, ZooKeeper, OpenSearch, PostgreSQL, Redis, MLflow)
make up

# 3. Create Kafka message topics
make topics

# 4. Provision OpenSearch index template and retention ISM policy
make index

# 5. Seed reference data (ATT&CK taxonomy, detection rules, assets, demo detections)
make seed

# 6. Run automated M1 verification suite
make verify
```

Alternatively, run the complete setup pipeline in a single step:
```bash
make bootstrap
```

## Repository Structure

```text
cybersentry/
├── config/              # Detection rules, Kafka topic specs, OpenSearch index mappings
├── docs/                # Architectural overviews, ADRs, design documentation
├── libs/
│   └── sentry_domain/   # Pure domain models, severity scoring, and temporal correlation
├── scripts/             # Infrastructure provisioning, database migration, seeding, and verification
├── services/            # Microservices (log_collector, normalizer, detection_engine, etc.)
├── tests/               # Unit and integration test suites
├── docker-compose.yml   # Multi-service local infrastructure orchestration
└── Makefile             # Operational tasks and automation targets
```

## Technology Stack

- **Apache Kafka & ZooKeeper**: Distributed high-throughput telemetry message bus (`sec.raw`, `sec.normalized`, `sec.detections`, `sec.dlq`).
- **OpenSearch 2.14**: Inverted index and document search for normalized telemetry with automated ISM lifecycle retention.
- **PostgreSQL 16**: Relational storage for entity assets, identities, detection rules, incidents, and audit trails.
- **Redis 7**: Fast cache for entity deduplication windows and real-time state tracking.
- **MLflow 2.14**: Tracking server and model registry for machine learning lifecycle artifacts.

## Troubleshooting

### OpenSearch Virtual Memory Limit (`vm.max_map_count`)
OpenSearch requires `vm.max_map_count` to be set to at least `262144`. If OpenSearch exits with an error on Linux or Windows Docker Desktop (WSL2), run:

```bash
# On Linux host:
sudo sysctl -w vm.max_map_count=262144

# On Windows (WSL2 / Docker Desktop):
wsl -d docker-desktop sysctl -w vm.max_map_count=262144
```

To make this persistent across reboots on Linux, append `vm.max_map_count=262144` to `/etc/sysctl.conf`.

## License

This project is licensed under the [MIT License](LICENSE).