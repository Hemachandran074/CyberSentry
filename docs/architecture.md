# CyberSentry — System Architecture (Milestone 1)

## 1. Architectural Context
Security telemetry generates high-volume, append-only streams that require rapid full-text indexing, flexible keyword matching, and time-range filtering. Conversely, incident tracking, asset registers, and rule management involve low-volume, highly relational entities that demand transactional ACID guarantees and referential integrity.

Attempting to force both workloads into a single database engine results in severe compromises. Consequently, CyberSentry implements a split-store architecture:
- **OpenSearch** handles unstructured and semi-structured telemetry logs.
- **PostgreSQL** stores operational case state, detection rules, MITRE ATT&CK taxonomy, and incident data.

Milestone 1 provisions both stores, defines the event schemas, and builds the end-to-end streaming backbone before introducing machine learning models in Milestone 2.

## 2. Component Responsibilities

- **log-collector**: Ingests incoming telemetry payloads via HTTP and syslog endpoints, validates the envelope structure against strict Pydantic schemas, and routes messages onto Kafka topic `sec.raw`.
- **normalizer**: Consumes from `sec.raw`, parses heterogeneous source events into a standard CyberSentry event model, attaches asset and user context, writes documents to OpenSearch (`sentry-events-*`), and publishes to `sec.normalized`.
- **detection-engine**: Consumes normalized events, evaluates detection-as-code rules, validates threshold windows, persists matches to the PostgreSQL `detections` table, and broadcasts to `sec.detections`.
- **correlation-agent**: Aggregates detections within a temporal sliding window, groups them by primary entity (host, identity, or IP), evaluates compound risk scores, and manages `incidents` records in PostgreSQL.
- **response-agent**: Maps verified incidents to defined incident response playbooks, proposes remediation actions (e.g. host isolation, account revocation), and tracks approvals.

## 3. Data Flow

1. Host agents and network appliances send JSON telemetry to `log-collector`.
2. `log-collector` validates envelopes and produces messages to `sec.raw` partitioned by `host_id`.
3. `normalizer` maps incoming fields to standard ECS-aligned keys, annotates asset criticality, sends the event to OpenSearch for time-series analytics, and writes to `sec.normalized`.
4. `detection-engine` executes detection rules against events. Matches generate records in PostgreSQL (`detections`) with the associated MITRE ATT&CK technique ID and OpenSearch document reference, followed by publication to `sec.detections`.
5. `correlation-agent` groups detections based on shared entity attributes and sliding time windows, calculating incident severity and risk scores.
6. `response-agent` queues containment actions in PostgreSQL (`response_actions`), requiring analyst sign-off before destructive execution.

## 4. Non-Functional Requirements

- **Durability & Fault Tolerance**: Detections, incidents, and audit logs persist across container and broker restarts. Message replay on Kafka is bounded and predictable.
- **Provenance & Auditability**: Detections permanently reference rule versions and MITRE ATT&CK IDs. An append-only audit log records administrative changes and system executions.
- **Safety First**: Destructive response actions (e.g. host isolation, credential termination) strictly require explicit operator approval in PostgreSQL (`action_approvals`).
- **Data Governance**: PII and telemetry data are isolated; raw data is managed via DVC with strict Git exclusion rules.

## 5. Known Limitations (M1)

- **Entity Precedence Clustering**: Correlation groups detections by a single primary entity determined via precedence (`host_id` > `user_name` > `source_ip`). Detections belonging to the same broader attack campaign that only share secondary entities will produce distinct incidents in M1. Graph-based entity linkage (union-find) is slated for M2/M3.
- **Container Build Contexts**: Microservice containers currently cannot directly import from `libs/sentry_domain` because their individual build contexts are scoped to `services/<service_name>/`. Shared domain package installation or monorepo build contexts will be established in M2.