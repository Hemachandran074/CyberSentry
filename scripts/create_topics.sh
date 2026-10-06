#!/usr/bin/env bash
set -euo pipefail

# CyberSentry Kafka Topic Initialization
# Creates the 4 required Kafka topics matching config/kafka_topics.yml

COMPOSE_CMD=${COMPOSE:-"docker compose -p cybersentry"}
BOOTSTRAP_SERVER=${KAFKA_BOOTSTRAP_SERVER:-"kafka:29092"}

echo "[kafka] Provisioning topics on ${BOOTSTRAP_SERVER}..."

topics=(
  "sec.raw:3:604800000"
  "sec.normalized:3:604800000"
  "sec.detections:3:604800000"
  "sec.dlq:1:1209600000"
)

for entry in "${topics[@]}"; do
  IFS=":" read -r name partitions retention <<< "$entry"
  echo " - Creating topic: ${name} (partitions: ${partitions}, retention: ${retention}ms)"
  $COMPOSE_CMD exec -T kafka kafka-topics \
    --bootstrap-server "$BOOTSTRAP_SERVER" \
    --create \
    --if-not-exists \
    --topic "$name" \
    --partitions "$partitions" \
    --replication-factor 1 \
    --config "retention.ms=${retention}" \
    --config "cleanup.policy=delete"
done

echo "[kafka] Topic list on ${BOOTSTRAP_SERVER}:"
$COMPOSE_CMD exec -T kafka kafka-topics --bootstrap-server "$BOOTSTRAP_SERVER" --list
