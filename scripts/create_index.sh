#!/usr/bin/env bash
set -euo pipefail

# CyberSentry OpenSearch Index & ISM Lifecycle Provisioning
OS_URL=${OPENSEARCH_URL:-http://localhost:9200}
RETENTION_DAYS=${EVENT_RETENTION_DAYS:-30}

echo "[opensearch] Applying index template to ${OS_URL}..."
curl -sS --fail-with-body -X PUT "${OS_URL}/_index_template/sentry-events" \
  -H "Content-Type: application/json" \
  --data-binary @config/opensearch_index.json
echo ""

echo "[opensearch] Applying ISM retention policy sentry-retention (${RETENTION_DAYS} days)..."

POLICY_PAYLOAD=$(cat <<EOF
{
  "policy": {
    "description": "Delete telemetry indices after retention",
    "default_state": "hot",
    "states": [
      {
        "name": "hot",
        "actions": [],
        "transitions": [
          {
            "state_name": "delete",
            "conditions": {
              "min_index_age": "${RETENTION_DAYS}d"
            }
          }
        ]
      },
      {
        "name": "delete",
        "actions": [
          {
            "delete": {}
          }
        ],
        "transitions": []
      }
    ],
    "ism_template": [
      {
        "index_patterns": ["sentry-events-*"],
        "priority": 100
      }
    ]
  }
}
EOF
)

# Check if policy already exists for idempotent update
HTTP_STATUS=$(curl -sS -o /dev/null -w "%{http_code}" "${OS_URL}/_plugins/_ism/policies/sentry-retention" || true)

if [ "$HTTP_STATUS" = "200" ]; then
  echo "ISM policy sentry-retention exists. Fetching version metadata for update..."
  CURRENT_POLICY=$(curl -sS --fail-with-body "${OS_URL}/_plugins/_ism/policies/sentry-retention")
  SEQ_NO=$(echo "$CURRENT_POLICY" | grep -o '"_seq_no":[0-9]*' | head -1 | cut -d: -f2 || true)
  PRI_TERM=$(echo "$CURRENT_POLICY" | grep -o '"_primary_term":[0-9]*' | head -1 | cut -d: -f2 || true)

  if [ -n "$SEQ_NO" ] && [ -n "$PRI_TERM" ]; then
    curl -sS --fail-with-body -X PUT "${OS_URL}/_plugins/_ism/policies/sentry-retention?if_seq_no=${SEQ_NO}&if_primary_term=${PRI_TERM}" \
      -H "Content-Type: application/json" \
      -d "$POLICY_PAYLOAD"
    echo ""
  else
    echo "Existing policy found; skipping update."
  fi
else
  curl -sS --fail-with-body -X PUT "${OS_URL}/_plugins/_ism/policies/sentry-retention" \
    -H "Content-Type: application/json" \
    -d "$POLICY_PAYLOAD"
  echo ""
fi

echo "[opensearch] Provisioning complete."