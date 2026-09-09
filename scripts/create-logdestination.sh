#!/bin/bash
# =============================================================================
# create-logdestination.sh — Create HAProxy LogDestination for Vector syslog
# =============================================================================
# Creates a LogDestination in the coreX Manager API so HAProxy sends request
# logs to Vector via UDP syslog (vector:514). This adds the destination to
# the database; you must then apply the config in the coreX UI (or it auto-
# applies if no other pending config changes exist).
#
# Usage:
#   COREX_PASS=YourAdminPassword ./scripts/create-logdestination.sh
#
# Environment variables:
#   COREX_API    - coreX API base URL (default: http://localhost:8000/api/v1)
#   COREX_USER   - admin username (default: admin)
#   COREX_PASS   - admin password (required)
# =============================================================================
set -euo pipefail

COREX_API="${COREX_API:-https://localhost:3443/api/v1}"
COREX_USER="${COREX_USER:-admin}"
COREX_PASS="${COREX_PASS:?Error: COREX_PASS must be set}"

echo "Authenticating to coreX API at ${COREX_API}..."
TOKEN=$(curl -sk -X POST "${COREX_API}/auth/token" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d "username=${COREX_USER}&password=${COREX_PASS}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

echo "Checking for existing 'opensearch-vector' LogDestination..."
EXISTING=$(curl -sk "${COREX_API}/log-destinations" \
  -H "Authorization: Bearer ${TOKEN}" \
  | python3 -c "
import sys, json
dests = json.load(sys.stdin)
for d in dests:
    if d.get('name') == 'opensearch-vector':
        print(d['id'])
        break
")

if [ -n "${EXISTING}" ]; then
  echo "  Found existing LogDestination (id=${EXISTING}). Updating target..."
  curl -sk -X PUT "${COREX_API}/log-destinations/${EXISTING}" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H 'Content-Type: application/json' \
    -d '{
      "name": "opensearch-vector",
      "target": "vector:514",
      "facility": "local0",
      "level": "info",
      "enabled": true
    }' | python3 -c "import sys,json; r=json.load(sys.stdin); print('  Updated id:', r['id'], 'target:', r['target'])"
else
  echo "  Creating new LogDestination..."
  curl -sk -X POST "${COREX_API}/log-destinations" \
    -H "Authorization: Bearer ${TOKEN}" \
    -H 'Content-Type: application/json' \
    -d '{
      "name": "opensearch-vector",
      "target": "vector:514",
      "facility": "local0",
      "level": "info",
      "enabled": true
    }' | python3 -c "import sys,json; r=json.load(sys.stdin); print('  Created id:', r['id'], 'target:', r['target'])"
fi

echo ""
echo "LogDestination configured. HAProxy will send logs to vector:514."
echo "Apply the config in the coreX UI (or it auto-applies if no other pending changes)."
