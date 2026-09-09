#!/bin/bash
# =============================================================================
# setup-opensearch.sh — Create index templates and Dashboards index patterns
# =============================================================================
# Run this once after `docker compose up -d` to configure OpenSearch with the
# correct field mappings for HAProxy and WAF logs, and to create Dashboards
# index patterns so the Discover UI can browse the data.
#
# Usage:
#   OPENSEARCH_ADMIN_PASSWORD=YourPassword ./scripts/setup-opensearch.sh
# =============================================================================
set -euo pipefail

OS_HOST="${OS_HOST:-https://localhost:9200}"
OS_USER="${OS_USER:-admin}"
OS_PASS="${OPENSEARCH_ADMIN_PASSWORD:?Error: OPENSEARCH_ADMIN_PASSWORD must be set}"
DASH_HOST="${DASH_HOST:-http://localhost:5601}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Waiting for OpenSearch to be healthy..."
until curl -sk --user "${OS_USER}:${OS_PASS}" "${OS_HOST}/_cluster/health" 2>/dev/null | grep -q '"status":"green"\|"status":"yellow"'; do
  printf "."
  sleep 5
done
echo ""
echo "OpenSearch is healthy."

echo "Creating index template: corex-log..."
curl -sk --user "${OS_USER}:${OS_PASS}" -X PUT \
  "${OS_HOST}/_index_template/corex-log" \
  -H 'Content-Type: application/json' \
  -d @"${SCRIPT_DIR}/index-templates/corex-log.json" | python3 -c "import sys,json; r=json.load(sys.stdin); print('  acknowledged:', r.get('acknowledged', r))"

echo "Creating index template: waf-logs..."
curl -sk --user "${OS_USER}:${OS_PASS}" -X PUT \
  "${OS_HOST}/_index_template/waf-logs" \
  -H 'Content-Type: application/json' \
  -d @"${SCRIPT_DIR}/index-templates/waf-logs.json" | python3 -c "import sys,json; r=json.load(sys.stdin); print('  acknowledged:', r.get('acknowledged', r))"

echo ""
echo "Waiting for OpenSearch Dashboards to be ready..."
until curl -s --user "${OS_USER}:${OS_PASS}" "${DASH_HOST}/api/status" 2>/dev/null | grep -q '"state":"green"'; do
  printf "."
  sleep 5
done
echo ""
echo "Dashboards is ready."

# Helper: find-or-create an index pattern (avoids duplicates on re-run)
find_or_create_index_pattern() {
  local title="$1"
  local encoded
  encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$title'))")
  local existing
  existing=$(curl -s --user "${OS_USER}:${OS_PASS}" \
    "${DASH_HOST}/api/saved_objects/_find?type=index-pattern&search=${encoded}&per_page=100" \
    -H 'osd-xsrf: true' 2>/dev/null | \
    python3 -c "
import sys,json
d=json.load(sys.stdin)
for o in d.get('saved_objects',[]):
    if o['attributes']['title'] == '$title':
        print(o['id']); break
" 2>/dev/null)
  if [ -n "$existing" ]; then
    echo "  exists: $title -> $existing"
  else
    local result
    result=$(curl -s --user "${OS_USER}:${OS_PASS}" -X POST \
      "${DASH_HOST}/api/saved_objects/index-pattern" \
      -H 'osd-xsrf: true' \
      -H 'Content-Type: application/json' \
      -d "{\"attributes\":{\"title\":\"$title\",\"timeFieldName\":\"@timestamp\"}}" \
      2>/dev/null | python3 -c "import sys,json; r=json.load(sys.stdin); print(r.get('id', r.get('message', r)))" 2>/dev/null)
    echo "  created: $title -> $result"
  fi
}

echo "Creating Dashboards index pattern: corex-log-*..."
find_or_create_index_pattern "corex-log-*"

echo "Creating Dashboards index pattern: waf-logs-*..."
find_or_create_index_pattern "waf-logs-*"

echo "Creating Dashboards index pattern: corex-log-*,waf-logs-* (combined for correlation)..."
find_or_create_index_pattern "corex-log-*,waf-logs-*"

echo ""
echo "Creating saved searches, visualizations, and dashboards..."
OPENSEARCH_ADMIN_PASSWORD="${OS_PASS}" DASH_HOST="${DASH_HOST}" \
  python3 "${SCRIPT_DIR}/setup-dashboards.py"

echo ""
echo "Setup complete!"
echo "  OpenSearch:       ${OS_HOST}"
echo "  Dashboards:       ${DASH_HOST}"
echo "  HAProxy index:    corex-log-*"
echo "  WAF index:        waf-logs-*"
echo "  Dashboards:       CoreX HAProxy Overview, CoreX WAF Overview"
