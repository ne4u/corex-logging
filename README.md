# coreX Logging Pipeline

OpenSearch + OpenSearch Dashboards + OpenSearch MCP server for HAProxy + WAF + MCP Gateway logs, using Docker Compose.

This is a standalone project that runs alongside the [coreX Manager](https://github.com/akauffman/corex_manager) stack. It provides the OpenSearch storage, Dashboards UI, and an OpenSearch MCP server (tool interface for querying logs) for HAProxy request logs, WAF (Coraza SPOA) logs, and MCP Gateway audit logs.

> **Note:** The [Vector](https://vector.dev) log collector that ships logs from HAProxy/Coraza/MCP Gateway into OpenSearch is now part of coreX Manager. This repo no longer runs a Vector service — it only provides OpenSearch, OpenSearch Dashboards, and the OpenSearch MCP server. See the coreX Manager stack for Vector configuration, sources, VRL transforms, and HAProxy LogDestination setup.

## Architecture

```
corex_manager stack                          corex-logging stack
┌──────────┐   ┌─────────┐                ┌────────────┐
│ HAProxy  │   │ Vector  │ ─────────────> │ OpenSearch │
│ (corex)  │   │ (corex) │                │ haproxy-*  │
└──────────┘   └─────────┘                ├────────────┤
┌──────────┐      │                       │ waf-logs-* │
│ Coraza   │ ─────┘                       ├────────────┤
│ SPOA     │                              │ mcp-       │
└──────────┘                              │ gateway-*  │
┌──────────┐   ┌─────────┐                │            │
│ MCP      │   │ Vector  │ ─────────────> │            │
│ Gateway  │   │ (corex) │                └────────────┤
└──────────┘   └─────────┘                  │
                                          ┌────────────┐
                                          │ Dashboards │
                                          │ :5601      │
                                          └────────────┘
                                          ┌────────────┐
┌──────────┐                              │ OpenSearch │
│ MCP      │  <──── corex-net ──────────> │ MCP Server │
│ clients  │                              │ :9900      │
└──────────┘                              └────────────┘
```

| Log type | Source | OpenSearch Index |
|----------|--------|------------------|
| HAProxy request logs | HAProxy `log` directive (syslog, collected by Vector in coreX Manager) | `corex-log-YYYY.MM.DD` |
| WAF (Coraza SPOA) logs | `/app/data/coraza-spoa.log` file (tailed by Vector in coreX Manager) | `waf-logs-YYYY.MM.DD` |
| MCP Gateway audit logs | MCP Gateway audit log (collected by Vector in coreX Manager) | `mcp-gateway-logs-YYYY.MM.DD` |

Vector (in coreX Manager) collects HAProxy request logs via syslog, WAF (Coraza SPOA) logs via file tailing, and MCP Gateway audit logs, decodes JA4 TLS fingerprints, request fingerprints (req_fp), and unique request IDs into structured sub-fields, and ships them to separate OpenSearch indices in this stack.

## Prerequisites

1. **coreX Manager stack running** via `docker compose up -d` in the `corex_manager/` directory (this includes the Vector log collector)
2. **Docker Compose** (v2+)

## Setup

### 1. Configure environment

```bash
cd corex-logging
cp .env.example .env
# Edit .env — set OPENSEARCH_ADMIN_PASSWORD
#   Must be 16+ chars with uppercase, lowercase, digit, and special char.
#   Avoid '#' in the password (Docker Compose .env parsing may truncate at '#').
```

By default, OpenSearch data is stored in a Docker named volume (`opensearch-data`). To use a host directory instead (e.g. NFS/network storage), uncomment and set `OPENSEARCH_DATA_DIR` in `.env`:

```env
OPENSEARCH_DATA_DIR=/mnt/nsf-volume/opensearch
```

The directory must exist and be writable by the OpenSearch container (UID 1000). Create it before starting the stack:

```bash
mkdir -p /mnt/nsf-volume/opensearch
chown 1000:1000 /mnt/nsf-volume/opensearch
```

The `opensearch-mcp` service joins the external `corex-net` network so coreX Manager and other MCP clients can reach it. If your coreX Manager deployment uses a non-default Docker Compose project name, update `COREX_NETWORK_NAME` in `.env` to match the external network name:

```env
COREX_NETWORK_NAME=haproxy_manager_corex-net
```

You can verify the network name with:
```bash
docker network ls | grep corex-net
```

### 2. Start the logging stack

```bash
docker compose up -d
```

This starts three services:
- **opensearch** — single-node OpenSearch with security plugin (demo certs), port 9200
- **opensearch-dashboards** — OpenSearch Dashboards UI, port 5601
- **opensearch-mcp** — OpenSearch MCP server (streamable HTTP transport), port 9900; joins both `logging-net` (to reach OpenSearch) and `corex-net` (so coreX Manager / MCP clients can reach it)

Wait for OpenSearch to become healthy:
```bash
docker compose logs -f opensearch
# Wait for "Active license is now ..." / cluster health yellow/green
```

### 3. Create index templates, Dashboards patterns, and dashboards

```bash
OPENSEARCH_ADMIN_PASSWORD=YourPassword ./scripts/setup-opensearch.sh
```

This creates:
- OpenSearch index templates for `corex-log-*`, `waf-logs-*`, and `mcp-gateway-logs-*` with explicit field mappings (JA4 sub-fields, req_fp sub-fields, IP types, MCP Gateway audit fields, etc.)
- Dashboards index patterns so the Discover UI can browse all indices
- Saved searches: "4xx/5xx Errors", "Slow Requests (>1s)", "WAF Blocked Requests", "Security Rule Hits", "MCP Gateway Errors", "MCP Gateway Denied", "MCP Gateway DLP/Guardrail Hits", "MCP Gateway Slow Requests (>1s)"
- Visualizations: requests over time, status code distribution, top client IPs, top ASN organizations, top request paths, avg response time, WAF events over time, WAF events by message, WAF actions, top WAF client IPs, MCP requests over time, MCP method/action/status distribution, top MCP tools/servers/identities, MCP avg latency, MCP latency by tool
- Dashboards: "CoreX HAProxy Overview" (6 panels), "CoreX WAF Overview" (4 panels), and "MCP Gateway Overview" (9 panels)

### 4. Verify data in OpenSearch

Once Vector (in coreX Manager) is configured to ship logs to this OpenSearch instance:

```bash
# Check HAProxy log count
curl -sku admin:$OPENSEARCH_ADMIN_PASSWORD https://localhost:9200/corex-log-*/_count

# Check a sample document — verify JA4 and req_fp sub-fields are decoded
curl -sku admin:$OPENSEARCH_ADMIN_PASSWORD https://localhost:9200/corex-log-*/_search?size=1 | python3 -m json.tool

# Check WAF log count (generate WAF traffic first by triggering a Coraza rule)
curl -sku admin:$OPENSEARCH_ADMIN_PASSWORD https://localhost:9200/waf-logs-*/_count

# Check MCP Gateway log count
curl -sku admin:$OPENSEARCH_ADMIN_PASSWORD https://localhost:9200/mcp-gateway-logs-*/_count
```

### 5. Open OpenSearch Dashboards

Navigate to `http://localhost:5601` and log in with `admin` / your `OPENSEARCH_ADMIN_PASSWORD`.

Go to **Discover** and select the `corex-log-*`, `waf-logs-*`, or `mcp-gateway-logs-*` index pattern to browse logs. The decoded JA4 sub-fields (`ja4_proto`, `ja4_version`, `ja4_sni`, etc.) and req_fp sub-fields (`req_fp_method`, `req_fp_path_depth`, `req_fp_hdr_count`, etc.) are available as searchable columns in the HAProxy index. MCP Gateway audit fields (`method`, `tool`, `action`, `status`, `latency_ms`, etc.) are available in the MCP Gateway index.

## Decoded Fields

The fields below are decoded by Vector (now in coreX Manager) before logs are shipped to OpenSearch. They are documented here so you know what's available to query and visualize in Dashboards.

### JA4 (TLS fingerprint)

The `ja4` field is fully decoded into human-readable sub-fields:

| Field | Description | Example |
|-------|-------------|---------|
| `ja4_proto` | Raw protocol code | `t` |
| `ja4_protocol` | Decoded protocol name | `TLS` |
| `ja4_version` | Raw version code | `13` |
| `ja4_tls_version` | Decoded TLS version | `TLSv1.3` |
| `ja4_sni` | Raw SNI code | `d` |
| `ja4_sni_present` | Decoded SNI status | `domain` |
| `ja4_cipher_count` | Number of cipher suites (integer) | `15` |
| `ja4_ext_count` | Number of extensions (integer) | `16` |
| `ja4_alpn` | Raw ALPN code | `h2` |
| `ja4_alpn_decoded` | Decoded ALPN | `h2` or `none` |
| `ja4_cipher_hash` | Truncated SHA-256 of cipher list | `8daaf6152771` |
| `ja4_ext_hash` | Truncated SHA-256 of extensions+sigalgs | `b186095e22b6` |
| `ja4_a` | Full JA4_a prefix (10 chars) | `t13d1516h2` |
| `ja4_b` | Cipher hash | `8daaf6152771` |
| `ja4_c` | Extension hash | `b186095e22b6` |

Protocol decode map: `t`→TLS, `d`→DTLS, `q`→QUIC

Version decode map: `13`→TLSv1.3, `12`→TLSv1.2, `11`→TLSv1.1, `10`→TLSv1.0, `s3`→SSLv3, `s2`→SSLv2, `d1`→DTLSv1.0, `d2`→DTLSv1.2, `d3`→DTLSv1.3

SNI decode map: `d`→domain (SNI present), `i`→ip (no SNI)

### req_fp (HTTP request fingerprint)

The `req_fp` field (17 underscore-separated fields) is decoded into human-readable sub-fields. The base62-encoded path (field 1) is kept as a raw keyword for fingerprint matching — the `path` and `query` fields from HAProxy's `%HP`/`%HQ` log directives already provide the human-readable request path. All other encoded field codes are mapped to human-readable values.

| Field | Description | Example |
|-------|-------------|---------|
| `req_fp_path_b62` | Raw base62-encoded path (for fingerprint matching) | `1fT` |
| `req_fp_method_raw` | Raw 2-char method code | `ge` |
| `req_fp_method` | Decoded HTTP method | `GET` |
| `req_fp_http_ver_raw` | Raw version code | `11` |
| `req_fp_http_ver` | Decoded HTTP version | `HTTP/1.1` |
| `req_fp_path_depth` | Path depth (count of `/`) | `3` |
| `req_fp_param_keys` | First chars of parameter names | `ns` |
| `req_fp_param_types_raw` | Raw parameter type codes | `is` |
| `req_fp_param_lens` | Parameter value lengths (dash-separated) | `5-10` |
| `req_fp_ctype` | Raw Content-Type subtype (4 chars) | `json` |
| `req_fp_hdr_count` | Header count (integer) | `12` |
| `req_fp_hdr_list` | Sorted header name initials | `acch` |
| `req_fp_accept_lang` | Raw Accept-Language (4 chars) | `enus` |
| `req_fp_auth_type_raw` | Raw auth type code | `b` |
| `req_fp_auth_type` | Decoded auth type | `basic` |
| `req_fp_cookie_raw` | Raw cookie code | `c` |
| `req_fp_cookie` | Decoded cookie status | `present` |
| `req_fp_cookie_fields` | Cookie field name initials | `stu` |
| `req_fp_referer_raw` | Raw referer code | `s` |
| `req_fp_referer` | Decoded referer status | `same-origin` |
| `req_fp_status` | HTTP response status (integer) | `200` |
| `req_fp_body_bytes` | Response body bytes (long) | `1024` |

Method decode map: `ge`→GET, `po`→POST, `pu`→PUT, `de`→DELETE, `pa`→PATCH, `he`→HEAD, `op`→OPTIONS, `co`→CONNECT, `tr`→TRACE

HTTP version decode map: `09`→HTTP/0.9, `10`→HTTP/1.0, `11`→HTTP/1.1, `20`→HTTP/2.0, `30`→HTTP/3.0

Auth type decode map: `n`→none, `b`→basic, `t`→bearer, `d`→digest, `o`→other

Cookie decode map: `c`→present, `n`→absent

Referer decode map: `n`→none, `s`→same-origin, `x`→cross-origin

Param type decode map (raw field, not auto-decoded): `i`→int, `f`→float, `s`→string, `c`→char, `b`→bool, `t`→time, `d`→date, `z`→datetime+tz, `e`→empty, `o`→object, `l`→list

### unique_id (HAProxy request identifier)

The `unique_id` field is HAProxy's `%ID` — a hex-encoded composite identifier. It's used as the OpenSearch document `_id` for deduplication, and also decoded into structured sub-fields.

Format: `%{+X}o %ci:%cp_%Ts_%rt:%pid` (3 underscore-separated parts, all hex)

Example: `4A07F20E:8C04_6A9889FC_14FD:0012`

| Field | Description | Example |
|-------|-------------|---------|
| `unique_id` | Raw HAProxy unique ID | `4A07F20E:8C04_6A9889FC_14FD:0012` |
| `unique_id_client_ip` | Client IP decoded from hex | `74.7.242.14` |
| `unique_id_client_port` | Client port decoded from hex | `35844` |
| `unique_id_timestamp` | Unix timestamp (epoch seconds) decoded from hex | `1788420092` |
| `unique_id_timestamp_iso` | ISO 8601 timestamp (UTC) | `2026-08-31T12:41:32Z` |
| `unique_id_request_counter` | HAProxy request counter decoded from hex | `5373` |
| `unique_id_pid` | HAProxy process ID decoded from hex | `18` |

If `unique_id` is missing, a UUID v4 is generated for the document `_id` and the decoded sub-fields are not set.

### ASN enrichment (GeoLite2-ASN)

HAProxy enriches each log entry with ASN data from the MaxMind GeoLite2-ASN database via the Rust `geoip2` Lua module. The following fields are emitted directly in the JSON log-format — no Vector-side enrichment needed:

| Field | Description | Example |
|-------|-------------|---------|
| `asn` | Autonomous system number with `AS` prefix | `AS7922` |
| `asn_org` | Autonomous system organization name | `Comcast Cable Communications, LLC` |
| `asn_network` | Network CIDR block containing the client IP | `73.0.0.0/8` |

These fields are populated when the Rust geoip2 module is available and the GeoLite2-ASN database is loaded. If the lookup fails (e.g., IP not in database), the fields are empty strings.

### Captured HTTP headers

In addition to the core request fields, HAProxy emits the following HTTP headers as top-level fields in the JSON log line:

| Field | Description | Example |
|-------|-------------|---------|
| `xff` | Full `X-Forwarded-For` header chain as received from the client/upstream proxy | `203.0.113.195, 198.51.100.42` |
| `referer` | `Referer` HTTP header (the full URL/URI the request came from, when present) | `https://example.com/page` |

### MCP Gateway audit fields

The MCP Gateway emits one JSON audit event per request, with fields for the calling identity, target server, MCP method, and authorization/guardrail outcomes. These fields are available in the `mcp-gateway-logs-*` index:

| Field | Description | Example |
|-------|-------------|---------|
| `@timestamp` | Event timestamp (ISO 8601 with nanosecond precision) | `2026-09-13T02:41:26.006727176+00:00` |
| `request_id` | Unique request identifier (16-char hex) | `e76c9edc36774adf` |
| `session_id` | MCP session identifier | `R3AvIq9SXgR4hE2h7-1vZJ2Df7GQxDrpo-BhqhjLJMM` |
| `identity_id` | Calling identity ID (integer) | `2` |
| `identity_name` | Calling identity name | `grok-agent` |
| `team_id` | Calling team ID (integer) | `2` |
| `team_name` | Calling team name | `platform` |
| `server_id` | Target MCP server ID (integer) | `3` |
| `server_name` | Target MCP server name | `corex-manager` |
| `method` | MCP method | `tools/call` |
| `tool` | Tool name (for `tools/call`), format `server__tool` | `corex-manager__list_users` |
| `resource_uri` | Resource URI (for `resources/read`), null otherwise | `null` |
| `prompt` | Prompt name (for `prompts/get`), null otherwise | `null` |
| `action` | Authorization decision | `allow` or `deny` |
| `status` | Request outcome | `ok` or `error` |
| `latency_ms` | Request latency in milliseconds (integer) | `395` |
| `error` | Error message (null when status is `ok`) | `null` |
| `bytes_in` | Request payload size in bytes (long) | `51` |
| `bytes_out` | Response payload size in bytes (long) | `1096` |
| `dlp_hits` | DLP (Data Loss Prevention) rule hits (flattened object, null when none) | `null` |
| `guardrail_hits` | Guardrail rule hits (flattened object, null when none) | `null` |

The `dlp_hits` and `guardrail_hits` fields use the OpenSearch `flattened` type, so any sub-field within them is queryable as a keyword (e.g., `dlp_hits.rule_name: "ssn"`). They are `null` when no DLP or guardrail rules were triggered.

## Services

| Service | Port | Description |
|---------|------|-------------|
| OpenSearch | 9200 | Search engine API (HTTPS) |
| OpenSearch Dashboards | 5601 | Web UI for querying and visualizing logs |
| OpenSearch MCP Server | 9900 | MCP server exposing OpenSearch as a tool (streamable HTTP, read-only) |

## OpenSearch MCP Server

The `opensearch-mcp` service exposes OpenSearch as an [MCP](https://modelcontextprotocol.io/) tool server using the [opensearch-mcp-server-py](https://pypi.org/project/opensearch-mcp-server-py/) package. It runs on port 9900 with the streamable HTTP transport and is configured read-only (`OPENSEARCH_SETTINGS_ALLOW_WRITE=false`) so MCP clients can search and inspect logs but cannot modify indices or settings.

The service joins two Docker networks:
- **`logging-net`** — to reach the `opensearch` service (`OPENSEARCH_URL=https://opensearch:9200`)
- **`corex-net`** (external, `haproxy_manager_corex-net`) — so coreX Manager and other MCP clients on the coreX network can reach it at `opensearch-mcp:9900`

To register the OpenSearch MCP server as a tool in coreX Manager, point the MCP client at:
```
http://opensearch-mcp:9900
```

Authentication uses the same `OPENSEARCH_ADMIN_PASSWORD` as the rest of the stack (mapped to `OPENSEARCH_PASSWORD` for the MCP server) with username `admin`. TLS verification is disabled (`OPENSEARCH_SSL_VERIFY=false`) because OpenSearch uses bundled demo certificates.

## Log Correlation

Both HAProxy logs and WAF (Coraza SPOA) logs share the same `unique_id` field — HAProxy passes its `%ID` to the Coraza SPOA via the `id=unique-id` SPOE argument, and Coraza includes it in its log output. This allows correlating a request's HAProxy log entry with all WAF rule hits for that request.

### Combined Saved Search (auto-created)

The setup script creates a combined index pattern `corex-log-*,waf-logs-*` with `@timestamp` as the common time field, plus a saved search "Request Correlation (HAProxy + WAF)". To use it:

1. Open Dashboards → Discover
2. Open the saved search "Request Correlation (HAProxy + WAF)"
3. Add a filter: `unique_id` = the request ID you want to investigate (e.g. `4A07F20E:8C04_6A9889FC_14FD:0012`)
4. You'll see the HAProxy log entry and all WAF events for that request, sorted by `@timestamp`

The `@timestamp` field is added by Vector to both log types (parsed from `ts` for HAProxy logs and from the WAF log's `time` or `timestamp` field for WAF logs; the redundant source time fields are dropped) so the combined index pattern has a working time picker.

The saved search defaults to these columns: `@timestamp`, `unique_id`, `client`, `client_ip`, `method`, `path`, `status`, `action`, `rule_id`, `msg`, `severity`, `uri`. Columns only contain values for the row's source index (e.g. `msg` is only set on `waf-logs-*` rows, `method`/`path`/`status` only on `corex-log-*` rows).

If WAF fields like `msg` or `rule_id` are not visible, the combined index pattern's field cache was likely populated before WAF data was ingested. Re-run `scripts/setup-dashboards.py` after both indices have documents, or go to **Stack Management → Index Patterns → `corex-log-*,waf-logs-*`** and click the refresh icon to update the field list.

### OpenSearch Transform (optional, for advanced analysis)

For a more structured correlation, you can use OpenSearch's [Transform](https://docs.opensearch.org/latest/data-prepper/transform/) feature to continuously join WAF events with HAProxy logs on `unique_id` into a new `corex-corlated-*` index. Each document in the correlated index would contain the full HAProxy request context (method, path, status, ASN, JA4) plus an array of WAF rule hits.

To set this up manually:

1. Create a transform that pivots WAF events by `unique_id` and joins with `corex-log-*`:

```bash
curl -ku admin:$OPENSEARCH_ADMIN_PASSWORD -X PUT \
  "https://localhost:9200/_plugins/_transform/corex-correlated" \
  -H 'Content-Type: application/json' \
  -d '{
    "transform": {
      "enabled": true,
      "continuous": true,
      "source_index": ["waf-logs-*"],
      "pivot": {
        "group_by": {
          "unique_id": { "terms": { "field": "unique_id" } }
        },
        "aggregations": {
          "waf_rule_ids": { "terms": { "field": "rule_id" } },
          "waf_actions": { "terms": { "field": "action" } },
          "waf_event_count": { "value_count": { "field": "rule_id" } },
          "waf_messages": { "top_hits": { "size": 10, "sort": [{ "@timestamp": "asc" }], "_source": ["msg", "severity", "uri", "client_ip"] } }
        }
      },
      "target_index": "corex-correlated",
      "schedule": { "interval": { "period": 1, "unit": "minutes" } }
    }
  }'
```

2. Create an index template for the correlated index with the HAProxy fields you want to join:

```bash
curl -ku admin:$OPENSEARCH_ADMIN_PASSWORD -X PUT \
  "https://localhost:9200/_index_template/corex-correlated" \
  -H 'Content-Type: application/json' \
  -d @scripts/index-templates/corex-log.json
```

3. Use an [enrichment pipeline](https://docs.opensearch.org/latest/data-prepper/transform/) to enrich the correlated documents with HAProxy fields (method, path, status, ASN, JA4) by looking up `unique_id` in `corex-log-*`.

4. Create a Dashboards index pattern for `corex-correlated` to visualize WAF rule hits with full request context.

## Troubleshooting

### No logs appearing in OpenSearch

Vector (now in coreX Manager) ships logs into this OpenSearch instance. If no documents are appearing:

1. Verify this stack is up and OpenSearch is healthy: `docker compose ps` and `docker compose logs opensearch`
2. Verify Vector in coreX Manager is configured to ship to this OpenSearch (`opensearch:9200` on the shared network, with the correct admin password)
3. Check the coreX Manager Vector logs for sink/transport errors

### OpenSearch health check fails

1. Check OpenSearch logs: `docker compose logs opensearch`
2. Ensure `OPENSEARCH_ADMIN_PASSWORD` is at least 16 characters
3. Ensure Docker has at least 4GB of memory allocated (OpenSearch + Dashboards)

### Demo certificates warning

This setup uses OpenSearch's bundled demo certificates (`esnode.pem`, `root-ca.pem`). These are for development/internal use only. For production, replace with custom TLS certificates by mounting your certs and updating `opensearch/opensearch.yml`.

## Files

```
corex-logging/
├── docker-compose.yml          # OpenSearch + Dashboards + OpenSearch MCP server
├── .env.example                # Config template (passwords, network/volume names)
├── README.md                   # This file
├── opensearch-dashboards/
│   └── opensearch_dashboards.yml # Dashboards config (connects to OpenSearch)
└── scripts/
    ├── setup-opensearch.sh     # Create index templates + Dashboards patterns + dashboards
    ├── setup-dashboards.py     # Create saved searches, visualizations, and dashboards
    ├── delete-dashboards-objects.py # Remove saved objects created by setup-dashboards.py
    └── index-templates/
        ├── corex-log.json      # OpenSearch index template for HAProxy logs
        ├── waf-logs.json       # OpenSearch index template for WAF logs
        └── mcp-gateway-logs.json # OpenSearch index template for MCP Gateway logs
```
