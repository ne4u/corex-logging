#!/usr/bin/env python3
"""
Create saved searches, visualizations, and dashboards in OpenSearch Dashboards.

Run after setup-opensearch.sh has created the index patterns. This script
queries Dashboards for the existing index pattern IDs, then creates:

  Saved Searches:
    - 4xx/5xx Errors
    - Slow Requests (>1s)
    - WAF Blocked Requests
    - Security Rule Hits
    - Request Correlation (HAProxy + WAF)
    - MCP Gateway Errors
    - MCP Gateway Denied
    - MCP Gateway DLP/Guardrail Hits
    - MCP Gateway Slow Requests (>1s)

  Visualizations (HAProxy):
    - Requests Over Time (area chart, split by status)
    - Status Code Distribution (pie)
    - Top Client IPs (table)
    - Top ASN Organizations (bar)
    - Top Request Paths (table)
    - Avg Response Time (line)

  Visualizations (WAF):
    - WAF Events Over Time (area)
    - WAF Events by Message (bar)
    - WAF Actions (pie)
    - Top WAF Client IPs (table)

  Visualizations (MCP Gateway):
    - MCP Requests Over Time (area, split by method)
    - MCP Method Distribution (pie)
    - MCP Action Distribution (pie)
    - MCP Status Distribution (pie)
    - Top MCP Tools (table)
    - Top MCP Servers (table)
    - Top MCP Identities (table)
    - MCP Avg Latency (line)
    - MCP Latency by Tool (bar)

  Dashboards:
    - CoreX HAProxy Overview (6 panels)
    - CoreX WAF Overview (4 panels)
    - MCP Gateway Overview (9 panels)

Usage:
  OPENSEARCH_ADMIN_PASSWORD=YourPassword ./scripts/setup-dashboards.py
"""
import base64
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request

DASH_HOST = os.environ.get("DASH_HOST", "http://localhost:5601")
OS_HOST = os.environ.get("OS_HOST", "https://localhost:9200")
OS_USER = os.environ.get("OS_USER", "admin")
OS_PASS = os.environ["OPENSEARCH_ADMIN_PASSWORD"]

_CTX = ssl.create_default_context()
_CTX.check_hostname = False
_CTX.verify_mode = ssl.CERT_NONE

_AUTH = base64.b64encode(f"{OS_USER}:{OS_PASS}".encode()).decode()


def _http_json(method, url, body=None):
    """Send an HTTP request with auth headers and return parsed JSON."""
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    req.add_header("osd-xsrf", "true")
    req.add_header("Authorization", f"Basic {_AUTH}")
    try:
        with urllib.request.urlopen(req, context=_CTX) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        err_body = e.read().decode()[:300]
        print(f"  ERROR {e.code}: {err_body}", file=sys.stderr)
        return None
    except urllib.error.URLError as e:
        print(f"  ERROR: {e}", file=sys.stderr)
        return None


def dash_req(method, path, body=None):
    return _http_json(method, f"{DASH_HOST}{path}", body)


def os_req(method, path, body=None):
    return _http_json(method, f"{OS_HOST}{path}", body)


def wait_for_dashboards():
    print("Waiting for OpenSearch Dashboards...", end=" ", flush=True)
    for _ in range(60):
        try:
            req = urllib.request.Request(f"{DASH_HOST}/api/status")
            req.add_header("Authorization", f"Basic {_AUTH}")
            with urllib.request.urlopen(req, context=_CTX, timeout=5) as resp:
                data = json.loads(resp.read().decode())
                if data.get("status", {}).get("overall", {}).get("state") == "green":
                    print("ready!")
                    return True
        except Exception:
            pass
        print(".", end="", flush=True)
        time.sleep(5)
    print("TIMEOUT", file=sys.stderr)
    return False


def find_index_pattern(title):
    import urllib.parse
    encoded = urllib.parse.quote(title)
    resp = dash_req("GET", f"/api/saved_objects/_find?type=index-pattern&search={encoded}&per_page=100")
    if not resp:
        return None
    for obj in resp.get("saved_objects", []):
        if obj["attributes"]["title"] == title:
            return obj["id"]
    return None


def create_index_pattern(title):
    """Create a Dashboards index pattern and return its id."""
    body = {
        "attributes": {
            "title": title,
            "timeFieldName": "@timestamp",
        }
    }
    resp = dash_req("POST", "/api/saved_objects/index-pattern", body)
    if not resp:
        return None
    print(f"  created index pattern: {title} -> {resp.get('id')}")
    return resp.get("id")


def populate_index_pattern_fields(pattern_title, pattern_id):
    """Populate the field cache for an index pattern by fetching field caps
    from OpenSearch and writing them directly into the saved object.

    OpenSearch Dashboards 3.x does NOT auto-populate the ``fields`` attribute
    when an index pattern is created via the Saved Objects API — the field
    list stays empty until a user opens the pattern in the UI. This causes
    visualizations referencing ``@timestamp`` (or any field) to fail with
    "Could not locate that index-pattern-field".

    This function queries OpenSearch's ``_field_caps`` API for the pattern's
    indices, builds the field metadata list in the format Dashboards expects,
    and PUTs it back into the saved object. This must be called AFTER documents
    have been ingested so the field caps return real mappings.
    """
    fc = os_req("GET", f"/{pattern_title}/_field_caps?fields=*")
    if not fc or "fields" not in fc:
        print(f"  {pattern_title}: no field caps returned", file=sys.stderr)
        return False

    # Map OpenSearch types to Dashboards field types
    _TYPE_MAP = {
        "date": "date",
        "integer": "number", "long": "number", "float": "number",
        "double": "number", "short": "number", "byte": "number",
        "ip": "ip",
        "boolean": "boolean",
        "keyword": "string", "text": "string",
    }

    fields = []
    for name, caps in fc["fields"].items():
        # Skip OpenSearch metadata fields (_id, _index, _score, _type, _source, ...).
        # Dashboards does not support index-pattern fields that start with an
        # underscore and will warn about them.
        if name.startswith("_"):
            continue
        for es_type, info in caps.items():
            fields.append({
                "name": name,
                "type": _TYPE_MAP.get(es_type, "string"),
                "esTypes": [es_type],
                "count": 0,
                "scripted": False,
                "searchable": info.get("searchable", True),
                "aggregatable": info.get("aggregatable", True),
                "readFromDocValues": info.get("aggregatable", True),
            })
            break  # Take first type per field

    # Fetch the current saved object, update its fields, PUT it back
    obj = dash_req("GET", f"/api/saved_objects/index-pattern/{pattern_id}")
    if not obj:
        return False
    attrs = obj["attributes"]
    attrs["fields"] = json.dumps(fields)
    put_resp = dash_req("PUT", f"/api/saved_objects/index-pattern/{pattern_id}",
                        {"attributes": attrs})
    if put_resp:
        ts = next((f for f in fields if f["name"] == "@timestamp"), None)
        ts_info = f", @timestamp={ts['type']}" if ts else ", @timestamp=MISSING"
        print(f"  {pattern_title}: {len(fields)} fields populated{ts_info}")
        return True
    return False


# ---------------------------------------------------------------------------
# Saved object creators
# ---------------------------------------------------------------------------

def _find_saved_object(obj_type, title):
    """Find a saved object by type and exact title. Returns id or None."""
    import urllib.parse
    encoded = urllib.parse.quote(title)
    resp = dash_req("GET", f"/api/saved_objects/_find?type={obj_type}&search={encoded}&per_page=100")
    if not resp:
        return None
    for obj in resp.get("saved_objects", []):
        if obj["attributes"].get("title") == title:
            return obj["id"]
    return None


def create_saved_search(title, description, query, index_pattern_id,
                        columns=None, sort=None):
    existing = _find_saved_object("search", title)
    search_source = json.dumps({
        "query": {"query": query, "language": "kuery"},
        "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
        "filter": [],
    })
    body = {
        "attributes": {
            "title": title,
            "description": description,
            "kibanaSavedObjectMeta": {"searchSourceJSON": search_source},
            "columns": columns or [],
            "sort": sort or [],
        },
        "references": [
            {"name": "kibanaSavedObjectMeta.searchSourceJSON.index",
             "type": "index-pattern", "id": index_pattern_id},
        ],
    }
    if existing:
        resp = dash_req("PUT", f"/api/saved_objects/search/{existing}", body)
        print(f"  saved search: {title} -> {existing} (updated)")
        return existing
    resp = dash_req("POST", "/api/saved_objects/search", body)
    oid = resp["id"] if resp else "?"
    print(f"  saved search: {title} -> {oid}")
    return oid


def create_viz(title, vis_type, aggs, params, index_pattern_id, schema="metric"):
    existing = _find_saved_object("visualization", title)
    if existing:
        print(f"  visualization: {title} -> {existing} (exists)")
        return existing
    vis_state = {
        "title": title,
        "type": vis_type,
        "params": params,
        "aggs": aggs,
    }
    search_source = json.dumps({
        "query": {"query": "", "language": "kuery"},
        "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
        "filter": [],
    })
    body = {
        "attributes": {
            "title": title,
            "visState": json.dumps(vis_state),
            "uiStateJSON": "{}",
            "description": "",
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": search_source},
        },
        "references": [
            {"name": "kibanaSavedObjectMeta.searchSourceJSON.index",
             "type": "index-pattern", "id": index_pattern_id},
        ],
    }
    resp = dash_req("POST", "/api/saved_objects/visualization", body)
    oid = resp["id"] if resp else "?"
    print(f"  visualization: {title} -> {oid}")
    return oid


def create_dashboard(title, panels, references):
    existing = _find_saved_object("dashboard", title)
    if existing:
        print(f"  dashboard: {title} -> {existing} (exists)")
        return existing
    body = {
        "attributes": {
            "title": title,
            "description": "",
            "panelsJSON": json.dumps(panels),
            "optionsJSON": json.dumps({"hidePanelTitles": False, "useMargins": True}),
            "version": 1,
            "timeRestore": False,
        },
        "references": references,
    }
    resp = dash_req("POST", "/api/saved_objects/dashboard", body)
    oid = resp["id"] if resp else "?"
    print(f"  dashboard: {title} -> {oid}")
    return oid


# ---------------------------------------------------------------------------
# Visualization builders — return (aggs, params) for create_viz
# ---------------------------------------------------------------------------

def agg_count(id="1"):
    return {"id": id, "type": "count", "schema": "metric", "params": {}}


def agg_terms(id, field, size=10, order="desc", order_by="1", schema="segment"):
    return {"id": id, "type": "terms", "schema": schema, "params": {
        "field": field, "size": size, "order": order, "orderBy": order_by,
    }}


def agg_date_histogram(id, field):
    return {"id": id, "type": "date_histogram", "schema": "segment", "params": {
        "field": field, "useNormalizedOpenSearchInterval": True,
        "min_doc_count": 1, "extended_bounds": {},
    }}


def agg_avg(id, field):
    return {"id": id, "type": "avg", "schema": "metric", "params": {"field": field}}


# Common axis/params templates

_AREA_PARAMS = {
    "type": "area",
    "addTooltip": True, "addLegend": True, "legendPosition": "right",
    "addTimeMarker": False, "times": [],
    "seriesParams": [{"show": True, "type": "area", "mode": "stacked",
                      "data": {"id": "1", "label": "Count"},
                      "drawLinesBetweenPoints": True, "showCircles": True,
                      "interpolate": "linear", "valueAxis": "ValueAxis-1"}],
    "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom",
                      "show": True, "style": {}, "scale": {"type": "linear"},
                      "labels": {"show": True, "truncate": 25}, "title": {}}],
    "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value",
                   "position": "left", "show": True, "style": {},
                   "scale": {"type": "linear", "mode": "normal"},
                   "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                   "title": {"text": "Count"}}],
    "grid": {"categoryLines": False, "style": {"color": "#eee"}},
}

_LINE_PARAMS = {
    "type": "line",
    "addTooltip": True, "addLegend": True, "legendPosition": "right",
    "seriesParams": [{"show": True, "type": "line", "mode": "normal",
                      "data": {"id": "1", "label": "Average"},
                      "drawLinesBetweenPoints": True, "showCircles": True,
                      "interpolate": "linear", "valueAxis": "ValueAxis-1"}],
    "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom",
                      "show": True, "style": {}, "scale": {"type": "linear"},
                      "labels": {"show": True, "truncate": 25}, "title": {}}],
    "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value",
                   "position": "left", "show": True, "style": {},
                   "scale": {"type": "linear", "mode": "normal"},
                   "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                   "title": {"text": "Avg ms"}}],
    "grid": {"categoryLines": False, "style": {"color": "#eee"}},
}

_PIE_PARAMS = {
    "type": "pie",
    "addTooltip": True, "addLegend": True, "legendPosition": "right",
    "isDonut": True,
    "labels": {"show": False, "values": True, "last_level": True, "truncate": 100},
}

_BAR_PARAMS = {
    "type": "histogram",
    "addTooltip": True, "addLegend": True, "legendPosition": "right",
    "seriesParams": [{"show": True, "type": "histogram", "mode": "stacked",
                      "data": {"id": "1", "label": "Count"},
                      "valueAxis": "ValueAxis-1"}],
    "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom",
                      "show": True, "style": {}, "scale": {"type": "linear"},
                      "labels": {"show": True, "truncate": 25}, "title": {}}],
    "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value",
                   "position": "left", "show": True, "style": {},
                   "scale": {"type": "linear", "mode": "normal"},
                   "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                   "title": {"text": "Count"}}],
    "grid": {"categoryLines": False, "style": {"color": "#eee"}},
}

_TABLE_PARAMS = {
    "perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False,
    "showTotal": False, "showToolbar": True, "totalFunc": "sum",
    "sort": {"columnIndex": None, "direction": None},
}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if not wait_for_dashboards():
        sys.exit(1)

    # Find index pattern IDs
    print("Finding index patterns...")
    corex_pattern_id = find_index_pattern("corex-log-*")
    waf_pattern_id = find_index_pattern("waf-logs-*")
    mcp_pattern_id = find_index_pattern("mcp-gateway-logs-*")

    if not corex_pattern_id:
        print("ERROR: index pattern 'corex-log-*' not found. Run setup-opensearch.sh first.",
              file=sys.stderr)
        sys.exit(1)
    if not waf_pattern_id:
        print("ERROR: index pattern 'waf-logs-*' not found. Run setup-opensearch.sh first.",
              file=sys.stderr)
        sys.exit(1)
    if not mcp_pattern_id:
        print("ERROR: index pattern 'mcp-gateway-logs-*' not found. Run setup-opensearch.sh first.",
              file=sys.stderr)
        sys.exit(1)

    print(f"  corex-log-* -> {corex_pattern_id}")
    print(f"  waf-logs-* -> {waf_pattern_id}")
    print(f"  mcp-gateway-logs-* -> {mcp_pattern_id}")

    combined_pattern_id = find_index_pattern("corex-log-*,waf-logs-*")
    if combined_pattern_id:
        print(f"  corex-log-*,waf-logs-* -> {combined_pattern_id}")
    else:
        print("  corex-log-*,waf-logs-* not found, creating...")
        combined_pattern_id = create_index_pattern("corex-log-*,waf-logs-*")

    # Populate index pattern field caches BEFORE creating visualizations.
    # This must run AFTER documents have been ingested so the field caps
    # return real mappings. Without this, Dashboards 3.x leaves the fields
    # array empty and visualizations fail with "Could not locate that
    # index-pattern-field" or "Saved field X is invalid for use with the
    # Terms aggregation".
    print("\nPopulating index pattern fields...")
    for title, pid in [("corex-log-*", corex_pattern_id),
                       ("waf-logs-*", waf_pattern_id),
                       ("mcp-gateway-logs-*", mcp_pattern_id),
                       ("corex-log-*,waf-logs-*", combined_pattern_id)]:
        if pid:
            ok = populate_index_pattern_fields(title, pid)
            if not ok:
                print(f"  {title}: FAILED", file=sys.stderr)

    # ---- Saved Searches ----
    print("\nCreating saved searches...")
    create_saved_search("4xx/5xx Errors", "HTTP 4xx and 5xx responses",
                        "status >= 400", corex_pattern_id)
    create_saved_search("Slow Requests (>1s)", "Requests with backend response time > 1000ms",
                        "be_response_time > 1000", corex_pattern_id)
    create_saved_search("WAF Blocked Requests", "WAF events with denied/blocked action",
                        'action: "denied" or action: "blocked"', waf_pattern_id)
    create_saved_search("Security Rule Hits", "Requests that triggered security rules",
                        "sec_rule: *", corex_pattern_id)

    # MCP Gateway saved searches
    create_saved_search("MCP Gateway Errors", "MCP Gateway requests with error status",
                        'status: "error"', mcp_pattern_id)
    create_saved_search("MCP Gateway Denied", "MCP Gateway requests that were denied",
                        'action: "deny"', mcp_pattern_id)
    create_saved_search("MCP Gateway DLP/Guardrail Hits",
                        "MCP Gateway requests that triggered DLP or guardrail rules",
                        "dlp_hits: * or guardrail_hits: *", mcp_pattern_id)
    create_saved_search("MCP Gateway Slow Requests (>1s)",
                        "MCP Gateway requests with latency > 1000ms",
                        "latency_ms > 1000", mcp_pattern_id)

    # Correlation saved search — spans both indices, sorted by timestamp
    if combined_pattern_id:
        create_saved_search(
            "Request Correlation (HAProxy + WAF)",
            "Combined view of HAProxy request logs and WAF events, correlated by unique_id. "
            "Filter by unique_id to see the full request lifecycle: HAProxy log entry + all WAF rule hits.",
            "unique_id: *", combined_pattern_id,
            columns=["@timestamp", "unique_id", "client", "client_ip",
                     "method", "path", "status", "action",
                     "rule_id", "msg", "severity", "uri"],
            sort=[["@timestamp", "desc"]])

    # ---- HAProxy Visualizations ----
    print("\nCreating HAProxy visualizations...")
    v_reqs_time = create_viz(
        "Requests Over Time", "area",
        [agg_count(), agg_date_histogram("2", "@timestamp"),
         {**agg_terms("3", "status", size=10, schema="group")}],
        _AREA_PARAMS, corex_pattern_id)

    v_status = create_viz(
        "Status Code Distribution", "pie",
        [agg_count(), agg_terms("2", "status", size=10)],
        _PIE_PARAMS, corex_pattern_id)

    v_top_ips = create_viz(
        "Top Client IPs", "table",
        [agg_count(), {**agg_terms("2", "client", size=20, schema="bucket"),
                       "params": {"field": "client", "size": 20, "order": "desc",
                                  "orderBy": "1", "customLabel": "Client IP"}}],
        _TABLE_PARAMS, corex_pattern_id)

    v_asn_orgs = create_viz(
        "Top ASN Organizations", "histogram",
        [agg_count(), agg_terms("2", "asn_org", size=10)],
        _BAR_PARAMS, corex_pattern_id)

    v_top_paths = create_viz(
        "Top Request Paths", "table",
        [agg_count(), {**agg_terms("2", "path", size=20, schema="bucket"),
                       "params": {"field": "path", "size": 20, "order": "desc",
                                  "orderBy": "1", "customLabel": "Request Path"}}],
        _TABLE_PARAMS, corex_pattern_id)

    v_avg_rt = create_viz(
        "Avg Response Time", "line",
        [agg_avg("1", "be_response_time"), agg_date_histogram("2", "@timestamp")],
        _LINE_PARAMS, corex_pattern_id)

    # ---- WAF Visualizations ----
    print("\nCreating WAF visualizations...")
    v_waf_time = create_viz(
        "WAF Events Over Time", "area",
        [agg_count(), agg_date_histogram("2", "@timestamp")],
        _AREA_PARAMS, waf_pattern_id)

    v_waf_messages = create_viz(
        "WAF Events by Message", "histogram",
        [agg_count(), agg_terms("2", "msg.keyword", size=15)],
        _BAR_PARAMS, waf_pattern_id)

    v_waf_actions = create_viz(
        "WAF Actions", "pie",
        [agg_count(), agg_terms("2", "action", size=10)],
        _PIE_PARAMS, waf_pattern_id)

    v_waf_ips = create_viz(
        "Top WAF Client IPs", "table",
        [agg_count(), {**agg_terms("2", "client_ip", size=20, schema="bucket"),
                       "params": {"field": "client_ip", "size": 20, "order": "desc",
                                  "orderBy": "1", "customLabel": "Client IP"}}],
        _TABLE_PARAMS, waf_pattern_id)

    # ---- MCP Gateway Visualizations ----
    print("\nCreating MCP Gateway visualizations...")
    v_mcp_time = create_viz(
        "MCP Requests Over Time", "area",
        [agg_count(), agg_date_histogram("2", "@timestamp"),
         {**agg_terms("3", "method", size=10, schema="group")}],
        _AREA_PARAMS, mcp_pattern_id)

    v_mcp_methods = create_viz(
        "MCP Method Distribution", "pie",
        [agg_count(), agg_terms("2", "method", size=10)],
        _PIE_PARAMS, mcp_pattern_id)

    v_mcp_actions = create_viz(
        "MCP Action Distribution", "pie",
        [agg_count(), agg_terms("2", "action", size=10)],
        _PIE_PARAMS, mcp_pattern_id)

    v_mcp_status = create_viz(
        "MCP Status Distribution", "pie",
        [agg_count(), agg_terms("2", "status", size=10)],
        _PIE_PARAMS, mcp_pattern_id)

    v_mcp_tools = create_viz(
        "Top MCP Tools", "table",
        [agg_count(), {**agg_terms("2", "tool", size=20, schema="bucket"),
                       "params": {"field": "tool", "size": 20, "order": "desc",
                                  "orderBy": "1", "customLabel": "Tool"}}],
        _TABLE_PARAMS, mcp_pattern_id)

    v_mcp_servers = create_viz(
        "Top MCP Servers", "table",
        [agg_count(), {**agg_terms("2", "server_name", size=20, schema="bucket"),
                       "params": {"field": "server_name", "size": 20, "order": "desc",
                                  "orderBy": "1", "customLabel": "Server"}}],
        _TABLE_PARAMS, mcp_pattern_id)

    v_mcp_identities = create_viz(
        "Top MCP Identities", "table",
        [agg_count(), {**agg_terms("2", "identity_name", size=20, schema="bucket"),
                       "params": {"field": "identity_name", "size": 20, "order": "desc",
                                  "orderBy": "1", "customLabel": "Identity"}}],
        _TABLE_PARAMS, mcp_pattern_id)

    v_mcp_latency = create_viz(
        "MCP Avg Latency", "line",
        [agg_avg("1", "latency_ms"), agg_date_histogram("2", "@timestamp")],
        _LINE_PARAMS, mcp_pattern_id)

    v_mcp_latency_tool = create_viz(
        "MCP Latency by Tool", "histogram",
        [agg_avg("1", "latency_ms"), agg_terms("2", "tool", size=15)],
        _BAR_PARAMS, mcp_pattern_id)

    # ---- Dashboards ----
    print("\nCreating dashboards...")

    # HAProxy Overview — 6 panels in a 48-col grid
    # Each panel needs a "version" field for Dashboards' migration logic
    # (is640To720Panel checks panel.version — null causes a crash).
    haproxy_panels = [
        {"panelIndex": 1, "gridData": {"x": 0, "y": 0, "w": 48, "h": 8, "i": "1"},
         "type": "visualization", "panelRefName": "panel_1", "version": "3.0.0"},
        {"panelIndex": 2, "gridData": {"x": 0, "y": 8, "w": 24, "h": 8, "i": "2"},
         "type": "visualization", "panelRefName": "panel_2", "version": "3.0.0"},
        {"panelIndex": 3, "gridData": {"x": 24, "y": 8, "w": 24, "h": 8, "i": "3"},
         "type": "visualization", "panelRefName": "panel_3", "version": "3.0.0"},
        {"panelIndex": 4, "gridData": {"x": 0, "y": 16, "w": 24, "h": 8, "i": "4"},
         "type": "visualization", "panelRefName": "panel_4", "version": "3.0.0"},
        {"panelIndex": 5, "gridData": {"x": 24, "y": 16, "w": 24, "h": 8, "i": "5"},
         "type": "visualization", "panelRefName": "panel_5", "version": "3.0.0"},
        {"panelIndex": 6, "gridData": {"x": 0, "y": 24, "w": 48, "h": 8, "i": "6"},
         "type": "visualization", "panelRefName": "panel_6", "version": "3.0.0"},
    ]
    haproxy_refs = [
        {"name": f"panel_{i+1}", "type": "visualization", "id": vid}
        for i, vid in enumerate([v_reqs_time, v_status, v_avg_rt,
                                 v_top_ips, v_asn_orgs, v_top_paths])
    ]
    create_dashboard("CoreX HAProxy Overview", haproxy_panels, haproxy_refs)

    # WAF Overview — 4 panels
    waf_panels = [
        {"panelIndex": 1, "gridData": {"x": 0, "y": 0, "w": 48, "h": 8, "i": "1"},
         "type": "visualization", "panelRefName": "panel_1", "version": "3.0.0"},
        {"panelIndex": 2, "gridData": {"x": 0, "y": 8, "w": 24, "h": 8, "i": "2"},
         "type": "visualization", "panelRefName": "panel_2", "version": "3.0.0"},
        {"panelIndex": 3, "gridData": {"x": 24, "y": 8, "w": 24, "h": 8, "i": "3"},
         "type": "visualization", "panelRefName": "panel_3", "version": "3.0.0"},
        {"panelIndex": 4, "gridData": {"x": 0, "y": 16, "w": 48, "h": 8, "i": "4"},
         "type": "visualization", "panelRefName": "panel_4", "version": "3.0.0"},
    ]
    waf_refs = [
        {"name": f"panel_{i+1}", "type": "visualization", "id": vid}
        for i, vid in enumerate([v_waf_time, v_waf_messages, v_waf_actions, v_waf_ips])
    ]
    create_dashboard("CoreX WAF Overview", waf_panels, waf_refs)

    # MCP Gateway Overview — 9 panels in a 48-col grid
    mcp_panels = [
        {"panelIndex": 1, "gridData": {"x": 0, "y": 0, "w": 48, "h": 8, "i": "1"},
         "type": "visualization", "panelRefName": "panel_1", "version": "3.0.0"},
        {"panelIndex": 2, "gridData": {"x": 0, "y": 8, "w": 16, "h": 8, "i": "2"},
         "type": "visualization", "panelRefName": "panel_2", "version": "3.0.0"},
        {"panelIndex": 3, "gridData": {"x": 16, "y": 8, "w": 16, "h": 8, "i": "3"},
         "type": "visualization", "panelRefName": "panel_3", "version": "3.0.0"},
        {"panelIndex": 4, "gridData": {"x": 32, "y": 8, "w": 16, "h": 8, "i": "4"},
         "type": "visualization", "panelRefName": "panel_4", "version": "3.0.0"},
        {"panelIndex": 5, "gridData": {"x": 0, "y": 16, "w": 24, "h": 8, "i": "5"},
         "type": "visualization", "panelRefName": "panel_5", "version": "3.0.0"},
        {"panelIndex": 6, "gridData": {"x": 24, "y": 16, "w": 24, "h": 8, "i": "6"},
         "type": "visualization", "panelRefName": "panel_6", "version": "3.0.0"},
        {"panelIndex": 7, "gridData": {"x": 0, "y": 24, "w": 16, "h": 8, "i": "7"},
         "type": "visualization", "panelRefName": "panel_7", "version": "3.0.0"},
        {"panelIndex": 8, "gridData": {"x": 16, "y": 24, "w": 16, "h": 8, "i": "8"},
         "type": "visualization", "panelRefName": "panel_8", "version": "3.0.0"},
        {"panelIndex": 9, "gridData": {"x": 32, "y": 24, "w": 16, "h": 8, "i": "9"},
         "type": "visualization", "panelRefName": "panel_9", "version": "3.0.0"},
    ]
    mcp_refs = [
        {"name": f"panel_{i+1}", "type": "visualization", "id": vid}
        for i, vid in enumerate([v_mcp_time, v_mcp_methods, v_mcp_actions,
                                 v_mcp_status, v_mcp_latency, v_mcp_latency_tool,
                                 v_mcp_tools, v_mcp_servers, v_mcp_identities])
    ]
    create_dashboard("MCP Gateway Overview", mcp_panels, mcp_refs)

    print("\nDashboard setup complete!")
    print(f"  Dashboards URL: {DASH_HOST}/app/dashboards")


if __name__ == "__main__":
    main()
