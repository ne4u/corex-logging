#!/usr/bin/env python3
"""
Delete OpenSearch Dashboards saved objects by type.

Useful when index mappings or field names change and you want to re-create
visualizations/dashboards from the latest setup-dashboards.py.

Examples:
  OPENSEARCH_ADMIN_PASSWORD=YourPassword ./scripts/delete-dashboards-objects.py
  OPENSEARCH_ADMIN_PASSWORD=YourPassword ./scripts/delete-dashboards-objects.py --types dashboard visualization
  OPENSEARCH_ADMIN_PASSWORD=YourPassword ./scripts/delete-dashboards-objects.py --dry-run
"""
import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.request

DASH_HOST = os.environ.get("DASH_HOST", "http://localhost:5601")
OS_USER = os.environ.get("OS_USER", "admin")
OS_PASS = os.environ.get("OPENSEARCH_ADMIN_PASSWORD")


def _auth_header() -> str:
    if not OS_PASS:
        raise SystemExit("Error: OPENSEARCH_ADMIN_PASSWORD must be set")
    return "Basic " + base64.b64encode(f"{OS_USER}:{OS_PASS}".encode()).decode()


def _request(method: str, path: str, body=None) -> dict:
    url = f"{DASH_HOST}/api/saved_objects{path}"
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", _auth_header())
    req.add_header("osd-xsrf", "true")
    if body:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        try:
            msg = json.load(e)
        except Exception:
            msg = e.read().decode(errors="replace")
        raise SystemExit(f"HTTP {e.code} for {method} {path}: {msg}") from e


def list_ids(obj_type: str) -> list[str]:
    ids: list[str] = []
    page = 1
    while True:
        resp = _request(
            "GET",
            f"/_find?type={obj_type}&per_page=100&page={page}&fields=id",
        )
        objects = resp.get("saved_objects", [])
        ids.extend(o["id"] for o in objects)
        if len(objects) < 100:
            break
        page += 1
    return ids


def delete_object(obj_type: str, obj_id: str, dry_run: bool) -> None:
    if dry_run:
        print(f"[dry-run] would delete {obj_type}: {obj_id}")
        return
    print(f"Deleting {obj_type}: {obj_id}")
    _request("DELETE", f"/{obj_type}/{obj_id}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Delete OpenSearch Dashboards saved objects"
    )
    parser.add_argument(
        "--types",
        nargs="+",
        default=["dashboard", "visualization"],
        help="Saved-object types to delete (default: dashboard visualization)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="List objects that would be deleted without deleting them",
    )
    args = parser.parse_args()

    for obj_type in args.types:
        ids = list_ids(obj_type)
        if not ids:
            print(f"No {obj_type} objects found")
            continue
        print(f"Found {len(ids)} {obj_type}(s)")
        for obj_id in ids:
            delete_object(obj_type, obj_id, args.dry_run)

    return 0


if __name__ == "__main__":
    sys.exit(main())
