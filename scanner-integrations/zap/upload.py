#!/usr/bin/env python3
"""OWASP ZAP wrapper: reads ZAP JSON report (zap.json) -> Finding schema."""
import json, os, sys
from pathlib import Path
import requests

RISK_MAP = {"3": "High", "2": "Medium", "1": "Low", "0": "Low", "High": "High", "Medium": "Medium", "Low": "Low"}

def normalise(raw: dict) -> dict:
    return {
        "tool": "ZAP",
        "title": raw.get("alert", raw.get("title", "ZAP alert")),
        "description": raw.get("description", ""),
        "file_path": raw.get("url", raw.get("file_path", "")),
        "line": None,
        "cve": raw.get("cve"),
        "cwe": int(raw["cweid"]) if str(raw.get("cweid", "")).isdigit() else raw.get("cwe"),
        "cvss": raw.get("cvss"),
        "severity": RISK_MAP.get(str(raw.get("risk", "Medium")), "Medium"),
        "status": "new",
    }

if __name__ == "__main__":
    if len(sys.argv) != 2: sys.exit("Usage: python upload.py <zap.json>")
    p = Path(sys.argv[1])
    if not p.is_file(): sys.exit(f"Not found: {p}")
    data = json.loads(p.read_text(encoding="utf-8"))
    items = data if isinstance(data, list) else data.get("site", data.get("alerts", data.get("findings", [])))
    if items and isinstance(items[0], dict) and "alerts" in items[0]:
        flat = []
        for site in items: flat.extend(site.get("alerts", []))
        items = flat
    backend = os.getenv("BACKEND_URL", "http://localhost:8000")
    ok = sum(1 for raw in items if requests.post(f"{backend.rstrip('/')}/findings/", json=normalise(raw), timeout=10).status_code in (200, 201))
    print(f"Uploaded {ok}/{len(items)} ZAP findings to {backend}")
