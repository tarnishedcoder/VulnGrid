#!/usr/bin/env python3
"""Black Duck (SCA) wrapper stub."""
import json, os, sys
from pathlib import Path
import requests

def normalise(raw: dict) -> dict:
    return {
        "tool": "BlackDuck",
        "title": raw.get("vulnerabilityName", raw.get("title", "Black Duck finding")),
        "description": raw.get("description", ""),
        "file_path": raw.get("component", raw.get("file_path", "")),
        "line": None,
        "cve": raw.get("cve"),
        "cwe": raw.get("cwe"),
        "cvss": float(raw["cvssScore"]) if raw.get("cvssScore") else raw.get("cvss"),
        "severity": raw.get("severity", "Medium"),
        "status": "new",
    }

if __name__ == "__main__":
    if len(sys.argv) != 2: sys.exit("Usage: python upload.py <blackduck.json>")
    p = Path(sys.argv[1])
    if not p.is_file(): sys.exit(f"Not found: {p}")
    data = json.loads(p.read_text(encoding="utf-8"))
    items = data if isinstance(data, list) else data.get("findings", [])
    backend = os.getenv("BACKEND_URL", "http://localhost:8000")
    ok = sum(1 for raw in items if requests.post(f"{backend.rstrip('/')}/findings/", json=normalise(raw), timeout=10).status_code in (200, 201))
    print(f"Uploaded {ok}/{len(items)} Black Duck findings to {backend}")
