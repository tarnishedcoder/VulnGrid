#!/usr/bin/env python3
"""SonarQube wrapper: maps SonarQube issues API JSON to Finding schema.

Export with: curl -u TOKEN: "$SONAR_HOST/api/issues/search?componentKeys=proj" > sonar.json
"""
import json, os, sys
from pathlib import Path
import requests

SEV_MAP = {"BLOCKER": "Critical", "CRITICAL": "High", "MAJOR": "Medium", "MINOR": "Low", "INFO": "Low"}

def load_export(p: Path):
    if not p.is_file(): sys.exit(f"Not found: {p}")
    data = json.loads(p.read_text(encoding="utf-8"))
    return data if isinstance(data, list) else data.get("issues", data.get("findings", []))

def normalise(raw: dict) -> dict:
    loc = raw.get("textRange", {}) or {}
    return {
        "tool": "SonarQube",
        "title": raw.get("rule", raw.get("category", "SonarQube issue")),
        "description": raw.get("message", raw.get("description", "")),
        "file_path": raw.get("component", raw.get("file_path", "")),
        "line": (loc.get("startLine") or raw.get("line")),
        "cve": raw.get("cve"),
        "cwe": raw.get("cwe"),
        "cvss": raw.get("cvss"),
        "severity": SEV_MAP.get(str(raw.get("severity", "MAJOR")).upper(), "Medium"),
        "status": "new",
    }

if __name__ == "__main__":
    if len(sys.argv) != 2: sys.exit("Usage: python upload.py <sonar.json>")
    items = load_export(Path(sys.argv[1]))
    backend = os.getenv("BACKEND_URL", "http://localhost:8000")
    ok = sum(1 for raw in items if requests.post(f"{backend.rstrip('/')}/findings/", json=normalise(raw), timeout=10).status_code in (200, 201))
    print(f"Uploaded {ok}/{len(items)} SonarQube findings to {backend}")
