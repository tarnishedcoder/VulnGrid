#!/usr/bin/env python3
"""Snyk wrapper: `snyk test --json` output -> Finding schema."""
import json, os, sys
from pathlib import Path
import requests

def load_export(p: Path):
    if not p.is_file(): sys.exit(f"Not found: {p}")
    data = json.loads(p.read_text(encoding="utf-8"))
    if isinstance(data, list): return data
    return data.get("vulnerabilities", data.get("findings", []))

def normalise(raw: dict) -> dict:
    return {
        "tool": "Snyk",
        "title": raw.get("title", "Snyk vulnerability"),
        "description": raw.get("description", ""),
        "file_path": raw.get("from", [""])[-1] if isinstance(raw.get("from"), list) else str(raw.get("packageName", "")),
        "line": None,
        "cve": (raw.get("identifiers", {}).get("CVE", [None])[0] if isinstance(raw.get("identifiers"), dict) else raw.get("cve")),
        "cwe": None,
        "cvss": float(raw.get("cvssScore", 0) or 0) or None,
        "severity": str(raw.get("severity", "medium")).capitalize(),
        "status": "new",
    }

if __name__ == "__main__":
    if len(sys.argv) != 2: sys.exit("Usage: python upload.py <snyk.json>")
    items = load_export(Path(sys.argv[1]))
    backend = os.getenv("BACKEND_URL", "http://localhost:8000")
    ok = sum(1 for raw in items if requests.post(f"{backend.rstrip('/')}/findings/", json=normalise(raw), timeout=10).status_code in (200, 201))
    print(f"Uploaded {ok}/{len(items)} Snyk findings to {backend}")
