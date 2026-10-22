#!/usr/bin/env python3
"""Fortify wrapper (stub). Replace load_export() with the real SSC/fcli export."""
import json, os, sys
from pathlib import Path
import requests

def load_export(p: Path):
    return json.loads(p.read_text(encoding="utf-8")) if p.is_file() else sys.exit(f"Not found: {p}")

def normalise(raw: dict) -> dict:
    return {
        "tool": "Fortify",
        "title": raw.get("category") or raw.get("title", "Fortify finding"),
        "description": raw.get("description", raw.get("brief", "")),
        "file_path": raw.get("fileName") or raw.get("file_path", ""),
        "line": raw.get("line"),
        "cve": raw.get("cve"),
        "cwe": int(raw["cweId"]) if raw.get("cweId") else raw.get("cwe"),
        "cvss": float(raw["cvssScore"]) if raw.get("cvssScore") else raw.get("cvss"),
        "severity": raw.get("severity", "Medium"),
        "status": "new",
    }

if __name__ == "__main__":
    if len(sys.argv) != 2: sys.exit("Usage: python upload.py <export.json>")
    data = load_export(Path(sys.argv[1]))
    items = data if isinstance(data, list) else data.get("findings", [])
    backend = os.getenv("BACKEND_URL", "http://localhost:8000")
    ok = 0
    for raw in items:
        r = requests.post(f"{backend.rstrip('/')}/findings/", json=normalise(raw), timeout=10)
        ok += r.status_code in (200, 201)
    print(f"Uploaded {ok}/{len(items)} Fortify findings to {backend}")
