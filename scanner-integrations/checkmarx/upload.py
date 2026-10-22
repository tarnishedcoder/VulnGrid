#!/usr/bin/env python3
"""Checkmarx wrapper: read a static JSON export, normalise, POST to /findings.

Usage:
    python upload.py <path-to-checkmarx-export.json>

Replace load_export() with a real Checkmarx CLI/API call when credentials
are available. The normalise() mapping is the only tool-specific part.
"""
import json
import os
import sys
from pathlib import Path

import requests


def load_export(export_path: Path):
    if not export_path.is_file():
        sys.exit(f"Export file not found: {export_path}")
    with open(export_path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return data if isinstance(data, list) else data.get("findings", data.get("results", []))


def normalise(raw: dict) -> dict:
    return {
        "tool": "Checkmarx",
        "title": raw.get("category") or raw.get("title", "Unknown"),
        "description": raw.get("description", ""),
        "file_path": raw.get("fileName") or raw.get("file_path", ""),
        "line": raw.get("line"),
        "cve": raw.get("cve"),
        "cwe": int(raw["cweId"]) if raw.get("cweId") else raw.get("cwe"),
        "cvss": float(raw["cvssScore"]) if raw.get("cvssScore") else raw.get("cvss"),
        "severity": raw.get("severity", "Medium"),
        "status": "new",
    }


def push(api_url: str, payload: dict) -> bool:
    resp = requests.post(f"{api_url.rstrip('/')}/findings/", json=payload, timeout=10)
    if resp.status_code not in (200, 201):
        print(f"  error {resp.status_code}: {resp.text[:300]}")
        return False
    return True


def main() -> None:
    if len(sys.argv) != 2:
        sys.exit("Usage: python upload.py <path-to-checkmarx-export.json>")
    data = load_export(Path(sys.argv[1]))
    backend = os.getenv("BACKEND_URL", "http://localhost:8000")
    ok = sum(1 for raw in data if push(backend, normalise(raw)))
    print(f"Uploaded {ok}/{len(data)} findings to {backend}")


if __name__ == "__main__":
    main()
