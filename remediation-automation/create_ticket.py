#!/usr/bin/env python3
"""Create a GitHub Issue (remediation ticket) for a CVE stored in the backend.

Usage:
    python create_ticket.py CVE-2023-12345

Env: GITHUB_TOKEN, GITHUB_REPO (e.g. owner/repo), BACKEND_URL
"""
import os
import sys

import requests

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")
REPO = os.getenv("GITHUB_REPO")


def create_github_issue(title: str, body: str) -> str:
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    url = f"https://api.github.com/repos/{REPO}/issues"
    payload = {"title": title, "body": body, "labels": ["security", "remediation"]}
    r = requests.post(url, json=payload, headers=headers, timeout=15)
    r.raise_for_status()
    return r.json()["html_url"]


def main() -> None:
    if not GITHUB_TOKEN or not REPO:
        sys.exit("Set GITHUB_TOKEN and GITHUB_REPO environment variables")
    if len(sys.argv) != 2:
        sys.exit("Usage: create_ticket.py <CVE-ID>")
    cve = sys.argv[1].upper()
    r = requests.get(f"{BACKEND_URL.rstrip('/')}/findings/", timeout=15)
    r.raise_for_status()
    findings = r.json()
    match = next((f for f in findings if (f.get("cve") or "").upper() == cve), None)
    if not match:
        sys.exit(f"No finding with CVE {cve} found in the backend")

    title = f"Remediation – {cve} ({match['title']})"
    body = f"""**CVE:** {cve}
**Tool:** {match.get('tool')}
**Severity:** {match.get('severity')}
**CVSS:** {match.get('cvss', 'N/A')}
**EPSS:** {match.get('epss', 'N/A')}
**Location:** `{match.get('file_path')}` line {match.get('line')}

**Description**
{match.get('description')}

**Suggested remediation**
> Add the concrete fix here – e.g. upgrade library X to >= 1.2.3, parameterize queries, etc.

---

*Ticket generated automatically by `remediation-automation`.*
"""
    issue_url = create_github_issue(title, body)
    print(f"Issue created: {issue_url}")


if __name__ == "__main__":
    main()
