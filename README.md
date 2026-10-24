# VulnGrid 

> End-to-end open-source showcase of a **full Application Security / DevSecOps pipeline**.

##  What's inside?

| Component | Description |
|-----------|-------------|
| **backend** | FastAPI service that stores normalized findings, enriches them with EPSS, and calculates a risk-score (`CVSS × EPSS × 10`). |
| **scanner-integrations** | Thin wrappers for Checkmarx, Fortify, SonarQube, Snyk, Black Duck, Burp Suite, OWASP ZAP. Each reads a JSON export, normalises it, and POSTs to `/findings`. |
| **epss-service** | Daily job that downloads the public EPSS CSV and stores the score alongside each CVE. |
| **dashboard** | React 18 + Vite + Material-UI table with colour-coded risk and filters. |
| **pr-security-bot** | GitHub App (Flask + gidgethub) that comments on new PRs with CWE references and pushes a placeholder finding. |
| **remediation-automation** | Script that creates a GitHub Issue for a given CVE, pre-filled with CVSS/EPSS/remediation template. |
| **docs** | MkDocs handbook – OWASP Top 10, CWE mapping, SSDLC checklist. |

##  Quick start (local)

```bash
# 1. Clone the repo
git clone https://github.com/tarnishedcoder/VulnGrid.git
cd VulnGrid

# 2. (Optional) configure secrets
cp .env.example .env   # fill in GITHUB_* values for bot + remediation

# 3. Bring up the whole stack
docker compose up -d --build

# 4. Verify API health
curl http://localhost:8000/health   # {"status":"ok"}
curl http://localhost:8000/docs     # Swagger UI (in browser)

# 5. Open the dashboard
# http://localhost:3000

# 6. Push sample findings (no scanner needed)
python scanner-integrations/checkmarx/upload.py samples/checkmarx-export.json

# 7. Enrich with EPSS (uses live feed, falls back to sample offline)
docker compose run --rm epss
```

You should now see the uploaded findings in the dashboard with risk scores.

##  Without Docker (backend only)

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate  |  Linux/macOS: source .venv/bin/activate
pip install -r backend/requirements.txt
set SQLITE_FILE=%CD%\backend\app\db\sqlite.db
uvicorn backend.app.main:app --reload --port 8000
```

##  API cheat sheet

```bash
# Create
curl -X POST http://localhost:8000/findings/ -H "Content-Type: application/json" \
  -d '{"tool":"Checkmarx","title":"SQL Injection","file_path":"src/main.py","line":42,"cve":"CVE-2023-12345","cwe":89,"cvss":9.1,"severity":"Critical"}'

# List / filter
curl "http://localhost:8000/findings/?severity=Critical"
curl "http://localhost:8000/findings/?min_cvss=7&min_epss=0.2"

# Attach EPSS
curl -X POST http://localhost:8000/epss/ -H "Content-Type: application/json" \
  -d '{"cve":"CVE-2023-12345","epss":0.85}'

# Remediation ticket
set GITHUB_TOKEN=ghp_...& set GITHUB_REPO=owner/repo
python remediation-automation/create_ticket.py CVE-2023-12345
```

Risk formula: `risk = round(cvss × epss × 10, 2)` → 0–100.
CI gate fails a PR when any finding has `CVSS ≥ 7.0 and EPSS ≥ 0.2`.

##  PR bot setup

1. GitHub → Settings → Developer settings → GitHub Apps → New GitHub App.
2. Webhook URL `http://<host>:8080/`, secret → `GITHUB_WEBHOOK_SECRET`.
3. Permissions: Pull requests (read), Issues/PR comments (write).
4. Install on your repo, open a PR → bot comments + finding appears on dashboard.

##  Docs

```bash
pip install mkdocs-material
mkdocs serve -f docs/mkdocs.yml   # http://127.0.0.1:8000
```

Published to GitHub Pages by `.github/workflows/docs.yml`.

##  Tech stack (all free / open-source)

API: FastAPI, SQLModel, SQLite (swap `SQLITE_FILE`/engine URL for Postgres) ·
CI: GitHub Actions · Dashboard: React 18 + Vite + MUI ·
Bot: Flask + gidgethub · Automation: Python + GitHub Issues API ·
Docs: MkDocs-Material · Containers: Docker Compose

## 📜 License

MIT – fork and extend freely.
