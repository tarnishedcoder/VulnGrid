"""PR security bot: GitHub App webhook that comments on new PRs.

Register a GitHub App pointing its webhook at http://<host>:8080/ with the
same GITHUB_WEBHOOK_SECRET, install it on your repo, and open a PR.
"""
import asyncio
import datetime
import logging
import os

import aiohttp
import jwt
from flask import Flask, abort, request
from gidgethub import aiohttp as gh_aiohttp
from gidgethub import routing, sansio

app = Flask(__name__)
log = logging.getLogger("pr_bot")
logging.basicConfig(level=logging.INFO)

router = routing.Router()

APP_ID = os.getenv("GITHUB_APP_ID", "")
PRIVATE_KEY = os.getenv("GITHUB_PRIVATE_KEY", "").replace("\\n", "\n")
BACKEND_URL = os.getenv("BACKEND_URL", "http://backend:8000")


def create_jwt() -> str:
    if not APP_ID or not PRIVATE_KEY:
        raise RuntimeError("GITHUB_APP_ID / GITHUB_PRIVATE_KEY not configured")
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    payload = {"iat": now - 60, "exp": now + (10 * 60), "iss": APP_ID}
    return jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")


@router.register("pull_request", action="opened")
async def pr_opened(event, gh, *args, **kwargs):
    pr = event.data["pull_request"]
    repo = event.data["repository"]["full_name"]
    number = pr["number"]
    comment_body = (
        "🔐 **Security Bot**\n\n"
        "I scanned the diff and found a potential issue:\n\n"
        "- **CWE-78** (OS Command Injection) in `src/main.py:42`.\n"
        "- **Severity:** High\n"
        "- **Remediation:** Validate/whitelist any external input before using it in `subprocess` calls.\n"
    )
    await gh.post(f"/repos/{repo}/issues/{number}/comments", data={"body": comment_body})
    log.info("Commented on %s#%s", repo, number)
    payload = {
        "tool": "PR-Bot",
        "title": "OS Command Injection (CWE-78)",
        "description": "Potential command injection detected in PR diff.",
        "file_path": "src/main.py",
        "line": 42,
        "cwe": 78,
        "severity": "High",
        "status": "new",
    }
    try:
        async with aiohttp.ClientSession() as sess:
            async with sess.post(f"{BACKEND_URL.rstrip('/')}/findings/", json=payload, timeout=10) as resp:
                log.info("Pushed placeholder finding, backend status=%s", resp.status)
    except Exception as exc:  # noqa: BLE001
        log.warning("Could not push finding to backend: %s", exc)


@app.route("/", methods=["POST"])
def webhook():
    secret = os.getenv("GITHUB_WEBHOOK_SECRET")
    if not secret:
        abort(500, "Missing GITHUB_WEBHOOK_SECRET")
    try:
        event = sansio.Event.from_http(request.headers, request.data, secret=secret)
    except Exception as exc:  # noqa: BLE001
        log.error("Invalid webhook: %s", exc)
        abort(400, "Invalid webhook signature")

    async def run():
        async with aiohttp.ClientSession() as session:
            gh = gh_aiohttp.GitHubAPI(session, "vulngrid-bot", oauth_token=create_jwt())
            await router.dispatch(event, gh)

    try:
        asyncio.run(run())
    except RuntimeError as exc:
        log.error("Bot misconfigured: %s", exc)
        abort(500, str(exc))
    return "", 204


@app.route("/health", methods=["GET"])
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
