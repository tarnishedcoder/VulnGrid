# PR Security Bot

Tiny Flask + gidgethub app that receives `pull_request` webhooks and comments
with a sample CWE finding. It also pushes a placeholder finding to the backend
so it shows up on the dashboard.

## Registering the app

1. GitHub → Settings → Developer settings → GitHub Apps → New GitHub App.
2. Webhook URL: `http://<your-host>:8080/` (use ngrok while testing locally).
3. Webhook secret → `GITHUB_WEBHOOK_SECRET`.
4. Permissions: Pull requests (read), Issues / Pull-request comments (write).
5. Generate a private key → `GITHUB_PRIVATE_KEY`, note the App ID → `GITHUB_APP_ID`.
6. Install the app on your test repo.
7. Open a PR → the bot comments automatically.
