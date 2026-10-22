# Checkmarx Wrapper

Thin wrapper that reads a static JSON export from Checkmarx and pushes each
finding to the Security Delivery Lab API.

## How to use

```bash
# 1. Export a Checkmarx scan to JSON (UI or CLI)
# 2. Run the wrapper
python scanner-integrations/checkmarx/upload.py samples/checkmarx-export.json
```

With Docker:

```bash
docker run --rm -v ${PWD}/samples:/data \
  -e BACKEND_URL=http://host.docker.internal:8000 \
  python:3.12-slim python /data/upload.py /data/checkmarx-export.json
```

When you have a real scanner, replace `load_export()` with the CLI call that
streams JSON to stdout. Only `normalise()` is tool-specific.
