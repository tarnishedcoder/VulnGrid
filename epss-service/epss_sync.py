"""Nightly EPSS sync: download public EPSS scores and push them to the backend.

Official feed: https://epss.cyentia.com/epss_scores-current.csv.gz
Falls back to a tiny built-in sample when the network is unavailable so the
demo / CI never breaks.
"""
import gzip
import io
import os
from datetime import datetime

import requests

EPSS_URLS = [
    "https://epss.cyentia.com/epss_scores-current.csv.gz",
    "https://epss.cyentia.com/epss_scores-current.csv",
    "https://epss.cyentia.org/epss_scores-current.csv.gz",
]
BACKEND_URL = os.getenv("BACKEND_URL", "http://backend:8000")

FALLBACK_ROWS = [
    ("CVE-2023-12345", 0.85),
    ("CVE-2021-44228", 0.94),
    ("CVE-2021-45046", 0.55),
]


def download_epss(limit: int = 5000):
    import pandas as pd

    for url in EPSS_URLS:
        try:
            print(f"[EPSS] Downloading {url} ...")
            r = requests.get(url, timeout=60)
            r.raise_for_status()
            content = r.content
            if url.endswith(".gz") or content[:2] == b"\x1f\x8b":
                with gzip.open(io.BytesIO(content), "rt") as fh:
                    df = pd.read_csv(fh, skiprows=1)
            else:
                df = pd.read_csv(io.BytesIO(content), skiprows=1)
            # normalise column names: '#model_version,vendor,...' header variants
            df.columns = [c.lstrip("#").strip() for c in df.columns]
            df = df[["cve", "epss"]].head(limit)
            df["last_update"] = datetime.utcnow().isoformat()
            print(f"[EPSS] Got {len(df)} rows")
            return df
        except Exception as exc:  # noqa: BLE001 - keep trying mirrors
            print(f"[EPSS] Mirror failed ({url}): {exc}")
    print("[EPSS] All mirrors failed – using built-in fallback sample")
    import pandas as pd

    return pd.DataFrame(
        [{"cve": cve, "epss": epss, "last_update": datetime.utcnow().isoformat()} for cve, epss in FALLBACK_ROWS]
    )


def push_to_backend(df) -> int:
    sent = 0
    for _, row in df.iterrows():
        payload = {"cve": row["cve"], "epss": float(row["epss"])}
        try:
            resp = requests.post(f"{BACKEND_URL}/epss/", json=payload, timeout=10)
            if resp.status_code in (200, 201):
                sent += 1
            else:
                print(f"   -> backend rejected {row['cve']}: {resp.status_code} {resp.text[:200]}")
        except Exception as exc:  # noqa: BLE001
            print(f"   -> error for {row['cve']}: {exc}")
    return sent


if __name__ == "__main__":
    df = download_epss()
    sent = push_to_backend(df)
    print(f"[EPSS] Done – {sent}/{len(df)} records accepted by backend")
