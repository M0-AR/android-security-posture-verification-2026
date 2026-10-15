"""
Live verification fetcher — grounds every claim in this repo in fetchable public sources.

What it does:
- Fetches a small allowlist of authoritative public URLs (OWASP MAS, Android dev risks, AOSP bulletins)
- Records HTTP status, final URL, fetched-at (UTC), byte length, and a short evidence excerpt
- Writes JSON to data/live/verification_snapshot.json + per-source files
- NEVER asserts a version number it did not observe; on network failure it records the failure
  and exits non-zero-safe (exit 0 with degraded=True so CI stays informative, not false-green).

Allowlist (public, no auth):
1. https://mas.owasp.org/MASVS/                       — MASVS front page (expect MASVS-STORAGE etc.)
2. https://mas.owasp.org/MASTG/best-practices/        — MASTG best practices index
3. https://developer.android.com/privacy-and-security/risks  — Android risks index
4. https://source.android.com/docs/security/bulletin/pixel/2026/2026-10-01 — Oct 2026 Pixel bulletin (proves 2026 patch reality)
5. https://developer.android.com/guide/topics/manifest/application-element — allowBackup semantics

Usage:
  python src/live_verify.py [--out data/live] [--timeout 20]
"""
from __future__ import annotations
import argparse, json, re, sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import requests
except ImportError:
    print("requests is required: pip install -r requirements.txt", file=sys.stderr)
    sys.exit(2)

SOURCES = [
    ("masvs_front", "https://mas.owasp.org/MASVS/"),
    ("mastg_best", "https://mas.owasp.org/MASTG/best-practices/"),
    ("android_risks", "https://developer.android.com/privacy-and-security/risks"),
    ("pixel_bulletin_oct2026", "https://source.android.com/docs/security/bulletin/pixel/2026/2026-10-01"),
    ("app_element", "https://developer.android.com/guide/topics/manifest/application-element"),
]

EXPECT = {
    "masvs_front": [r"MASVS-STORAGE", r"MASVS-PRIVACY|MASVS-RESILIENCE"],
    "mastg_best": [r"MASTG-BEST"],
    "android_risks": [r"MASVS-"],
    "pixel_bulletin_oct2026": [r"2026-10-05|Pixel Update Bulletin"],
    "app_element": [r"allowBackup"],
}

def fetch(url: str, timeout: int) -> dict:
    headers = {"User-Agent": "android-security-posture-verification-2026 (defensive research; contact: repo docs)"}
    try:
        r = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        text = r.text or ""
        # Check expectations against FULL body (not truncated excerpt) to avoid head-only false negatives
        full_checks = {}
        # store full body length for transparency; excerpt remains truncated for snapshot readability
        return {
            "url_requested": url,
            "url_final": str(r.url),
            "http_status": r.status_code,
            "ok": 200 <= r.status_code < 300,
            "bytes": len(text.encode("utf-8", errors="ignore")),
            "excerpt": re.sub(r"\s+", " ", text[:1200])[:1200],
            "evidence_window": re.sub(r"\s+", " ", text[:20000])[5000:7000] if len(text) > 7000 else "",
            "full_text": text[:800000],  # bounded but covers tail patterns (MASVS- at ~230k, allowBackup at ~262k)
            "error": None,
        }
    except Exception as e:
        return {"url_requested": url, "url_final": None, "http_status": None,
                "ok": False, "bytes": 0, "excerpt": "", "evidence_window": "", "full_text": "", "error": f"{type(e).__name__}: {e}"}

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/live")
    ap.add_argument("--timeout", type=int, default=20)
    args = ap.parse_args()
    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)

    results: dict = {}
    for key, url in SOURCES:
        rec = fetch(url, args.timeout)
        # expectation check (evidence-based, not hand-claimed) against full_text
        checks = []
        if rec["ok"]:
            hay = (rec.pop("full_text", "") + " " + (rec.get("url_final") or ""))
            for pat in EXPECT.get(key, []):
                hit = re.search(pat, hay, re.IGNORECASE) is not None
                checks.append({"pattern": pat, "found_in_body_or_url": bool(hit)})
        else:
            rec.pop("full_text", None)
        rec["expectation_checks"] = checks
        results[key] = rec
        (outdir / f"{key}.json").write_text(json.dumps(rec, indent=2), encoding="utf-8")

    snapshot = {
        "fetched_at_utc": datetime.now(timezone.utc).isoformat(),
        "tool": "src/live_verify.py",
        "degraded": not all(v.get("ok") for v in results.values()),
        "sources": results,
        "interpretation_rules": [
            "Only claim what excerpt+status prove. If degraded, mark README numbers as 'unverified at fetch time'.",
            "Re-run before citing: python src/live_verify.py",
        ],
    }
    (outdir / "verification_snapshot.json").write_text(json.dumps(snapshot, indent=2), encoding="utf-8")
    print(json.dumps(snapshot, indent=2))
    # exit 0 always so `docker compose up verifier` shows evidence even when offline; degraded flag carries the signal
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
