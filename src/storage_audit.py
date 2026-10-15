"""
Defensive local-storage pattern scanner (static, no exfiltration).

Flags code patterns that HISTORICALLY led to M2 / MASVS-STORAGE failures,
and points to 2026 replacements. Does not read device data, does not bypass
sandbox, does not decrypt anything.

2026 context (verified via live web search 2026-10-15):
- Jetpack Security EncryptedSharedPreferences / EncryptedFile is DEPRECATED; do not adopt for new code.
- Current direction: Jetpack DataStore (proto/preferences) + Android Keystore for keys,
  SQLCipher / encrypted DB where needed, scoped storage, allowBackup=false or curated rules.
Refs:
- https://developer.android.com/privacy-and-security/risks
- https://mas.owasp.org/MASTG/best-practices/
"""
from __future__ import annotations
import re
from pathlib import Path
from dataclasses import dataclass, asdict

PATTERNS = [
    ("STORAGE-001", "HIGH", r"MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE",
     "World-readable/world-writable mode. Any app could read/write.",
     "Remove; use MODE_PRIVATE + Keystore/DataStore; never world-accessible."),
    ("STORAGE-002", "MEDIUM", r"getSharedPreferences\s*\(",
     "Unencrypted SharedPreferences usage site. Review what is stored.",
     "Do not store tokens/passwords/PII in cleartext prefs. Migrate to DataStore with Keystore-backed encryption; set allowBackup/dataExtractionRules."),
    ("STORAGE-003", "INFO", r"EncryptedSharedPreferences",
     "Deprecated Jetpack Security API detected.",
     "Plan migration to DataStore + Keystore per 2026 guidance; do not start new code on deprecated crypto wrapper."),
    ("STORAGE-004", "MEDIUM", r"getExternalStorageDirectory|getExternalFilesDir|Environment\.getExternalStorage",
     "External/scoped-storage write. World-accessible history; scoped storage limits but misuse persists.",
     "Avoid sensitive data on external storage; use internal storage + encryption; request minimal permissions."),
    ("STORAGE-005", "MEDIUM", r"android\.util\.Log\.(d|v|i)\s*\(.*(password|token|secret|ssn|credit|pin)",
     "Potential sensitive data in logcat.",
     "Remove sensitive logs; guard with BuildConfig.DEBUG only for non-sensitive diagnostics."),
    ("STORAGE-006", "LOW", r"http://",
     "Cleartext http:// string in source (candidate, needs network-config review).",
     "Enforce https:// + Network Security Config; set usesCleartextTraffic=false."),
]

@dataclass
class Hit:
    check_id: str
    severity: str
    file: str
    line: int
    match: str
    guidance: str

def scan_paths(paths: list[str | Path]) -> list[dict]:
    hits: list[Hit] = []
    compiled = [(cid, sev, re.compile(rx, re.IGNORECASE), msg + " " + guide) for cid, sev, rx, msg, guide in PATTERNS]
    files: list[Path] = []
    for base in paths:
        b = Path(base)
        if b.is_file():
            files.append(b)
        elif b.is_dir():
            for ext in ("*.java", "*.kt", "*.xml", "*.gradle", "*.gradle.kts"):
                files.extend(b.rglob(ext))
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            for cid, sev, rx, guide in compiled:
                # Reduce namespace noise: xmlns declarations contain http:// but are not cleartext traffic
                if cid == "STORAGE-006" and "xmlns" in line:
                    continue
                m = rx.search(line)
                if m:
                    hits.append(Hit(cid, sev, str(f), i, m.group(0)[:120], guide))
    return [asdict(h) for h in hits]

if __name__ == "__main__":
    import json, sys
    print(json.dumps(scan_paths(sys.argv[1:]), indent=2))
