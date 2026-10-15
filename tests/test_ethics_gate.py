"""Ethics gate: fail if offensive payload/bypass strings are introduced."""
from pathlib import Path

FORBIDDEN = [
    "gesture.key", "password.key", "locksettings.db",
    "am start -n", "am broadcast", "content query --uri content://",
    "webview_addjavascriptinterface", "TrustKiller",
    "Runtime.getRuntime().exec", "in.readLine()",
    "BasicNameValuePair", "UrlEncodedFormEntity",
    "ettercap", "msfconsole",
]

def test_no_forbidden_strings():
    # Gate applies to executable / fixture surface (where payloads would run),
    # not to prose docs (ETHICS.md must be allowed to NAME prohibited topics to forbid them).
    root = Path(__file__).resolve().parents[1]
    offenders = []
    scan_roots = [root / "src", root / "fixtures", root / "tests"]
    scan_files = []
    for sr in scan_roots:
        if sr.exists():
            scan_files.extend(sr.rglob("*.py"))
            scan_files.extend(sr.rglob("*.java"))
            scan_files.extend(sr.rglob("*.kt"))
            scan_files.extend(sr.rglob("*.xml"))
    # also gate container entrypoints
    for extra in ["Dockerfile", "docker-compose.yml"]:
        p = root / extra
        if p.exists():
            scan_files.append(p)
    for p in scan_files:
        if ".git" in str(p):
            continue
        try:
            t = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        if p.name == "test_ethics_gate.py":
            continue
        for s in FORBIDDEN:
            if s in t:
                offenders.append(f"{p}:{s}")
    assert not offenders, f"Offensive/bypass strings introduced (see ETHICS.md): {offenders[:20]}"
