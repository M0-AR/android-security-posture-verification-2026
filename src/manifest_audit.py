"""
Defensive AndroidManifest posture auditor.

Scope: strictly defensive. Parses a manifest and FLAGS risky posture.
Does NOT launch components, craft intents, query providers, or bypass anything.
Use only on apps you own or are authorized to test (see ETHICS.md).

Checks (traceable to 2026 sources):
- MASVS-PLATFORM / MASTG-BEST-0052: exported components must be explicit + guarded
- Android 12+ (API 31): components with intent-filter must declare android:exported explicitly
- android:debuggable must be false in release
- android:allowBackup should be false OR governed by backup rules for sensitive apps
- cleartextTraffic / networkSecurityConfig posture
Refs:
- https://developer.android.com/privacy-and-security/risks/android-exported
- https://developer.android.com/privacy-and-security/risks/access-control-to-exported-components
- https://mas.owasp.org/MASTG/best-practices/MASTG-BEST-0052/
"""
from __future__ import annotations
import xml.etree.ElementTree as ET
from dataclasses import dataclass, asdict
from pathlib import Path

ANDROID_NS = "http://schemas.android.com/apk/res/android"

def _attr(el: ET.Element, name: str) -> str | None:
    return el.get(f"{{{ANDROID_NS}}}{name}")

@dataclass
class Finding:
    check_id: str
    severity: str  # INFO, LOW, MEDIUM, HIGH
    component: str
    message: str
    remediation: str

def audit_manifest(manifest_path: str | Path) -> list[dict]:
    p = Path(manifest_path)
    tree = ET.parse(p)
    root = tree.getroot()
    findings: list[Finding] = []

    app = root.find("application")
    if app is None:
        return [asdict(Finding("MANIFEST-001", "LOW", "manifest",
            "No <application> node found; cannot assess posture.",
            "Provide a valid AndroidManifest.xml."))]

    # 1. debuggable
    debuggable = _attr(app, "debuggable")
    if debuggable == "true":
        findings.append(Finding("MANIFEST-DEBUGGABLE", "HIGH", "application",
            "android:debuggable=true in manifest. Debuggable release builds widen attack surface.",
            "Remove android:debuggable or set false for release; rely on buildType debug flags, never ship debuggable=true. See MASTG code/platform guidance."))

    # 2. allowBackup
    allow_backup = _attr(app, "allowBackup")
    # Default is true historically; flag when true or unspecified for sensitive apps as INFO requiring review
    if allow_backup == "true":
        findings.append(Finding("MANIFEST-ALLOWBACKUP", "MEDIUM", "application",
            "android:allowBackup=true allows backup/restore of app data including via adb.",
            "Set android:allowBackup=false for sensitive apps, or curate with android:dataExtractionRules / fullBackupContent to exclude tokens, keys, PII. See https://developer.android.com/privacy-and-security/risks (backups)."))
    elif allow_backup is None:
        findings.append(Finding("MANIFEST-ALLOWBACKUP-DEFAULT", "INFO", "application",
            "android:allowBackup unspecified (historic default true). Explicit is better.",
            "Explicitly set android:allowBackup and dataExtractionRules; do not rely on defaults."))

    # 3. cleartext
    cleartext = _attr(app, "usesCleartextTraffic")
    if cleartext == "true":
        findings.append(Finding("MANIFEST-CLEARTEXT", "HIGH", "application",
            "android:usesCleartextTraffic=true permits cleartext HTTP.",
            "Set false and enforce HTTPS via Network Security Config + HSTS; see MASVS-NETWORK."))

    # 4. components
    for tag in ("activity", "activity-alias", "service", "receiver", "provider"):
        for el in app.findall(tag):
            name = _attr(el, "name") or el.get("name") or f"<unnamed {tag}>"
            exported = _attr(el, "exported")
            has_filter = el.find("intent-filter") is not None
            perm = _attr(el, "permission")
            read_perm = _attr(el, "readPermission")
            write_perm = _attr(el, "writePermission")

            # Explicitness (API 31+ rule)
            if has_filter and exported is None:
                findings.append(Finding("MANIFEST-EXPORTED-EXPLICIT", "HIGH", name,
                    f"<{tag}> with <intent-filter> lacks explicit android:exported. Pre-31 defaults varied; 31+ requires explicit.",
                    "Always set android:exported explicitly; default to false. See https://developer.android.com/privacy-and-security/risks/android-exported"))
            # Exported without guard
            if exported == "true":
                guarded = bool(perm or read_perm or write_perm)
                # Launcher entry (MAIN + LAUNCHER) is expected exported; report as INFO, not a flaw
                is_launcher = False
                if tag in ("activity", "activity-alias"):
                    for f in el.findall("intent-filter"):
                        acts = {(_attr(a, "name") or "") for a in f.findall("action")}
                        cats = {(_attr(c, "name") or "") for c in f.findall("category")}
                        if "android.intent.action.MAIN" in acts and "android.intent.category.LAUNCHER" in cats:
                            is_launcher = True
                if not guarded:
                    if is_launcher:
                        findings.append(Finding("MANIFEST-LAUNCHER-EXPORTED", "INFO", name,
                            "Launcher activity exported without permission guard (expected for MAIN/LAUNCHER).",
                            "No action if this is the genuine launcher entry; ensure no sensitive extras are trusted from the launching intent."))
                    else:
                        findings.append(Finding("MANIFEST-EXPORTED-UNGUARDED", "MEDIUM", name,
                            f"Exported <{tag}> declares no android:permission / readPermission / writePermission.",
                            "If external access is not required set exported=false. If required, protect with signature-level permission and validate all inputs; see MASTG-BEST-0052 and permission-based access control guidance."))
                else:
                    findings.append(Finding("MANIFEST-EXPORTED-GUARDED", "INFO", name,
                        f"Exported <{tag}> declares permission guard ({perm or (read_perm or '') + '/' + (write_perm or '')}). Verify protectionLevel and necessity.",
                        "Confirm permission protectionLevel (prefer signature for same-developer), least privilege, and input validation."))
            # Providers: grantUriPermissions
            if tag == "provider":
                grant = _attr(el, "grantUriPermissions")
                if exported == "true" and grant == "true":
                    findings.append(Finding("MANIFEST-PROVIDER-GRANT", "MEDIUM", name,
                        "Exported provider sets grantUriPermissions=true; review temporary URI grants.",
                        "Set grantUriPermissions=false unless strictly required; scope grants minimally."))

    if not findings:
        findings.append(Finding("MANIFEST-OK", "INFO", "manifest",
            "No high-signal posture issues detected by static manifest rules. Manual review still required.",
            "Complete MASVS L1/L2 checklist via MASTG tests; automated rules are necessary but not sufficient."))
    return [asdict(f) for f in findings]

if __name__ == "__main__":
    import json, sys
    print(json.dumps(audit_manifest(sys.argv[1]), indent=2))
