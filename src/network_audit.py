"""
Defensive network-posture checker (static only).

Checks:
- res/xml/network_security_config.xml presence and cleartext policy
- Manifest cleartext flag (delegates to manifest_audit finding ids)
- Guidance for pinning/HSTS/CA validation WITHOUT intercepting traffic,
  installing CA certs, or bypassing pinning (explicitly out of scope).

Ethics: interception/pinning-bypass only on your own apps with written
authorization in an isolated lab. This tool does not perform it.
See ETHICS.md and https://mas.owasp.org/MASTG (MASVS-NETWORK).
"""
from __future__ import annotations
import xml.etree.ElementTree as ET
from pathlib import Path
from dataclasses import dataclass, asdict

@dataclass
class Finding:
    check_id: str
    severity: str
    target: str
    message: str
    remediation: str

def audit_network(app_dir: str | Path) -> list[dict]:
    base = Path(app_dir)
    out: list[Finding] = []
    # Find network security config candidates
    candidates = list(base.rglob("network_security_config.xml"))
    if not candidates:
        out.append(Finding("NET-001", "INFO", str(base),
            "No network_security_config.xml found in tree. Cannot confirm cleartext/pinning posture statically.",
            "Add res/xml/network_security_config.xml; set cleartextTrafficPermitted=false; prefer system CAs, certificate pinning for high-assurance endpoints, HSTS on server."))
        return [asdict(f) for f in out]
    for cfg in candidates:
        try:
            tree = ET.parse(cfg)
            xml_text = cfg.read_text(encoding="utf-8", errors="ignore")
        except Exception as e:
            out.append(Finding("NET-PARSE", "LOW", str(cfg), f"Cannot parse config: {e}", "Validate XML."))
            continue
        # crude but transparent checks
        if "cleartextTrafficPermitted=\"true\"" in xml_text:
            out.append(Finding("NET-CLEARTEXT", "HIGH", str(cfg),
                "Config permits cleartext traffic.",
                "Set cleartextTrafficPermitted=false; serve exclusively over TLS with HSTS."))
        if "<pin-set" in xml_text or "sha256/" in xml_text:
            out.append(Finding("NET-PINNING-PRESENT", "INFO", str(cfg),
                "Pin-set material present. Pinning is a defense-in-depth control, not a substitute for CA validation.",
                "Pin with backup pins, rotation plan, and reporting; test failure modes. Do not document bypasses."))
        else:
            out.append(Finding("NET-PINNING-ABSENT", "INFO", str(cfg),
                "No pin-set found. Pinning is optional and risk-based.",
                "Consider pinning only for high-value endpoints after assessing rotation/DoS risk per MASVS-NETWORK."))
        if "trust-anchors" in xml_text and "user" in xml_text:
            out.append(Finding("NET-USER-CA", "MEDIUM", str(cfg),
                "Config trusts user-added CAs in some section.",
                "Restrict debug-overrides to debug builds; production should not trust user CAs broadly."))
    return [asdict(f) for f in out]

if __name__ == "__main__":
    import json, sys
    print(json.dumps(audit_network(sys.argv[1]), indent=2))
