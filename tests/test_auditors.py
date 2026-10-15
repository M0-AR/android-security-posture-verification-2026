"""Pytest: auditors must flag weak fixture and pass hardened fixture (defensive only)."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from manifest_audit import audit_manifest
from storage_audit import scan_paths
from network_audit import audit_network

FIX = Path(__file__).resolve().parents[1] / "fixtures"

def test_weak_manifest_flagged():
    f = audit_manifest(FIX / "benign_manifests" / "synthetic_weak.xml")
    ids = {x["check_id"] for x in f}
    assert "MANIFEST-DEBUGGABLE" in ids
    assert "MANIFEST-ALLOWBACKUP" in ids
    assert "MANIFEST-CLEARTEXT" in ids
    assert "MANIFEST-EXPORTED-EXPLICIT" in ids  # receiver/activity with filter but no exported
    assert "MANIFEST-EXPORTED-UNGUARDED" in ids

def test_hardened_manifest_quieter():
    f = audit_manifest(FIX / "benign_manifests" / "synthetic_hardened.xml")
    ids = {x["check_id"] for x in f}
    assert "MANIFEST-DEBUGGABLE" not in ids
    assert "MANIFEST-CLEARTEXT" not in ids
    # guarded service should be INFO, not unguarded
    assert "MANIFEST-EXPORTED-UNGUARDED" not in ids

def test_storage_scanner_flags_synthetic():
    hits = scan_paths([FIX / "SyntheticStorage.java"])
    ids = {h["check_id"] for h in hits}
    assert "STORAGE-002" in ids  # getSharedPreferences
    assert "STORAGE-006" in ids  # http://

def test_network_audit_missing_config_is_info():
    out = audit_network(FIX)
    assert any(x["check_id"] == "NET-001" for x in out)
