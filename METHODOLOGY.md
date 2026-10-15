# Methodology — zero-to-hero verification (defensive, reproducible)

## 0. Principle: no hand-written claim without execution
Every factual claim in README/PAPER must come from one of:
1. `src/live_verify.py` evidence (`data/live/verification_snapshot.json`), or
2. `pytest` output over synthetic fixtures, or
3. A directly cited fetchable source with URL + access date.
If offline, the claim is marked `UNVERIFIED AT FETCH TIME (degraded=True)`.

## 1. Research votes (multi-source, sequential to avoid 429)
One search at a time, distinct keywords per tool (as requested):
- `websearch` (Exa): MASVS 2026 verification best practice → MASVS v2 profiles, MASTG v2 atomic tests, MASWE chain.
- `duckduckgo_search`: Pixel bulletin Oct-2026 + CVE-2026-58704 modem zero-day → patch-level as verification control.
- `openresearch.web_search`: EncryptedSharedPreferences deprecated → DataStore+Keystore direction.
- `paper-search.search_papers`: McNdroid longitudinal drift + 2014–2026 critical review (TESSERACT bias) → benchmark inflation lesson.
- `agent-reach_search (web)`: exported-component CVEs 2026 (CWE-926) + Android 17 IPC study (80.8% gaps in corpus) → vuln class still real.
- `duckduckgo_search` (2nd, different kw): allowBackup/scoped storage → backup curation rule.
- `openresearch hacker_news`, `gsd_websearch`, `arxiv` run as negative/orthogonal votes (no result = signal to not overclaim).

Synthesis rule: a claim needs ≥2 independent votes or 1 authoritative primary (AOSP/OWASP/Android docs) + live fetch.

## 2. Verification harness
```
python src/live_verify.py --out data/live     # live public evidence
python -m pytest -q                           # defensive detectors on synthetic fixtures
python src/manifest_audit.py fixtures/benign_manifests/synthetic_weak.xml
python src/storage_audit.py fixtures
docker compose config                         # compose validity
docker compose up --build verifier            # full reproducible run (needs network for live step)
```

## 3. Benchmark design (what makes this PhD-grade)
- **Mapping benchmark**: `benchmarks/mapping_2015book_to_masvs2026.csv` maps each legacy chapter to MASVS v2 control + verdict (OBSOLETE / SUPERSEDED / STILL-REAL-BUT-RESTRICTED / EXCLUDED).
- **Detector benchmark**: weak vs hardened synthetic manifests + storage fixture; report precision/recall of static rules (expected: high recall on known patterns, explicit non-goal: no dynamic exploit).
- **Temporal benchmark**: McNdroid-style train-test time-gap lesson — do not report single-split accuracy; if ML is added later, require temporal splits + TESSERACT-style bias audit.
- **Live-data anchor**: Pixel bulletin patch-level + CWE-926 2026 CVEs prove the threat class persists while the 2015 tooling does not.

## 4. Hidden patterns we surface (for later PhD extension)
1. **Framework-primitive gap**: ContentProvider/Service hold-rates exceed Activity/Receiver in the Android-17 IPC study because the former expose caller identity/strict validators; the latter lack framework caller verification. Implication: secure defaults beat developer discipline.
2. **Taxonomy drift**: 2014 Mobile Top-10 → MASVS v2 + MASWE + atomic MASTG tests. Papers reporting 94%→98% accuracy without temporal splits inflate (TESSERACT). Reproducibility requires time-aware evaluation.
3. **Deprecation churn as signal**: EncryptedSharedPreferences → DataStore migration shows crypto-wrapper half-life <5y; Keystore-backed, platform-owned storage outlives wrappers. Measure wrapper churn as a risk metric.
4. **Backup as forgotten exfiltration**: allowBackup defaults + curated rules remain the cheapest high-yield check; most 2015 backup flows still conceptually apply but via DataExtractionRules, not abe.jar.
5. **Toolchain extinction**: Drozer/Cydia/QARK-Windows/dex2jar-JD-GUI replaced by MASTG demos + jadx/apktool + managed test devices. Re-running 2015 commands verbatim is a non-replication by design.

## 5. Threats to validity
- Live fetches are point-in-time; bulletins rotate monthly. Snapshot date is recorded.
- Synthetic fixtures prove detector logic, not real-world prevalence.
- No dynamic execution on real devices in this repo (intentional ethics boundary); dynamic claims cite MASTG/McNdroid, not local runs.
- Search-engine excerpts are untrusted; only primary docs count as evidence.

## 6. From-zero-to-hero checklist for a new contributor
1. Read ETHICS.md. 2. Run live_verify. 3. Run pytest. 4. Read mapping CSV. 5. Pick one MASVS control, write a MASTG-atomic-style test (Overview/Steps/Observation/Evaluation), add fixture + test. 6. Re-run harness. 7. Document evidence links.
