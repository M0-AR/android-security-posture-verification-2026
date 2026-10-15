# Ethics & Scope — non-negotiable

This is **defensive security research only**.

## Allowed
- Auditing **your own apps** or apps you have **written authorization** to test, in an isolated lab.
- Static posture checks (manifest, storage patterns, network config) that **flag** risk and link to fixes.
- Verifying claims against **public, fetchable sources** (OWASP MAS, Android docs, AOSP bulletins) with `src/live_verify.py`.
- Publishing **remediation guidance**, methodology, and aggregate benchmark counts.

## Prohibited in this repo (will not be added, will be rejected in review)
- Malware construction: reverse shells, SMS stealers, exfiltration servers, infecting legitimate apps, obfuscation to evade detection.
- Bypassing authentication: pattern/PIN/password lock bypass, `gesture.key` / `password.key` extraction or cracking, lockscreen intent tricks (including historic CVE-2013-6271 reuse).
- Interception / pinning bypass against third-party apps: installing CA certs to inspect others' traffic, `TrustKiller`-style bypasses, MitM payload injection, Metasploit browser exploitation.
- Privilege escalation / rooting how-tos for daily-driver devices; bootloader unlock / custom ROM flashing instructions.
- Targeting third-party app data: `adb pull /data/data/<other-app>`, backup unpacking of apps you do not own, provider traversal or SQL-injection string crafting to extract data.

Why: the source text describes 2015-era offensive flows that are (a) largely obsolete on API 34–37, (b) illegal without authorization in most jurisdictions, and (c) incompatible with a publishable, reproducible PhD artifact. The scientific contribution here is **measuring how much of that playbook no longer replicates**, and what replaces it under MASVS v2 / MASTG v2.

## Lab rules
1. Use a dedicated test device/AVD. Never root a personal device holding private data.
2. Test only your synthetic fixtures under `fixtures/` or your own builds.
3. Get written authorization before any dynamic test touching network or other principals.
4. Record authorization, scope, and cleanup in every experiment log.
5. If you discover a live vulnerability in someone else's app, follow coordinated disclosure; do not publish exploit steps.

## Review gate
Any PR adding exploit strings, payload code, bypass commands, or third-party data extraction will fail the ethics gate (`tests/test_ethics_gate.py`, to be added) and must be reverted.
