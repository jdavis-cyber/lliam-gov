# Lliam-GOV Dependency Review Record — 2026-06-12 (AI-227, WBS LG-5.3)

**SBOM:** evidence/sbom/cyclonedx-2026-06-12.json (CycloneDX 1.6, 223 components,
generated from uv.lock via 'uv export --frozen --all-extras' + cyclonedx-py).
**Scanner:** pip-audit (PyPA Advisory DB + OSV), full-extras resolution.
**CI posture:** OSV scanner runs on every PR (fail-on-vuln=false, findings reported
in workflow logs; SARIF upload disabled — code scanning unavailable on private repo).

## Findings (verbatim scanner output)
```
Name      Version ID             Fix Versions
--------- ------- -------------- ------------
aiohttp   3.13.3  CVE-2026-34515 3.13.4
aiohttp   3.13.3  CVE-2026-34513 3.13.4
aiohttp   3.13.3  CVE-2026-34516 3.13.4
aiohttp   3.13.3  CVE-2026-34517 3.13.4
aiohttp   3.13.3  CVE-2026-34519 3.13.4
aiohttp   3.13.3  CVE-2026-34518 3.13.4
aiohttp   3.13.3  CVE-2026-34520 3.13.4
aiohttp   3.13.3  CVE-2026-34525 3.13.4
aiohttp   3.13.3  CVE-2026-22815 3.13.4
aiohttp   3.13.3  CVE-2026-34514 3.13.4
aiohttp   3.13.3  CVE-2026-34993 3.14.0
aiohttp   3.13.3  CVE-2026-47265 3.14.0
anthropic 0.86.0  CVE-2026-34450 0.87.0
anthropic 0.86.0  CVE-2026-34452 0.87.0
cbor2     5.8.0   CVE-2026-26209 5.9.0
pygments  2.19.2  CVE-2026-4539  2.20.0
pyjwt     2.12.1  PYSEC-2026-179 2.13.0
pyjwt     2.12.1  PYSEC-2026-175 2.13.0
pyjwt     2.12.1  PYSEC-2026-177 2.13.0
pyjwt     2.12.1  PYSEC-2026-178 2.13.0
pynacl    1.5.0   CVE-2025-69277 1.6.2
pytest    9.0.2   CVE-2025-71176 9.0.3
starlette 0.52.1  PYSEC-2026-161 1.0.1
starlette 0.52.1  PYSEC-2026-161 1.0.1
urllib3   2.6.3   PYSEC-2026-142 2.7.0
urllib3   2.6.3   PYSEC-2026-142 2.7.0
urllib3   2.6.3   PYSEC-2026-141 2.7.0
```

## Disposition

All findings are resolvable with patch/minor version bumps:
aiohttp→3.14.0, anthropic→0.87.0, cbor2→5.9.0, pygments→2.20.0, pyjwt→2.13.0,
pynacl→1.6.2, pytest→9.0.3, starlette→1.0.1, urllib3→2.7.0.

**Decision (2026-06-12):** remediate in a dedicated dependency-bump PR validated
against the full CI suite (not bundled into the Phase 5 evidence PR). Tracked in
Linear as a Phase 5 exit-gate item; none of the affected CVEs touch the
Lliam-GOV security modules' direct code paths (key_manager/audit_logger use
cryptography+keyring, not the affected packages), but aiohttp/urllib3/starlette
sit in gateway and provider paths, so the bump is required before Phase 6.

## Release / signature posture (for later tags)

- Releases are git tags on jdavis-cyber/lliam-gov (private). No PyPI publication.
- Future signed tags: 'git tag -s' with the operator key; SBOM regenerated per
  release into evidence/sbom/cyclonedx-<date>.json; pip-audit re-run and this
  record re-issued per release.
- Dependency pinning policy per AGENTS.md: exact pins in pyproject/uv.lock;
  Dependabot PRs gated by full CI.
