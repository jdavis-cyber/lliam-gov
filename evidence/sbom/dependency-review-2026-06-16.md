# Dependency review — clean Hermes v2026.6.5 rebuild (2026-06-16)

**Scope:** supply-chain hygiene controls SP 800-171 3.14.2 / 3.14.3, ISO/IEC 27001
A.8.8 (technical vulnerability management), A.5.20/A.5.21 (supplier / ICT supply
chain), A.5.7 (threat intelligence). **Process artifact** — these controls require a
documented, repeatable vulnerability-management process with an SBOM, not a zero-CVE
snapshot.

## Inputs
- SBOM: `evidence/sbom/cyclonedx-2026-06-16.json` (CycloneDX 1.6, regenerated from the
  rebuilt `.venv` with `cyclonedx-py environment`).
- Scan: `evidence/sbom/pip-audit-2026-06-16.json` (`pip-audit` against the locked
  requirements exported from `uv.lock`).

## Findings (17 advisories across 5 packages — all inherited from the upstream
## v2026.6.5 pin, all with published fix versions)

| Package | Pinned | Advisories | Fix |
|---|---|---|---|
| cryptography | 46.0.7 | GHSA-537c-gmf6-5ccf | 48.0.1 |
| pygments | 2.19.2 | CVE-2026-4539 | 2.20.0 |
| pyjwt | 2.12.1 | PYSEC-2026-175..179 | 2.13.0 |
| urllib3 | 2.6.3 | PYSEC-2026-141/142 | 2.7.0 |
| starlette | 1.0.1 | CVE-2026-48817/48818/54282/54283 | 1.3.1 |

## Disposition

These advisories originate in transitive dependencies pinned by upstream Hermes
v2026.6.5 (the deliberate, recorded base of this rebuild), not in the Lliam-GOV
governance overlay. Remediation path: bump each package to its fix version in a
dedicated dependency-bump change, then re-run the overlay + upstream regression
suites and re-capture this review — mirroring the prior `dependency-bump-2026-06-12.md`
workflow. The `starlette` jump (1.0.1 → 1.3.1) crosses minor versions that touch the
dashboard/web server and MUST be validated against a live dashboard before landing;
it is therefore tracked, not applied blind in this rebuild.

**Status:** identified + tracked with a remediation path; no fix applied in this
change set (would require live-dashboard validation outside the current scope).
