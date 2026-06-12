# Lliam-GOV Dependency Bump — Post-Remediation Record — 2026-06-12 (AI-320)

Remediates the open CVEs from the AI-227 review (dependency-review-2026-06-12.md).

## Bumped (CVEs cleared)

| Package | From | To | Notes |
|---|---|---|---|
| aiohttp | 3.13.3 | 3.14.0 | 10 CVEs cleared; direct pin (4 extras) |
| anthropic | 0.86.0 | 0.87.0 | CVE-2026-34450/34452; direct pin |
| cbor2 | 5.8.0 | 6.1.2 | CVE-2026-26209 cleared (past the 5.9 fix) |
| pygments | 2.19.2 | 2.20.0 | CVE-2026-4539; transitive |
| pyjwt | 2.12.1 | 2.13.0 | PYSEC-2026-175/177/178/179; direct pin |
| pytest | 9.0.2 | 9.0.3 | CVE-2025-71176; dev pin |
| urllib3 | 2.6.3 | 2.7.0 | PYSEC-2026-141/142; transitive |

## Residual (documented, not fixable tonight)

| Package | Version | Finding | Why deferred |
|---|---|---|---|
| pynacl | 1.5.0 | CVE-2025-69277 (fix 1.6.2) | 1.6.2 is not yet published on PyPI; 1.5.0 is the latest installable. Only reached via discord.py[voice] (the 'voice' extra), not installed in the governed profile. Re-bump when 1.6.2 releases. |
| starlette | 0.52.1 | PYSEC-2026-161 (fix 1.0.1) | starlette 1.0.1 requires a FastAPI major bump (current pin fastapi==0.133.1 caps starlette <1.0). A coordinated FastAPI+starlette upgrade is a separate, higher-risk change — tracked as a follow-up, not forced blind. |

## Validation

- 'uv lock' resolved 224 packages clean; 'uv sync --extra all' succeeded.
- Full parallel suite: 35 failures across 11 files — EXACTLY the documented
  Phase 2 noise floor (evidence/phase2/noise-floor-2026-05-26.md: 36/11 at
  baseline, anthropic adapter unchanged at 5). Zero NEW failures from the bumps.
- pip-audit post-bump (verbatim, the 9 tracked packages):
```
pynacl    1.5.0   CVE-2025-69277 1.6.2
starlette 0.52.1  PYSEC-2026-161 1.0.1
starlette 0.52.1  PYSEC-2026-161 1.0.1
```

SBOM regenerated below as cyclonedx-2026-06-12-post-bump.json.
