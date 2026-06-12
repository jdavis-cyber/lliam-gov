# Lliam-GOV Dependency Residual Clearance — 2026-06-12 (AI-321)

Closes out the two residuals deferred from AI-320 (dependency-bump-2026-06-12.md,
"Residual" section). Outcome: starlette CLEARED, pynacl still residual with an
updated (different) blocker.

## starlette — PYSEC-2026-161 — CLEARED

| Package | From | To | Notes |
|---|---|---|---|
| fastapi | 0.133.1 | 0.136.3 | direct pin (`web` extra); 0.136.x dropped the starlette upper cap (`starlette>=0.46.0`, no `<1.0`), so the coordinated bump did NOT require waiting for a 0.140 line as AI-321 anticipated |
| starlette | 0.52.1 | 1.3.1 | PYSEC-2026-161 fixed in 1.0.1; 1.3.1 is latest |

Acceptance evidence:

- `tests/hermes_cli/` web surface — test_web_server.py,
  test_web_server_host_header.py, test_web_server_oauth_write.py,
  test_web_oauth_dispatch.py, test_web_server_cron_profiles.py,
  test_dashboard_lifecycle_flags.py: **182 passed, 0 failed** on
  starlette 1.3.1. (One StarletteDeprecationWarning: httpx-based
  TestClient deprecated in favor of httpx2 — future maintenance note,
  not a failure.)
- Full parallel suite: see Validation below.
- pip-audit post-bump: PYSEC-2026-161 no longer reported (see below).

## pynacl — CVE-2025-69277 — STILL RESIDUAL (blocker changed)

pynacl 1.6.2 **is now published on PyPI** (the AI-320-era blocker is gone),
but `discord.py` — including the latest release, 2.7.1 — caps
`PyNaCl<1.6,>=1.5.0` on its `voice` extra. `uv lock --upgrade-package pynacl`
(the AI-321 acceptance command) was run and correctly refuses the upgrade
under that constraint.

Forcing past a declared upstream cap via `[tool.uv] override-dependencies`
was considered and rejected: it would ship a dependency combination upstream
explicitly excludes, untested by either project — the same "forced blind"
risk AI-320 declined. Mitigation unchanged and verified: pynacl is reached
ONLY via `discord.py[voice]`, which is not installed in the governed
production profile.

**New unblock condition:** discord.py release that allows PyNaCl >=1.6
(watch https://pypi.org/project/discord.py/ requires_dist), then re-run
`uv lock --upgrade-package pynacl` and confirm CVE-2025-69277 cleared.

## Validation

- `uv lock` resolved 224 packages clean; `uv sync --extra all` succeeded.
- Full parallel suite (`scripts/run_tests_parallel.py`): 36 failures across
  11 files — file list and per-file counts match the documented Phase 2
  noise floor (evidence/phase2/noise-floor-2026-05-26.md) line for line.
  Zero NEW failures from the FastAPI/starlette bump.
- pip-audit post-bump (verbatim, full findings table):
```
Found 1 known vulnerability in 1 package
Name   Version ID             Fix Versions
------ ------- -------------- ------------
pynacl 1.5.0   CVE-2025-69277 1.6.2
```
  starlette no longer appears; PYSEC-2026-161 cleared.

SBOM regenerated as cyclonedx-2026-06-12-ai321.json (CycloneDX 1.6,
224 components; fastapi 0.136.3 / starlette 1.3.1 / pynacl 1.5.0 captured).
