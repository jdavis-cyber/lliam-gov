# Phase R Verification Report — hermes → lliam rename

> **Purpose:** R.V verify-gate evidence that the Lliam-GOV build is **renamed AND unbroken** (Katmai Adoption Build Plan, Task R.V). Review-by: 2026-10-01 (or at the P6 cutover, whichever is first).
> **Verified at:** `main` @ `524df8af` (merge of [PR #92](https://github.com/jdavis-cyber/lliam-gov/pull/92), merged by the operator 2026-07-08). Report authored 2026-07-11 during the Phase R close-out session.

## Verdict

**PASS.** All R.V gate items verified green or documented as accepted residuals. `gov-R-good` may be tagged at `main` (524df8af or the commit carrying this report). PATH-FREEZE is re-imposed from that tag forward — P1–P6 are additive only.

## Gate evidence

### 1. Completeness guard — GREEN

`tests/rename/test_no_hermes_identifiers.py` (case-sensitive, token-level keep-pattern allowlist) passes at `main`. By construction this means every surviving `hermes` token in the repo is a documented, justified keep. Justifications: `docs/governance/verification/R8e-keep-register.md` (+ `R8d-upstream-keep-register.md`). Verified 2026-07-11: **13/13 rename tests pass** (guard + 12 data-migration/env-fallback tests), Python 3.12.13, fresh `uv` venv.

### 2. Full pytest suite — at the characterized noise floor

- Invocation (per the floor file's 2026-07-08 warning): `HERMES_HOME=<throwaway>` **only** — `LLIAM_HOME` unset (a shared `LLIAM_HOME` overrides per-test isolation and poisons ~1000+ tests; also the runaway-gateway vector from the 2026-07-07 incident).
- Run 2026-07-11 in the dedicated dev clone (`~/dev/lliam-gov`, provisioned venv) at `main` @ `524df8af`.
- Result: **60 failed across 21 files — name-level match to the floor.** All 59 active floor entries reproduce; the single non-floor failure is `tests/tools/test_base_environment.py::TestAtomicSnapshotConcurrencyBehavioral::test_concurrent_writes_never_tear_the_snapshot`, one of the two documented run-varying flakes (re-run 4× in isolation: 1 pass / 3 fail — confirms flaky, not a rename regression; the underlying PATH-snapshot race predates Phase R and remains an open product defect, not a gate item).
- Floor reference: `~/dev/lliam-gov-baseline/branch-noise-floor.txt` (60 characterized entries: live-OAuth-credential family, macOS `/private/tmp` path-assertion family, documented flakes; the intentional guard entry is retired — guard is green).
- Collection errors: **0**.
- Independent corroboration: PR #92 merge CI ran the full suite in 8 slices — **all green** (run 28969909060).

### 3. Fresh-clone governed install — PASS

```
git clone <repo> lliam-freshclone && uv venv && uv pip install -e .
lliam-gov --help    → usage renders as lliam-gov, no hermes in usage line
lliam-gov version   → "Lliam-GOV v0.17.0 (2026.6.19)"
```
Console scripts installed: `lliam-gov`, `lliam` (short alias), `lliam-gov-agent`, `lliam-gov-acp`. Verified 2026-07-11.

### 4. Data migration — PASS

`tests/rename/test_home_migration.py`: 12/12 green — one-time copy migration (`~/.hermes` → `~/.lliam`), idempotency, no-op guards, interrupted-copy recovery, staging-dir crash recovery, and `getenv_compat` LLIAM_→HERMES_ fallback precedence. Env fallback is keep-for-one-release (keep-register, §env-fallback).

### 5. Electron desktop — build green; IPC round-trip accepted residual

- Merge CI (run 28969909060): **Build desktop app PASS**; TypeScript checks PASS for `apps/desktop`, `apps/bootstrap-installer`, `apps/shared`, `ui-tui`, `web`.
- Local `npm run test:ui` (node 22, clean `npm ci`, 2026-07-11): **19 failed / 946 passed — at the documented floor** (19–20 failed / 945–946 passed).
- `npm run pack` (2026-07-11): **PASS** — produced `release/mac-arm64/Lliam-GOV.app` with `CFBundleIdentifier = com.secondorderstrategy.lliam-gov` (locked D5 appId), `CFBundleName`/`CFBundleExecutable`/`CFBundleDisplayName` = `Lliam-GOV`. Unsigned/ad-hoc as designed — cert provisioning and notarization are AI-326 (deploy workstream).
- **GUI IPC round-trip: accepted residual → AI-326 (deploy workstream).** Channel symmetry (`lliam:*` on both main and renderer sides) was proven statically at R.5; the `lliam-media://` protocol was confirmed live in Electron process args at R.5. A live dev-launch round-trip could not be exercised headlessly during Phase R and transfers to AI-326's fresh-machine QA smoke matrix.

### 6. Attribution unchanged (D4) — PASS

`git diff pre-rename-baseline..main -- NOTICE ATTRIBUTION.md LICENSE docs/upstream` → **empty** (verified 2026-07-11). Upstream "Built on Hermes Agent by Nous Research (MIT)" credit intact; MIT attribution obligation preserved.

### 7. R.9 wiring — verified with one residual fixed post-merge

- `docs/governance/control-matrix.md`: zero `hermes_cli` owner paths remain; owners reference `lliam_cli/*`.
- CI workflows: internally consistent at merge (all checks green). Remaining `hermes` strings in `.github/workflows/` are upstream-gated (`if: github.repository == 'NousResearch/hermes-agent'` — never run on the fork) or comments, consistent with the keep-register.
- **Fixed in this close-out (post-merge, pre-tag):** `upload_to_pypi.yml` publish-environment display URL `pypi.org/p/hermes-agent` → `pypi.org/p/lliam-gov-agent` (missed R.9 item; dist artifacts themselves already build from `lliam_cli`).
- `nix/nixosModules.nix`: surviving `hermes` refs are OS-user / `/opt/hermes` install-identity + upstream refs, kept per the keep-register ("Container / OS install identity"). `nix flake check` could not run (nix not installed on the verification host) — cross-file consistency verified by ripgrep only.

## Governance observations (carried forward)

1. **Test-isolation least-privilege finding (P2 candidate):** during this close-out, a suite invocation without home isolation wrote a live `gateway_state.json` (feishu platform "connected", auto-restart supervisor state) into the operator's real `~/.lliam` within ~2 minutes — the same mechanism as the 2026-07-07 runaway-gateway incident. Polluted state quarantined to `~/.lliam/.gateway-state-backup-20260711-session/`. Reinforces the keep-register §F finding: tests that spawn networked gateways must be sandboxed/denied by P2 egress + least-privilege controls.
2. **Open product decisions (Jerome, non-blockers):** (a) website install/download still points at upstream `hermes-agent.nousresearch.com`; (b) `website/docusaurus.config.ts` `organizationName`/`editUrl` still reference NousResearch. Decide when the fork publishes its own docs/download site.

## Chain of custody

| Item | Value |
|---|---|
| Pre-rename restore point | tag `pre-rename-baseline` (pushed) |
| Rename branch | `rename/hermes-to-lliam`, merged as PR #92 → `main` @ `524df8af` |
| Merge CI | run 28969909060 — all required checks pass |
| Keep registers | `R8d-upstream-keep-register.md`, `R8e-keep-register.md` |
| This report | `docs/governance/verification/R-rename-report.md` |
| Phase tag | `gov-R-good` (pushed after operator go) |

**PATH-FREEZE re-imposed at `gov-R-good`.** Next: Phase 1 (AI-516 → AI-517 → AI-518; AI-519/AI-520/AI-479 parallel after AI-516; gate AI-480).
