# Lliam-GOV Codex Continuation Handoff — 2026-05-28

Use this as the initial prompt for a fresh Codex session started in:

`/Volumes/WORKSPACE/1-Projects/lliam-gov`

Repository: `jdavis-cyber/lliam-gov` (private)

Current local state at handoff:

- Branch: `main`
- HEAD: `b0171c9` — `Merge pull request #10 from jdavis-cyber/phase3/encryption-and-audit`
- Worktree status: clean
- PR #9 merged: Phase 2 noise-floor recalibration
- PR #10 merged: Phase 3 `key_manager.py` + FIPS-probe `runtime_guard.py` stub
- PR #10 CI fix landed before merge: `.github/workflows/osv-scanner.yml` now sets `upload-sarif: false` because code scanning is not enabled for this private repo; OSV still scans and reports findings in workflow logs with `fail-on-vuln: false`

You are continuing the Lliam-GOV build, an in-flight governance-grade fork of Hermes Agent for Katmai ISO 42001 / CMMC L2 / ISO 27001 evidence.

## Read First

Before editing, read these:

1. `/Volumes/WORKSPACE/0-Orientation/Hermes-to-Lliam-ISO42001-Plan-COMPREHENSIVE-v3-2026-05-25.docx`
2. `/Volumes/WORKSPACE/0-Orientation/Lliam-GOV-Phase3-Handoff-2026-05-25.md`
3. `/Volumes/WORKSPACE/1-Projects/lliam-gov/docs/governance/control-matrix.md`
4. `/Volumes/WORKSPACE/1-Projects/lliam-gov/evidence/control-matrix.csv`
5. Reference only, do not edit: `/Volumes/WORKSPACE/1-Projects/lliam_ai_agent/src/security/key-manager.ts` and `audit-logger.ts`

The active plan is Rev. 3 from 2026-05-25. A newer 2026-05-28 end-to-end plan exists, but the repo has already adopted the Rev. 3 “facelift + governance overlay” approach, not a full internal Hermes rename. Do not restart the plan or perform a bulk rename.

## What Is Done

Phases 0-2 are on `main`.

Phase 3 first slice is merged:

- `lliam_gov/security/key_manager.py`
- `lliam_gov/security/runtime_guard.py`
- `tests/lliam_gov/test_key_manager.py`
- `tests/lliam_gov/test_runtime_guard.py`
- dependency pins for `cryptography==46.0.7` and `keyring==25.7.0`

Local focused verification before merge:

```bash
UV_PROJECT_ENVIRONMENT=/Users/just_jerome/.venvs/lliam-gov \
  uv run pytest -q tests/lliam_gov/test_key_manager.py tests/lliam_gov/test_runtime_guard.py
```

Result: `22 passed`.

PR #10 checks were green before merge, including OSV after the SARIF-upload fix. Post-merge `main` checks may still be finishing depending on when you start; inspect with:

```bash
gh run list --repo jdavis-cyber/lliam-gov --branch main --limit 6
```

## Next Work

Continue Phase 3. The next highest-value task is `audit_logger.py`.

Phase 3 remaining scope per the handoff:

- Implement `lliam_gov/security/audit_logger.py`
- Add hash-chain build and verification
- Add deterministic `params_hash` using canonical key-sorted JSON
- Add monthly JSONL rotation
- Add fail-closed behavior when the audit file cannot open
- Add AEP export support, or a clean first slice toward it
- Add tests:
  - hash-chain build
  - chain-break / tamper detection
  - fail-closed when file cannot open
  - monthly rotation
  - AEP export round-trip
  - params_hash determinism
- Then wire audit events into:
  - `agent/conversation_loop.py`
  - tool dispatch path
  - `agent/agent_init.py` for `session_open` / `session_close`
  - `gateway/platforms/{slack,email,telegram}.py` for inbound auth events
- Later Phase 3 slices:
  - `EncryptedFile` abstraction
  - persisted-state encryption under `~/.lliam-gov`
  - `lliam-gov rotate-key`
  - `lliam-gov audit export-aep`
  - 24-hour smoke run and `evidence/phase3/`
  - update `evidence/control-matrix.csv` current_state rows only after implementation and evidence exist

## Operating Rules

- Do not edit `/Volumes/WORKSPACE/1-Projects/lliam_ai_agent`; it is dormant Lliam-OPS reference only.
- Do not push without explicit instruction from Jerome.
- Do not merge without explicit instruction from Jerome.
- Use small PR-sized slices.
- Keep internal Hermes package names unless the active Rev. 3 plan says otherwise.
- CUI handling is governance-controlled marking + audit only; do not build code-level CUI egress denial.
- FIPS is a hard production runtime requirement, but non-FIPS development uses `LLIAM_GOV_ALLOW_NON_FIPS=1`.
- The SSD is exFAT. Before every commit, run:

```bash
find . -name '._*' -type f ! -path './.git/*' -delete
```

- Always use the APFS venv:

```bash
UV_PROJECT_ENVIRONMENT=/Users/just_jerome/.venvs/lliam-gov
```

- Avoid plain `pytest -q` for the whole suite. Use:

```bash
UV_PROJECT_ENVIRONMENT=/Users/just_jerome/.venvs/lliam-gov \
  uv run python scripts/run_tests_parallel.py
```

Baseline noise floor is documented under `evidence/phase2/noise-floor-2026-05-26.md`: 11 files / 36 fails under `uv sync --extra all`, no collection errors.

## Suggested First Move

1. Confirm `main` is current and clean:

```bash
git fetch --all --prune
git switch main
git pull --ff-only
git status --short --branch
```

2. Create a new branch:

```bash
git switch -c phase3/audit-logger
```

3. Implement and test `audit_logger.py` as the next small Phase 3 PR.

Brief Jerome before any commit/push/PR if the design has ambiguity.
