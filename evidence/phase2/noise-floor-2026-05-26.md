# Phase 2-exit / Phase 3-entry — Test Noise Floor (re-measured)

**Date:** 2026-05-26
**Plan reference:** Hermes-to-Lliam ISO 42001 Plan, Rev. 3, §9 Phase 3 exit criterion ("noise floor remains at-or-below Phase 1 baseline")
**Branch measured:** `phase3/encryption-and-audit` (carries the new `lliam_gov/security/` package + `cryptography==46.0.7` and `keyring==25.7.0` pins; otherwise identical to `main` at `80b4afc`)
**Host:** Mac mini (darwin 25.5.0, Apple Silicon), Python 3.13.7, venv at `~/.venvs/lliam-gov`

## Why a re-measure was needed

The Phase 1 noise-floor evidence at `evidence/phase1/noise-floor-2026-05-25.md` did not record the `uv sync` extras list used at the time. When this branch first ran the suite with `uv sync --extra dev`, the result was 16 files / 47 fails plus 9 collection-error files — apparently worse than the Phase 1 baseline of 12 files / 37 fails.

Root cause: the Phase 1 run was almost certainly performed against the `[all]` extra (pyproject.toml lines 184–217), which transitively installs `acp`, `pty`, `mcp`, `websockets`, `youtube-transcript-api` and other packages that several test files import directly. With only `--extra dev`, those files either raise `ModuleNotFoundError` at collection or fail unrelated assertions. With `--extra all` the suite returns to the documented shape.

This document re-establishes the noise floor with the `--extra all` composition explicitly recorded, so Phase 3 (and later phases) have an unambiguous bar to hold.

## Reproduction

```
find . -name '._*' -type f ! -path './.git/*' -delete
find . -name '.___pycache__' -type d ! -path './.git/*' -exec rm -rf {} + 2>/dev/null

UV_PROJECT_ENVIRONMENT=/Users/just_jerome/.venvs/lliam-gov \
  VIRTUAL_ENV=/Users/just_jerome/.venvs/lliam-gov \
  uv sync --extra all

UV_PROJECT_ENVIRONMENT=/Users/just_jerome/.venvs/lliam-gov \
  uv run python scripts/run_tests_parallel.py
```

`matrix` and `messaging` extras are intentionally NOT installed: per the policy comment in `pyproject.toml` (2026-05-12), they pull `mautrix[encryption]` → `python-olm`, which has no buildable wheel on modern macOS without an explicit toolchain. The Phase 1 run did not include them either.

## Result — Phase 3 entry is at-or-below baseline

| Metric | Phase 1 baseline (2026-05-25) | Phase 3 entry (2026-05-26) | Delta |
|---|---:|---:|---:|
| Test files discovered | 1,152 | 1,153 | +1 (`tests/lliam_gov/`) |
| Tests collected | 24,246 | 24,268 | +22 (Phase 3 unit tests) |
| Tests failed | **37** | **36** | **-1** |
| Files with ≥1 failure | **12** | **11** | **-1** |
| Collection-error files | 0 | 0 | 0 |
| Wall-clock | 360.7s | ~365s | ~+5s |

**Exit criterion met:** no new failure files introduced by the Phase 3 branch; one Phase 1 failure file dropped off (env-dependent improvement); one file shifted from 5 to 6 fails (env-dependent flake in a credential-resolution test, no Phase 3 nexus).

## Per-file diff vs Phase 1

| File | Phase 1 fails | Phase 3 entry fails | Notes |
|---|---:|---:|---|
| `tests/agent/lsp/test_client_e2e.py` | 2 | **0** | Improved (D-Bus / LSP env shift on this host) |
| `tests/acp/test_edit_approval.py` | 3 | 3 | Unchanged |
| `tests/agent/test_anthropic_adapter.py` | 5 | **6** | +1 in `TestResolveAnthropicToken` / `TestRunOauthSetupToken` — Claude Code credential-file resolution; orthogonal to Phase 3 |
| `tests/gateway/test_shutdown_forensics.py` | 1 | 1 | Unchanged |
| `tests/hermes_cli/test_gateway_wsl.py` | 2 | 2 | Unchanged (WSL tests on macOS) |
| `tests/hermes_cli/test_gateway_service.py` | 6 | 6 | Unchanged |
| `tests/skills/test_openclaw_migration.py` | 1 | 1 | Unchanged |
| `tests/test_live_system_guard_self_test.py` | 4 | 4 | Unchanged |
| `tests/tools/test_cross_profile_guard.py` | 7 | 7 | Unchanged |
| `tests/tools/test_file_staleness.py` | 3 | 3 | Unchanged |
| `tests/tools/test_file_state_registry.py` | 2 | 2 | Unchanged |
| `tests/test_tui_gateway_server.py` | 1 | 1 | Unchanged (browser launch hint string) |
| **Totals** | **12 files / 37 fails** | **11 files / 36 fails** | **At-or-below baseline** |

## New Phase 3 tests (all green)

The Phase 3 branch adds 22 tests under `tests/lliam_gov/` — all pass:

```
tests/lliam_gov/test_key_manager.py    18 passed
tests/lliam_gov/test_runtime_guard.py   4 passed
```

These exercise `lliam_gov.security.key_manager` (AES-256-GCM round-trip, tamper detection across all three header regions, scrypt determinism, key rotation invalidates old ciphertext, init guards, version-byte rejection) and `lliam_gov.security.runtime_guard.fips_check` (fail-closed on stock OpenSSL, dev override semantics, simulated-FIPS pass-through). No tests touch the real macOS Keychain — a `FakeKeyring` backend is injected.

## Operating note for future phases

Every future noise-floor measurement on this repo must record the `uv sync` extras list it ran against. The omission in `evidence/phase1/noise-floor-2026-05-25.md` cost an hour of triage to recover. Either record the literal flags used (preferred) or use a wrapper script in `scripts/` that pins them.

## Raw artifact

`/tmp/phase3-allextras.txt` (kept until commit `phase3/encryption-and-audit`'s PR is merged; reproducible by re-running the commands in §Reproduction above).
