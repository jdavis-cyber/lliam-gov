# Phase 0 — Baseline Test Noise Floor

**Date:** 2026-05-25
**Plan reference:** Hermes-to-Lliam ISO 42001 Plan, Rev. 3, §9 Phase 0 exit criterion ("record any failing tests as the baseline noise floor")
**Upstream pin:** Hermes Agent v0.14.0, SHA `b62af47da8f1de5cfdbae423caaff5b64c060c9a`, committed 2026-05-25T16:23:24Z
**Host:** Mac mini (darwin 25.5.0, Apple Silicon), Python 3.13.7 via uv-managed venv at `~/.venvs/lliam-gov`
**Repo state at run:** commit `d0776f3` (baseline import, no edits)

## Test invocation

Raw `pytest -q` against the full suite wedged at 18 min with 0% CPU — upstream maintainers wrote `scripts/run_tests_parallel.py` precisely because the suite is impractical under plain pytest (per-test spawn overhead ≈70 CPU min; per-file subprocess isolation ≈3.5 min). The upstream-canonical invocation is therefore:

```
UV_PROJECT_ENVIRONMENT=~/.venvs/lliam-gov \
  uv run python scripts/run_tests_parallel.py
```

(Excludes `tests/e2e/`, `tests/integration/`, `tests/docker/` — those are dedicated CI jobs upstream.)

## Headline numbers

| Metric | Value |
|---|---|
| Test files discovered | 1,197 |
| Tests collected | 26,225 |
| Tests passed | 25,942 |
| Tests failed | 37 |
| Files with ≥1 failure | 12 |
| Pass rate | 98.99% of files / 98.86% of failing-file tests / **99.859%** of all tests |
| Wall-clock | 389.1s (~6.5 min) at `-j 20` |
| Workers | 20 (host CPU count) |

## Failing files (the noise floor)

| File | Failed tests |
|---|---|
| `tests/agent/lsp/test_client_e2e.py` | 2 |
| `tests/acp/test_edit_approval.py` | 3 |
| `tests/agent/test_anthropic_adapter.py` | 5 |
| `tests/gateway/test_shutdown_forensics.py` | 1 |
| `tests/hermes_cli/test_gateway_wsl.py` | 2 |
| `tests/hermes_cli/test_gateway_service.py` | 6 |
| `tests/skills/test_openclaw_migration.py` | 1 |
| `tests/test_live_system_guard_self_test.py` | 4 |
| `tests/tools/test_cross_profile_guard.py` | 7 |
| `tests/tools/test_file_staleness.py` | 3 |
| `tests/tools/test_file_state_registry.py` | 2 |
| `tests/test_tui_gateway_server.py` | 1 |
| **Total** | **37** |

Full raw output: `evidence/phase0/pytest-noise-floor-raw.log` (4,075 lines).

## Triage posture

This file documents the noise floor as a snapshot — it does NOT investigate or fix any of these failures. Per Rev. 3 plan §9 Phase 0 exit, "no edits yet."

Phase 1 (facelift + gateway trim) deletes several of the files that house these failing tests as part of the mechanical gateway-adapter removal — specifically anything under `tests/gateway/platforms/` for the ~17 removed platforms (Discord, WhatsApp, Signal, Matrix, Feishu, WeCom, Weixin, BlueBubbles, DingTalk, Yuanbao, SMS, HomeAssistant, QQBot, MsGraph, api_server, webhook). None of the 12 noise-floor files are on that delete list, so all 12 carry into Phase 1.

Phase 1 exit will re-run the parallel runner and require: failures ⊆ this baseline set (no new regressions introduced by the facelift). Any reduction in failure count from this baseline is a bonus, not a target.

WSL-specific failures (`test_gateway_wsl.py`) are expected-platform-skip on macOS — upstream may have an environmental marker not firing. To be confirmed in Phase 1 PR review, not addressed in Phase 0.

## Reproducibility

Re-running the same invocation on the same host with `__pycache__/` cleared should reproduce this floor within stochastic noise (a few flaky tests at the margin). If the floor drifts by more than ~3 failing tests run-to-run on the same host, flakiness is a Phase 1 follow-up.
