# Lliam-GOV — Pre-Hardening Baseline Capability Note

| Field | Value |
|---|---|
| Document | Baseline Capability Note (what works today, pre-hardening) |
| Phase | S0.1 — Phase 0 baseline |
| Branch | `harden/phase-0-baseline` |
| Captured | 2026-06-29 |
| Engine | Hermes Agent (Nous Research, MIT) — Lliam-GOV fork |
| Status | Living record — update as the baseline is re-measured each phase |

This note records the agent's **as-shipped, pre-hardening behavior** so later phases have a
truthful "before" to compare against. Per the capability-preservation doctrine, no hardening
control is allowed to remove a capability recorded here without a logged decision in
[`regression-log.md`](regression-log.md).

---

## Isolation context for this baseline

- **Clone under test:** `~/dev/lliam-gov` (fresh clone of `jdavis-cyber/lliam-gov`, branch `harden/phase-0-baseline`).
- **State isolation:** `HERMES_HOME=~/dev/lliam-gov-home` — set **per-invocation only**, never exported globally, never written to `~/.zshrc`. All test-agent credentials, memory, sessions, and logs live there, never in the live `~/.hermes`.
- **Interpreter:** the live venv at `~/.hermes/hermes-agent/venv/bin/python` drives the **clone's** code (Python puts the script dir first on `sys.path`, so the clone's `hermes_cli` wins). No code was modified to run this baseline.
- **Credentials:** `.env` + `auth.json` were **copied** from the live home into the throwaway home so the test instance is functional. The live install was never read from at runtime and never modified.
- **Backups in place:** `~/.hermes` → `~/.hermes.pre-harden-backup` (3.6G); `~/Library/Application Support/Lliam-GOV` → `…/Lliam-GOV.pre-harden-backup` (2.0M).

---

## What works today (verified 2026-06-29)

| Capability | How verified | Result |
|---|---|---|
| CLI launches from the clone | `hermes --help` lists full subcommand set | ✓ responds |
| Status / config introspection | `hermes status` | ✓ Provider `OpenAI Codex` (OAuth, logged in); model resolves to `gpt-5.4` from config |
| Provider inference | one-shot `-z` prompt against `gpt-5.4` via `openai-codex` | ✓ completes |
| File read tool | agent read `sample.py` in cwd | ✓ |
| Coding task / file write tool | agent created `multiply.py` with `multiply(a,b)` | ✓ correct (`multiply(6,7)=42`) |
| Plugin discovery | agent.log: "Plugin discovery complete: 51 found, 44 enabled" | ✓ |

**Smoke prompt used:** *"Read the file sample.py in the current directory, then create a new file
multiply.py containing a function multiply(a, b) that returns a*b. Reply with the single word DONE
when finished."* → agent read the file, wrote a correct `multiply.py`, replied `DONE` (exit 0).

### Baseline defaults observed (permissive — to be hardened additively)
- Default model `gpt-5.4`, provider `openai-codex`, `base_url https://chatgpt.com/backend-api/codex`.
- `agent.max_turns: 60`, `reasoning_effort: medium`.
- Plugin discovery enables 44/51 plugins by default (includes browser, image/video gen, web-search providers) — least-functionality review is a Phase-0 task (LG-CH-04 / LG-AZ-03).
- One-shot tool use required `--yolo` in non-interactive mode (approval gate is interactive by default).

---

## Standing capability corpus (re-run every phase — Implementation Plan §6)

Expect PASS each phase except where a control *intentionally* introduces an acceptable new block
(record those in the regression log, not as failures):

1. Multi-file code change within `HERMES_WRITE_SAFE_ROOT` (read, edit, run tests in sandbox).
2. Document/data analysis over a CUI-marked input (markings preserved, no leak).
3. Authorized-provider inference call on each routing path (primary + fallback).
4. Authorized-domain web fetch (allowlist hit) + an MCP call to an allowlisted server.
5. A high-risk action that proceeds **with** an approver and is correctly **denied without** one.

> S0.1 covers items 1 (partial — single-file, no sandbox yet) and the read/inference legs. The
> full corpus is exercised from Phase 0 exit onward as the controls that gate items 2–5 come online.

---

## Rollback reminder (config-only, reversible)

The governance overlay is **additive and environment-selected**. To drop back to shipped behavior:
unset/repoint `HERMES_CONFIG` (falls back to `cli-config.yaml.example`) or check out the previous
signed git tag of `cli-config.gov.yaml`. No frozen path is ever renamed, so there is nothing to un-rename.
