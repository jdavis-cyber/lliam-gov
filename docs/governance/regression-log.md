# Lliam-GOV — Capability Regression Log

| Field | Value |
|---|---|
| Document | Capability Regression Log |
| Purpose | Record every instance where a hardening control made the agent *worse* (removed/blocked a capability) and the decision taken |
| Branch | `harden/phase-0-baseline` (started here; carried forward through all phases) |
| Started | 2026-06-29 |
| Status | Living record |

**How to use this log.** Per the capability-preservation doctrine (Implementation Plan §1.4, §6),
hardening must not silently degrade the agent. Whenever a control blocks, breaks, or narrows a
capability recorded in [`_baseline-capability-note.md`](_baseline-capability-note.md):

1. Add a row below.
2. **Decision** is one of:
   - **Accept** — the block is intended and correct (e.g., godmode disabled, CUI-tainted egress denied). Cite the control as justification.
   - **Tune** — the control over-restricted; loosen the specific key/allowlist entry and record it as a deviation (LG-CH-08) with approval.
   - **Revert** — the control caused an unacceptable regression; roll it back (config-only) and re-design.
3. Reference the runtime-change audit entry (LG-SD-07) once Phase 1's ledger is live, so the decision is never silent.

Acceptable new blocks per phase are pre-enumerated in Implementation Plan §6 ("the *only* new
blocks that are acceptable"); anything outside that set needs a Tune or Revert decision here.

---

| Control ID | What regressed | Decision (Accept / Tune / Revert) | Date |
|---|---|---|---|
| — | _No capability regressions recorded._ Baseline captured at S0.1; agent fully functional through P0.4. | — | 2026-06-29 |
| LG-CH-05 | Under `terminal.backend: docker` the agent's file edits write INSIDE the container (`mount_docker_cwd` defaults false), so they don't persist to the host workspace by default. Coding tasks still complete in-sandbox (verified: `add(2,3)=5`). | **Accept (not a regression) + deployment note**: for real CUI coding work, the enclave must set `TERMINAL_DOCKER_MOUNT_CWD_TO_WORKSPACE=true` and bind-mount `HERMES_WRITE_SAFE_ROOT` so edits persist while staying sandboxed. Tracked for the Phase-6 deployment config. | 2026-06-30 |
| LG-AZ-04 / LG-CH-05 | At the P0.V gate: under docker backend the `file_write` tool's safe-root check runs host-side, so a *host* `HERMES_WRITE_SAFE_ROOT` made it deny in-container (`/root`) writes (agent fell back to shell; task still completed). | **Accept (config detail, not a control regression)**: under `terminal.backend: docker`, set `HERMES_WRITE_SAFE_ROOT` to the **container** workspace path (e.g. `/root` or the mounted `/workspace`). Re-ran B1 with `HERMES_WRITE_SAFE_ROOT=/root` → `write_file`/edit tools worked, tests green. No control back-pedaled. Folds into the Phase-6 deployment config above. | 2026-06-30 |
