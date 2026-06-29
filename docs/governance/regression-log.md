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
| — | _No regressions recorded yet. Baseline captured at S0.1; agent fully functional._ | — | 2026-06-29 |
