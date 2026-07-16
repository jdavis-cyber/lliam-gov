# P4 — Capability-Preservation Verification Report

| Field | Value |
|---|---|
| Phase | Phase 4 — Management System, Risk & Impact |
| Gate | AI-498 (P4.V) |
| Branch | `harden/phase-4-mgmt-system` (cut at `gov-P3-good` / `e92b6f35`) |
| Date | 2026-07-16 |
| Result | **PASS** — no mission capability regressed; no new runtime block |

## Purpose
Prove that Phase 4 (the management-system, risk, and documentation layer)
hardened Lliam-GOV's **governance** without cutting off any authorized
capability. Phase 4 is deliberately documentation- and CI-heavy: its only new
"block" is CI/preflight failing a **non-compliant change** — there is no new
*runtime* block introduced by any P4 step. Per the P4 emphasis (Plan §6),
every SSP/SoA/register/POA&M control must cite a REAL enforced config point;
godmode is excluded with justification; high-impact determinations carry a
signature block; and the P4.2 capability×impact tiering matrix equals the one
the P2.1 PDP already loads.

## Phase 4 slices verified
| Step | Issue | Controls | New block class |
|---|---|---|---|
| P4.1 | AI-493 | LG-GV-01/03/06/10 | CI/startup: absent/placeholder/expired governance artifact; unwaivered high-risk skill |
| P4.2 | AI-494 | LG-RM-01..07,09 | CI: SoA/POA&M not reconciled; unsigned high-impact determination |
| P4.3 | AI-495 | LG-IN-01/04..07 | CI: an SSP family citing a non-existent config point |
| P4.4 | AI-496 | LG-QT-*, LG-PF-01..07 | CI: a model/provider/prompt change without a fairness evaluation |
| P4.5 | AI-497 | LG-SD-02..08, LG-TP-01/02/04/08 | CI: a release with an unmet precondition (go/no-go NO-GO) |

**Every new block is a CI/preflight block on a non-compliant change — none is a runtime capability block.**

## Findings
- **Docs reconcile to enforcement (the P4 emphasis).** Three reconciliation
  gates prove every documented control cites a real enforced point:
  `regulatory_reconciliation_gate.py` (LG-GV-03, obligations → config), 
  `ssp_reconciliation_gate.py` (LG-IN-07, all 17 800-171 r3 families → config),
  `soa_gate.py` (LG-RM-04, SoA ↔ 188-control catalog ↔ POA&M). All green. Every
  backticked repo path in the SSP/boundary/QMS docs is verified to exist.
- **Tiering matrix identity (P4.2 depth check).** The capability×impact matrix
  the risk docs bind to IS `policy/tool-risk-policy.yaml`, the same file the
  P2.1 PDP (`tools/tool_policy.py`) loads — verified via `metadata.pdp_module`,
  the PDP source, and every determination's `action_classes` resolving to the
  matrix. No forked/duplicate matrix.
- **godmode exclusion removes no MISSION capability.** godmode/obliteratus are
  jailbreak/uncensoring skills — excluded (never waivable) in the SoA with
  justification and CI-asserted. They are not mission capability; the full
  core surface (file/shell/web/search/provider/MCP/memory) remains available.
- **High-impact determinations signed.** HID-2026-001..004 carry a signed
  acceptance + independent-reviewer attestation; the test rejects placeholder
  signers.
- **Fairness CI + V&V pass on the current baseline WITHOUT capability
  rollback.** `fairness_gate.py` passes against the current model/provider/
  prompt hashes (FE-2026-001); the red-team/V&V corpus (17 cases) passes
  against the real defenses with capability-preservation counter-cases
  (benign URL/command/content flow; complete no-op on low-side). Nothing was
  disabled to make a gate pass.
- **Capability corpora still green.** The P2 and P3 capability-preservation
  corpora (authorized provider routes on all 5 paths; approved skills/MCP load;
  safe-root coding; graduated enforcement) remain PASS — P4 touched no runtime
  seam.
- **Additive + path-frozen.** `path_freeze_gate.py` green vs `gov-P3-good`
  (29 guarded paths, none renamed); the rename guard passes.

## Full-suite vs noise floor
The full isolated suite (`scripts/run_tests_parallel.py`) was diffed against
the characterized noise floor (~59–60 fail / 21 files;
`~/dev/lliam-gov-baseline/branch-noise-floor.txt`). Phase 4 added only
documentation, CI gates, and tests — no product runtime module changed — so the
failing-file set stays within the floor (the two floor-adjacent files, the
rename-guard test under `tests/rename/` and the atomic-snapshot test under
`tests/tools/`, are the documented rename guard and the environment-dependent
atomic-snapshot flake; the rename guard is green in isolation on this branch
after correcting adapted-text references). See `P4.V-report.md` for the counted
result.

## Conclusion
Phase 4 hardened the **management system** — top-management policy, registers,
risk/impact/SoA/POA&M, SSP, QMS, privacy/fairness, and secure-dev governance —
and every documented control now reconciles to a real enforced config point,
proven by CI. The agent's runtime capability surface is **unchanged**: the only
new blocks are CI/preflight blocks on non-compliant changes. **No tested
mission capability regressed.** Save point `gov-P4-good` is eligible only after
the close-out merge to `main` and post-merge verification.
