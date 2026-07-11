# P1.V — Phase 1 Verify Gate / Capability-Preservation Report

| Field | Value |
|---|---|
| Gate | P1.V — Phase 1 (Identity, Audit & Accountability) verify gate |
| Linear | AI-480 |
| Branch | `harden/phase-1-identity-audit` (PR #94, cut at `gov-R-good` / `62cfe87d`) |
| Date | 2026-07-11 |
| Status | **STRUCTURAL VERIFICATION COMPLETE** · live capability corpus + Codex pass + `gov-P1-good` tag **PENDING** (see §Gate status) |

## Purpose
Confirm the six P1 slices (P1.1–P1.6) kept the agent's capabilities intact — the capability-preserving guarantee: the ledger is **record-then-proceed**, only *consequential* actions gate (fail-closed on audit-write failure / unauthenticated network control plane), and no tool/skill/MCP/provider was removed. Then tag `gov-P1-good`.

## Slices delivered (all on PR #94, each independently reviewed)
| Step | Linear | Controls | Verified |
|---|---|---|---|
| P1.1 | AI-516 | LG-AU-01..07,09 | append-only hash-chained ledger; multi-writer safe (post-review hardening) |
| P1.2 | AI-517 | LG-AU-02,10; MC-03; QT-03 | 100% dispatch coverage (34/34 tools emit) |
| P1.3 | AI-518 | LG-AU-08 | verify_chain + startup gate + CI/cron |
| P1.4 | AI-519 | LG-IA-01..05,10 | agent NPE identity + fail-closed credential isolation |
| P1.5 | AI-520 | LG-IA-06..09,11 | control-plane auth gate (API-key RCE gate + TLS) |
| P1.6 | AI-479 | LG-GV-04,05 | roles/RACI + SoD gate (honest deviations) |

## Structural verification — COMPLETE (green)
- **Governance test suite: 117/117 pass** across all six slices (`test_governance_audit`, `_hooks`, `agent_identity`, `secret_scope_isolation_gov`, `audit_chain_startup`, `control_plane_auth`, `security_audit_startup`, `sod_check`), under isolated `HERMES_HOME` on the provisioned dev-clone venv.
- **All five governance CI gates pass end-to-end** (`gov-R-good`..HEAD): path-freeze (29 guarded paths, none renamed/deleted — **PATH-FREEZE held across the entire phase**), baseline-drift (14 P0 keys intact), SoD (0 blocking / 2 tracked deviations), audit-chain self-test, prohibited-skill (godmode). PR #94 CI green.
- **Overlay loads + ledger activates** through the real `cli-config.gov.yaml` (`ledger_enabled: True`), and the agent binds the full gov toolset — the **P1.2 coverage demo showed 34/34 registered tools bind and emit** under the overlay (no tool removed).
- **Record-then-proceed confirmed** (the capability core): read-only tools are never fail-closed; a low-risk audit-write failure degrades to a logged warning (returns None, action proceeds); only high-risk (`mutating/privileged/egress/high_impact`) actions gate on a persisted record. Demonstrated in the P1.1/P1.2 verification demos.
- **Baseline coherence:** the single `security:`/`governance:` block invariant holds (no duplicate-key posture drop); strict posture coerces the new fail-closed switches (`api_server_key_required`, `require_tls`).

## Gate status — what remains (PENDING, needs Jerome's environment)
The following are **deliberately not done in this session** and gate the `gov-P1-good` tag:

1. **Live capability corpus (§6 task corpus).** The exit-criteria run — representative low/medium actions still allow/log (no prompt fatigue), high-risk actions complete when an approver is present, a CUI-tainted-egress attempt is the *only* class blocked, an authorized-domain web fetch still succeeds — requires a **working provider/model** (Bedrock GovCloud or equivalent). This isolated verification env has **no provider credentials** (auxiliary providers report payment/credit errors). This run must execute in Jerome's provisioned environment.
2. **Full-phase Codex adversarial pass.** Per the standing cadence, Codex reviews the accumulated PR #94 at the phase-V gate before merge — gated on Codex credits refreshing.
3. **`gov-P1-good` tag.** **Deliberately NOT applied.** A phase-good tag must attest to a completed verification (the exact P2 Codex caught on the Phase-R tag in #93 — "the tag must carry what it attests"). It will be applied only after items 1–2 pass, on the phase-close merge commit.

## Accepted residuals carried to the cross-phase remediation pass
- **LG-AU-08-R1** — external anchoring / WORM replication (verify_chain proves internal consistency, not authenticity vs full-file rewrite/truncation).
- **LG-IA-03-R1** — migrate `tools/terminal_tool.py` `TERMINAL_SSH_*` reads from `os.getenv` to `secret_scope.get_secret` (the allowlist is minimized; the direct read still bypasses scoping — must land before any multi-profile deploy).
- **LG-GV-05 runtime** — wire the authenticated approver principal into each `approval.decision` ledger record (`tools/approval.py`); the P1.2 subject seam + taxonomy already support it.
- Per-record identity signing; live `security.accounts` reconcile; Bitwarden managed-source migration; cert/SPKI pin enforcement; runtime `delegation.max_spawn_depth` enforcement; LG-IA-08-R1 per-endpoint MCP `ssl_verify`.

## Bottom line
Phase 1 is **built, internally verified, and CI-green** — the six controls are structurally sound and the capability-preserving design holds under every check runnable without a live model. The phase is **ready for the live capability corpus + Codex pass**, after which `gov-P1-good` is tagged and PR #94 merges to `main` on Jerome's word.
