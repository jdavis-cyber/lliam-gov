# Secure Development, V&V & Change Governance — Lliam-GOV

| Field | Value |
|---|---|
| Document | Secure-development governance: V&V gates, change control, corrective-action loop (LG-SD-02..08) |
| Owner | ISSO (`governance.role_bindings.isso`) |
| Classification | CUI//SP-PRIV (template — mark per instance) |
| Version | 1.0 · 2026-07-16 |
| Review-by | At each management review (LG-GV-08) |

> **Purpose.** The secure-development and change-governance layer for the hardening program: how requirements become testable controls (LG-SD-02), the V&V gates that prove guardrails fire before release (LG-SD-03), peer review + independent challenge (LG-SD-04), the security/red-team test suite (LG-SD-05), the release go/no-go gate (LG-SD-06), runtime-change control (LG-SD-07), and the nonconformity/corrective-action loop (LG-SD-08). LG-SD-01 (path-freeze change policy) has been enforced since P0.7.

## 1. Requirements → controls (LG-SD-02)

CUI/CMMC/M-25-21 requirements are captured as testable agent requirements in `docs/governance/requirements-traceability.yaml`: each requirement names its realizing LG-* control(s) and the verification method that proves it. The matrix is machine-checked (controls resolve to `docs/governance/control-catalog.yaml`).

## 2. Verification & Validation gates (LG-SD-03)

Each guardrail has a pass/fail V&V gate that must be green before a phase merges. The gates prove the guardrail **fires**, not just that it exists:

| Guardrail | V&V gate (pass criterion) |
|---|---|
| Approval / HITL fail-closed | `tests/lliam_cli/test_control_plane_auth.py` + P2.2 report — a headless dangerous action denies |
| Egress / SSRF | `tests/governance/test_p45_redteam_corpus.py` (metadata blocked) + P2.5 report |
| Prompt-injection defense | `tests/governance/test_p45_redteam_corpus.py` (injection flagged, taint set, sink blocked) |
| Audit-chain integrity | `ci/governance-ci-gates/audit_chain_selftest.py` — tamper detected |
| Provider allowlist | `tests/governance/test_p3_capability_corpus.py` — non-allowlisted route denied on all 5 paths |
| Prohibited skills | `ci/governance-ci-gates/prohibited_skills_gate.sh` — godmode enable fails |
| Baseline / path-freeze | `baseline_drift_gate.py` + `path_freeze_gate.py` |
| SoA / SSP / regulatory reconciliation | `soa_gate.py` + `ssp_reconciliation_gate.py` + `regulatory_reconciliation_gate.py` |
| Fairness | `fairness_gate.py` — unevaluated model/provider/prompt change blocked |
| Release preconditions | `go_no_go_gate.py` |

Capability preservation is itself a V&V gate: the P2/P3 capability corpora prove authorized work still flows.

## 3. Peer review & independent challenge (LG-SD-04)

`.github/CODEOWNERS` requires owner review on every governance-config, enforcement-code, policy-allowlist, CI-gate, and prompt/skill change; `docs/governance/branch-protection.md` is the `main` branch-protection configuration of record (require Code Owner review, no direct pushes, include administrators). High-impact governance changes additionally get independent challenge by the auditor role (SoD-separated).

## 4. Security tests & red-team suite (LG-SD-05)

The additive security tests (approval, egress, injection, audit-chain) plus the prompt-injection red-team corpus (`tests/governance/test_p45_redteam_corpus.py`) run in the local gate battery before every push (the CI substitute — no CI credits, July 2026; the same suite runs as required status checks when credits return). The corpus fires categorized adversarial payloads at the real shipped defenses and asserts each is caught by its responsible control. A **scheduled** (recurring, not just pre-merge) red-team + control-effectiveness job lands at P5.2 (POAM-P5-EVAL).

## 5. Release go/no-go gate (LG-SD-06)

`ci/governance-ci-gates/go_no_go_gate.py` fails closed unless every release precondition holds: strict posture, godmode + obliteratus disabled, provider allowlist enforced, audit ledger on, at-rest encryption asserted, a signed/unexpired/matching authorization record, and a reconciled (signed) SoA. It composes the machine gates into the human checklist assessors expect; it is also the go/no-go checklist embedded in the authorization record.

## 6. Runtime / in-operation change control (LG-SD-07)

In-operation changes — hot config reload, allowlist edit, provider failover — are controlled: the config baseline is version-controlled and drift-gated (LG-CH-03), writes never target the overlay, and any deviation is recorded in `docs/governance/deviation-register.yaml` (LG-CH-08) with pre/post state in `docs/governance/change-record.md`. Provider failover is bounded by the allowlist enforced on the fallback/MoA/auxiliary/delegation paths (LG-MP-02) — a failover cannot silently reach a non-allowlisted endpoint. Consequential runtime changes are ledger-recorded with the responsible principal (LG-AU-01/10).

## 7. Nonconformity & corrective-action loop (LG-SD-08)

Nonconformities (a failed V&V gate, a `policy.violation` ledger event, an audit finding) open a **corrective action (CAR)**: root-cause analysis, a remediation with owner + milestone tracked on `docs/governance/poam.yaml`, and **effectiveness re-testing** — the fix must be demonstrated by a passing V&V gate before the CAR closes. Recurring nonconformities feed the QMS continual-improvement cycle (`docs/governance/qms-process-maps.md` §5) and management review (LG-GV-08); a critical one triggers the halt/rollback runbook (LG-RM-09).

---

*Built on Hermes Agent (Nous Research, MIT). Governance overlay is additive and capability-preserving.*
