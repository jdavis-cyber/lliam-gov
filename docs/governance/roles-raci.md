# Roles, RACI & Separation of Duties (LG-GV-04 / LG-GV-05)

| Field | Value |
|---|---|
| Document | Governance Roles, RACI & SoD |
| Owner | Lliam-GOV Program |
| Classification | CUI//SP-PRIV (template — mark per instance) |
| Machine-readable source | `docs/governance/roles.yaml` |
| Bindings | `governance.role_bindings` in `cli-config.gov.yaml` |
| SoD gate | `ci/governance-ci-gates/sod_check.py` (fail-closed) |
| Review-by | 2026-10-11 (or at any org-change) |

> This is the human-accountability layer over `tools/approval.py`, `tools/interrupt.py`, and `acp_adapter/permissions.py`. It changes no agent behavior; it names **who owns** approvals, the kill-switch, and audit independence, and the SoD gate enforces that no one holds a conflicting pair of roles.

## Named accountable roles (LG-GV-04)

| Role | Title | Accountable for | SoD class |
|---|---|---|---|
| `caio` | Chief AI Officer | AI policy, risk acceptance, go/no-go authorization | authorizing |
| `isso` | Information System Security Officer | Security posture, control implementation, ATO evidence | security |
| `ai_risk_owner` | AI Risk Owner | Risk register, residual risk, harm anticipation | risk |
| `approver` | HITL Approver | High-risk action approval, override decisions | approval |
| `engineer` | Engineer / Operator (acting party) | Implementation, tool execution, config change | implementation |
| `auditor` | Independent Auditor | Audit review, chain verification, SoD review | audit |
| `killswitch_owner` | Kill-Switch / Containment Owner | Interrupt, containment, incident response | incident |

## RACI (governance activities)

| Activity | Responsible | Accountable | Consulted | Informed |
|---|---|---|---|---|
| High-risk action approval (HITL) | approver | caio | ai_risk_owner, isso | auditor |
| Tool execution / config change | engineer | isso | approver | auditor |
| Audit-chain verification & review | auditor | isso | — | caio, ai_risk_owner |
| Risk register & residual-risk sign-off | ai_risk_owner | caio | isso | auditor |
| Kill-switch / containment activation | killswitch_owner | caio | isso, ai_risk_owner | auditor |
| Go/no-go authorization | caio | caio | isso, ai_risk_owner | auditor |

## Separation of Duties (LG-GV-05, enforced by the SoD gate)

The SoD gate distinguishes **hard (non-waivable)** rules from **waivable** rules that a constrained deployment may co-hold ONLY via an explicit, owner-signed, expiring entry in `roles.yaml` → `sod_deviations` (never silently):

**Hard — non-waivable (can never be satisfied by a deviation):**
- **Approver ≠ Engineer** — no one both approves and implements a high-risk action (AC-5). The acting **engineer is the NPE agent** (its LG-IA-02 instance identity), the **approver is the human** — separated by construction.
- **Auditor independent** — the auditor must not also be the approver, engineer, AI risk owner, CAIO, or ISSO.

**Waivable — real separations, co-held in eval only with a tracked deviation:**
- **CAIO ≠ AI Risk Owner** — the authority that *accepts* risk must not also *own/characterize* it.
- **Approver ≠ ISSO** — ISSO owns control implementation (an implementing function).

**Also enforced:** no anonymous ownership (`approver`/`auditor`/`killswitch_owner`/`caio`/`isso` must each be bound); `security.require_authenticated_approver: true` fails an anonymous/non-interactive high-risk approval closed (couples to `deny_on_no_approver`).

## Eval-deployment note (single-operator boundary) — tracked deviations, not a silent green

The demo/eval boundary (a single human operator, personally-owned MacBook, no CUI in scope) genuinely violates two *waivable* separations: the operator co-holds CAIO+AI Risk Owner and Approver+ISSO. These are **not** hidden — the gate detects them and reports them as **ACCEPTED DEVIATIONS**, each with a justification, an accountable owner (`jdavis@agency.mil`), and a review-by date (2026-10-11), recorded in `roles.yaml` → `sod_deviations`. The **security-critical** Approver≠Engineer and Auditor-independence pairs are non-waivable and genuinely separated (human vs. NPE agent; auditor = distinct principal). A production/multi-operator deployment removes the deviations and assigns distinct principals; the gate hard-fails if any non-waivable pair is ever violated or a deviation expires/goes missing.

## Evidence produced
- This RACI + `roles.yaml` (named accountable parties incl. kill-switch owner + the SoD rule set with waivable/non-waivable flags).
- `governance.role_bindings` (role → authenticated principal).
- SoD report from `sod_check.py`: **0 blocking conflicts, 2 tracked accepted deviations** (the honest single-operator posture).
