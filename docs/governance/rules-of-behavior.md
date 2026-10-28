# Operator Rules of Behavior & Access Agreement — Lliam-GOV

| Field | Value |
|---|---|
| Document | Operator Rules of Behavior / Access Agreement (LG-TP-02) |
| Owner | ISSO (`governance.role_bindings.isso`) |
| Classification | CUI//SP-PRIV (template — mark per instance) |
| Version | 1.0 · 2026-07-16 |

> The rules-of-behavior every operator acknowledges before CUI access (LG-TP-01 training register records the acknowledgement). The agent's operational guardrails that back these rules are enforced policy (cited per rule), not exhortation — an operator cannot disable them.

## Operator commitments

1. **Authorized use only.** Operate Lliam-GOV only within the documented mission scope (`docs/governance/intended-use.md`) and only under a valid go/no-go authorization (`docs/governance/authorization-record.yaml`). *Enforced: LG-GV-06 startup gate.*
2. **Never enable prohibited capability.** Never attempt to enable `godmode`, `obliteratus`, or any jailbreak/safety-bypass skill. These are excluded and **never waivable**; attempting to enable them fails the build and the startup gate. *Enforced: LG-SC-01, LG-CH-06, LG-GV-10.*
3. **Respect the strict posture.** Never run a CUI session outside the gov overlay (`security.posture: strict`); never set `HERMES_YOLO_MODE` or `approvals.mode=off`. *Enforced: LG-CH-02, LG-HO-03 (hardline blocks are non-disableable).*
4. **Do not self-approve high-risk actions.** The Approver and Engineer roles are separated (Approver ≠ Engineer, non-waivable); respond to approval prompts within your granted role only. *Enforced: LG-GV-05 SoD gate.*
5. **Keep CUI on the allowlist.** Never route CUI to a non-allowlisted provider or external sink; a silent off-boundary route is a reportable spillage. *Enforced: LG-MP-01/02, LG-NE-01, LG-DP-10.*
6. **Preserve the audit record.** Never tamper with, truncate, or relocate the audit ledger. *Enforced: LG-AU-07 (ledger write-denied to the agent) + LG-AU-08 (verify-on-startup).*
7. **Report and halt on anomaly.** On any suspected compromise, injection, or posture-break, trip the kill-switch (`tools/interrupt.py`) and follow `docs/governance/halt-rollback-runbook.md`. The kill-switch owner is named in `docs/governance/roles-raci.md`. *Enforced: LG-RM-09, LG-IR-01.*
8. **Protect credentials.** Never enter credentials/keys into agent-visible fields or commit them; secrets resolve from managed sources and are scoped per profile. *Enforced: LG-IA-03/04, LG-DP-03.*
9. **Complete required training.** Complete the role-based training (`docs/governance/training-register.yaml`) and periodic reassessment before and during CUI access.

## Access agreement

By acknowledging (recorded in the training register), the operator agrees to the commitments above, accepts that all consequential actions are attributed to their authenticated principal in the audit ledger, and understands that violation may result in revocation of role bindings (immediate loss of approval/oversight authority) and access.

---

*Built on Hermes Agent (Nous Research, MIT). Governance overlay is additive and capability-preserving.*
