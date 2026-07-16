# AI System Impact Assessment & Risk Acceptance — Lliam-GOV

| Field | Value |
|---|---|
| Document | AI System Impact Assessment & Risk Acceptance — Lliam-GOV (LG-RM-05/06) |
| Owner | Lliam-GOV Program |
| Classification | CUI//SP-PRIV (template — mark per instance) |
| Version | 1.0 |
| Date | 2026-07-16 |
| Approval | Signed (§11) |

> **Purpose.** This is the OMB M-25-21 high-impact-AI **impact assessment** and **signed risk-acceptance package** for **Lliam-GOV**, an autonomous AI agent forked from Nous Research's Hermes Agent (MIT) and hardened via an additive, path-frozen governance overlay. It satisfies the M-25-21 §4(b)(ii) pre-deployment AI impact assessment with independent review, §4(b)(iii) ongoing monitoring, §4(b)(v) human-oversight-with-fail-safe, and §4(b)(vi) consultation/remedy expectations, and it provides the named-authority risk-acceptance signature required by **LG-RM-06**. It is the impact-assessment input to the SoA (LG-RM-04), the go/no-go authorization record (LG-GV-06), the high-impact determination register (LG-RM-06), and the threat register (LG-RM-02).
>
> **Grounding.** Every claim is bound to a canonical **LG-\*** control with its real, additive config point; enforcement is the graduated allow / detect-log / approval-gate / deny disposition mandated by **LG-RM-08** and recorded in the PDP tiering matrix `policy/tool-risk-policy.yaml` (LG-RM-03). **Additive — no existing upstream or Lliam path renamed.**

---

## 1. System Identification & Scope of Assessment

| Field | Value |
|---|---|
| System name | Lliam-GOV (autonomous AI agent) |
| System type | Multi-provider local-CLI inference agent; non-person entity (NPE) / privileged system user |
| Provenance | Forked from Hermes Agent (Nous Research, MIT); hardened via an additive, path-frozen governance overlay |
| Information processed | Eval deployment: **no CUI in scope**; posture floor enforced for CUI//SP-PRIV + PII regardless |
| CUI floor | NIST SP 800-171 r3 / CMMC Level 2 (primary); 800-172 / L3 enhancements annotated, not assumed |
| Assessment trigger | OMB M-25-21 high-impact-AI presumption (§3) |
| Assessment instrument | `docs/governance/ai-impact-assessment.md` (this artifact) — **LG-RM-05** |
| Determination register | `docs/governance/high-impact-determinations.yaml` — **LG-RM-06** |
| Authorization boundary | The agent itself (tools, MCP client, skills/plugins, persistent memory, ACP adapter, desktop app, inference routing across all five paths, hash-chained audit ledger, encryption-at-rest posture). Host OS, network fabric, facility **inherited**. |

This assessment covers the **gov-baseline profile** (`cli-config.gov.yaml` selected via `HERMES_CONFIG`, `security.posture: strict`). Each distinct use case is governed by its row in the LG-RM-06 determination register; this document is the master assessment those rows reference.

## 2. Intended Purpose & Expected Benefits

Lliam-GOV is authorized to perform **analyst-augmentation and IT/mission-support automation** within the documented mission scope (`docs/governance/intended-use.md`, LG-GV-02): document review/summarization, drafting/editing in a confined workspace, code authoring/review in a sandboxed backend, structured research over approved sources, and orchestration of vetted tools — under graduated enforcement and human oversight for high-impact actions.

**Capability-preservation principle (binding).** Enforcement is graduated per **LG-RM-08**: allow-by-policy (low-risk reads, allowlisted-provider inference) → detect-and-log (bounded mutation, to the LG-AU-01 ledger) → approval-gate (high-impact/irreversible/egress actions) → deny (only excluded capabilities, e.g. godmode). No tiered control blanket-denies where a graduated control keeps the agent useful; false-block and override rates are quality objectives (LG-QT-02) reviewed at management review.

## 3. High-Impact Determination Rationale (M-25-21)

**Determination: HIGH-IMPACT AI.** Recorded per use case in `docs/governance/high-impact-determinations.yaml` with signed acceptance; enforced at boot by the LG-GV-06/LG-GV-10 startup gates (`lliam_cli/security_audit_startup.py`) — a high-impact enablement without a valid signed record fails closed.

| # | Determinant | Why it drives the finding | Controls / threat refs |
|---|---|---|---|
| D1 | **Autonomy** | Headless/batch/sub-agent turns act without per-turn human review; as-shipped the loop breaker was warn-only. | LG-HO-02, LG-AZ-12, LG-RM-09 |
| D2 | **CUI/PII exposure class** | The posture floor governs CUI//SP-PRIV + PII handling; as-shipped `redact_pii: false` let PII flow to providers. | LG-DP-01/02/04/09, LG-PF-03/09 |
| D3 | **Real-world tool actions** | Model output is piped into shell, file write/edit, web, and an MCP client — one injected instruction becomes a real consequence. | LG-AZ-01..12, LG-NE-01..06 |
| D4 | **Off-boundary provider routing** | The router can reach non-US/commercial providers across five routing paths — a silent non-US route is reportable spillage. | LG-MP-01/02/03/04 |
| D5 | **Bundled offensive skill** | The fork ships `godmode`, a jailbreak skill that overwrites the agent's own system prompt. | LG-SC-01, LG-CH-06, LG-GV-02, LG-RM-04 |

Any of D2–D4 alone triggers the presumption; the conjunction makes it unambiguous. **No "not-high-impact" determination is claimed for any presumed-high-impact category** (which would require documented CAIO notification per LG-RM-06).

## 4. Foreseeable Misuse & Affected Parties (LG-RM-05)

| Misuse scenario (threat ref) | Mechanism | Affected parties | Mitigating disposition |
|---|---|---|---|
| Indirect prompt-injection → exfiltration (R-02, R-01) | Hostile instruction in fetched content steers a headless run to read and exfiltrate secrets. | Data owners; individuals whose PII is present | LG-PI-01/04/06 detection→approval; LG-NE-01/02/03 deny egress; LG-HO-02 fail-closed |
| Excessive agency → host compromise (R-03, R-14) | Standing shell/browser turns one injection into persistence and out-of-workspace writes. | Host owner; enclave | LG-AZ-03/05/07/11 least-privilege; LG-CH-05 sandbox; LG-PI-09 sink validation |
| Silent non-US provider route (R-06) | Fallback/MoA hop fails over off-allowlist with sensitive context. | Data owners; agency | LG-MP-01/02/03 deny fail-closed; LG-DP-10 taint gate |
| godmode enablement "to get an answer" (R-07) | Operator/attacker loads the jailbreak skill; agent rewrites its own system prompt. | All parties | LG-SC-01 deny + LG-CH-06 build-stop + never-waivable (LG-GV-10) |
| Memory poisoning → durable backdoor (R-09) | Background review "learns" an attacker rule that re-enters every session. | Future tasks; data owners | LG-MC-01/03 write-side validation + provenance; LG-HO-04 staged approval |
| Approval subversion in headless runs (R-04) | Auto-approve branch silently approves destructive commands unattended. | Workspace; host | LG-HO-02/03/06 fail-closed deny; LG-PI-07 guard hardening |
| Audit tampering (R-05) | Hijacked turn truncates its own log. | Assessor/AO accountability | LG-AU-01 hash chain; LG-AU-07 logs outside write reach; LG-AU-08/09 fail-closed |
| Denial-of-wallet / runaway loop (R-13) | Injection traps the agent in an expensive retry loop. | Budget; availability | LG-AZ-10/12 budgets + hard-stop; LG-IR-01/03 kill-switch (P5.3) |
| Confabulation → wrong high-impact action (R-16) | Hallucinated command executed or rubber-stamped. | Operators; affected individuals | LG-QT-05/06 grounding (P4.4); LG-HO-08/09 JIT rationale + appeal |

**Affected parties & privacy/civil-rights analysis.** Individuals whose PII/CUI-class data is processed are the primary affected party — mitigated by classification-driven redaction/routing (LG-DP-01/02/04, LG-MP-03; `privacy.redact_pii: true`), with rights-affecting harms treated under the PF domain (LG-PF-01..07, P4.4 — POAM-P4-QMS) and an appeal/human-handoff channel (LG-HO-09). Operators face automation-bias risk (LG-HO-07/08). Host/enclave owners face RCE/exfil (AZ/NE domains). The agency/AO faces residency spillage and accountability loss (LG-MP-01/02, LG-AU-01).

## 5. Quality & Appropriateness of Data

All ingested web/file/tool/MCP content is untrusted-by-default and provenance-tagged (LG-PI-01, LG-MC-03); always-on sanitization scrubs control-char/invisible/bidi smuggling (LG-PI-02). Lliam-GOV uses third-party foundation models via allowlisted providers and does not train on operational data; no-train terms are vetting preconditions (LG-MP-03) and per-model data appropriateness is documented in model cards (LG-MP-05). Memory hygiene: write-side validation, per-session partitioning, bounded TTL (LG-MC-01/02/05).

## 6. Independent Review (LG-RM-05)

The independent reviewer — bound to the `auditor` role (`governance.role_bindings.auditor`), organizationally independent of the build/deploy line by SoD (LG-GV-05, non-waivable) — confirmed the high-impact determination and register entries, validated foreseeable-misuse coverage against the threat model and SoA exclusions, and confirmed the testing evidence and monitoring plan below.

| Independent-review attestation | Value |
|---|---|
| Reviewer role / principal | auditor — auditor@independent.mil |
| Findings summary | Determinations HID-2026-001..004 consistent with the PDP tiering matrix and the SoA exclusions; misuse coverage traces to the threat register; monitoring items correctly carried on the POA&M rather than claimed. |
| Disposition | Concur |
| Date | 2026-07-16 |

## 7. Testing Before Deployment (M-25-21 §4(b)(ii))

| Test | What it proves | Status / evidence |
|---|---|---|
| Egress / exfiltration | Deny-by-default egress + SSRF/metadata blocking; non-allowlisted routes rejected on all five paths | PASS — P2.5/P3.1 reports (`docs/governance/verification/`) |
| Approval fail-closed | A dangerous command in a headless run is denied, not auto-approved | PASS — P2.2 report (LG-HO-02) |
| Audit-chain integrity | Chain detects deletion/reorder/edit; verifies at startup; fail-closed on write failure | PASS — P1.1/P1.3 reports + `audit_chain_selftest.py` |
| godmode exclusion preflight | Build fails if a prohibited skill is enabled | PASS — `prohibited_skills_gate.sh` (P0.7), waiver gate (P4.1) |
| Governance mandatory-artifacts | Policy/authorization/waiver artifacts enforced fail-closed at startup | PASS — P4.1 report |
| Prompt-injection red-team suite | Injection/jailbreak/tool-abuse corpus does not reach prohibited actions | Scheduled P4.5/P5.2 — POAM-P4-SDLC / POAM-P5-EVAL |
| Halt/rollback (kill-switch) | Halt suspends tools+inference; clean full-capability restore | Runbook documented (P4.2); test scheduled P5.3 — POAM-P5-IR |

## 8. Ongoing Monitoring (M-25-21 §4(b)(iii))

Post-authorization monitoring is scheduled on the POA&M and lands in Phase 5: ISCM/SIEM streaming (`monitoring.iscm_sink`, LG-MO-05) with anomaly/drift/runaway monitors (LG-MO-01..04/06) at P5.1; scheduled adversarial re-evaluation + control-effectiveness verification + output monitoring (LG-MO-07..10, LG-PF-08/09) at P5.2; the cATO re-authorization loop (LG-GV-07/08) at P5.4. Until then, the compensating posture is point-in-time authorization with hard expiry (LG-GV-06), verify-on-startup audit-chain integrity (LG-AU-08), and the local CI gate battery run before every push.

## 9. Human Oversight & Remedy (M-25-21 §4(b)(v)–(vi))

HITL on high-impact/irreversible actions at the approval seams with an authenticated approver (LG-HO-01, LG-GV-05); fail-safe deny-by-default scoped to high-risk tiers when no approver is reachable (LG-HO-02/06) — low/medium-risk work proceeds; non-disableable hardline blocks (LG-HO-03); JIT risk rationale + anti-fatigue rate limiting (LG-HO-07/08); appeal/override + human-handoff channels (LG-HO-09) with every decision ledger-recorded (LG-HO-10). The kill-switch procedure is `docs/governance/halt-rollback-runbook.md` (LG-RM-09).

## 10. Residual-Risk Statement

Residual ratings per risk are maintained in `docs/governance/threat-risk-register.yaml` (LG-RM-02): with the gov overlay applied, every Critical-inherent threat is reduced to Low or Low–Med and no residual exceeds **Medium**. Remaining Medium residuals (prompt injection, MCP supply chain, memory poisoning, CUI/PII disclosure, model supply chain, goal drift) are bounded by detect-and-log monitoring, the named POA&M items (`docs/governance/poam.yaml`: POAM-P4-QMS, POAM-P5-MON, POAM-P5-EVAL, POAM-P5-IR, POAM-FIPS, POAM-EGRESS-ENCLAVE), and the halt/rollback fail-safe. Residual risk is assessed **acceptable for the authorized eval scope under the conditions in §11.3**.

## 11. Risk Acceptance — Named-Authority Signature Block

Signers are the authenticated principals bound in `governance.role_bindings`; co-held roles in the single-operator eval deployment are covered by the tracked, expiring deviations in `docs/governance/roles.yaml` (LG-GV-05). The signed acceptance is referenced from `high-impact-determinations.yaml` (`signed_acceptance.reference`) and `authorization-record.yaml`.

### 11.1 Risk-acceptance authorities

| Role (LG-GV-04 RACI) | Principal | Decision | Date |
|---|---|---|---|
| Authorizing Official (Approver) — accepts residual risk; go/no-go (LG-GV-06) | jdavis@agency.mil | Authorize (eval scope, conditions §11.3) | 2026-07-16 |
| Chief AI Officer (CAIO) — high-impact determination + waivers (LG-RM-06, LG-GV-10) | jdavis@agency.mil | Concur | 2026-07-16 |
| ISSO — confirms 800-171 r3 / CMMC L2 posture floor | jdavis@agency.mil | Concur | 2026-07-16 |
| AI Risk Owner — residual-risk register (LG-RM-02) | jdavis@agency.mil | Concur | 2026-07-16 |

### 11.2 Independent reviewer (LG-RM-05)

| Reviewer | Principal | Disposition | Date |
|---|---|---|---|
| Independent review attestation (auditor role, SoD-enforced) | auditor@independent.mil | Concur | 2026-07-16 |

### 11.3 Conditions of acceptance

1. The gov overlay (`cli-config.gov.yaml`, `security.posture: strict`) is the only authorized runtime posture; the running baseline must match the approved pin (LG-GV-06, LG-CH-03).
2. godmode/obliteratus remain disabled — never waivable; other baseline-denied capabilities re-enable only via a valid time-boxed CAIO waiver (LG-GV-10) and re-acceptance.
3. Inference stays on the approved-provider allowlist across all five routing paths (LG-MP-01/02).
4. POA&M items are remediated on their milestones; status reviewed at each phase gate and management review (LG-GV-08).
5. This authorization is continuous, not point-in-time: it expires per `authorization-record.yaml` and auto-suspends on critical posture-break once the P5.4 cATO loop is in force; until then any posture-break requires manual halt per the runbook and re-authorization.

## 12. Evidence Index

| Evidence artifact | Source of truth | Control |
|---|---|---|
| This impact assessment | `docs/governance/ai-impact-assessment.md` | LG-RM-05 |
| Determination register + signed acceptance | `docs/governance/high-impact-determinations.yaml` | LG-RM-06 |
| Statement of Applicability + catalog | `docs/governance/SoA.md` + `control-catalog.yaml` | LG-RM-04 |
| Go/no-go authorization record | `docs/governance/authorization-record.yaml` | LG-GV-06 |
| RACI / roles / SoD | `docs/governance/roles-raci.md` / `roles.yaml` | LG-GV-04/05 |
| Capability×impact tiering (PDP-enforced) | `policy/tool-risk-policy.yaml` + `tools/tool_policy.py` | LG-RM-03 / LG-RM-08 |
| Threat register | `docs/governance/threat-risk-register.yaml` | LG-RM-02 |
| POA&M | `docs/governance/poam.yaml` | LG-RM-07 |
| Halt/rollback runbook | `docs/governance/halt-rollback-runbook.md` | LG-RM-09 |
| Per-step verification evidence | `docs/governance/verification/` | (all) |

---

*Built on Hermes Agent (Nous Research, MIT). Governance overlay is additive and capability-preserving.*
