# AI Governance Policy

| Field | Value |
|---|---|
| Document | AI Governance Policy — Lliam-GOV (policy of record, LG-GV-01) |
| Policy ID | LG-POL-001 |
| Owner | Lliam-GOV Program |
| Classification | CUI//SP-PRIV (template — mark per instance) |
| Version | 1.0 |
| Date | 2026-07-16 |
| Approval | Approved (signature block, §11) |
| Review-by | 2027-07-16 (`governance.policy_review_date`, startup-enforced) |

> **Purpose of this artifact.** This is the top-management AI governance policy of record for Lliam-GOV. It is the human-accountability and management-system layer that authorizes, scopes, and continuously re-authorizes the autonomous operation of the Lliam-GOV agent. It is the single document referenced by the gov configuration overlay (`cli-config.gov.yaml`, selected via `HERMES_CONFIG`) as its `governance.policy_id` / `governance.policy_version` of record (LG-GV-01), and it is the parent under which all subordinate governance artifacts (roles/RACI, registers, impact assessments, authorization record, waiver register, halt/rollback runbook) are issued.
>
> **Audience.** Federal ISSO / assessor, the Chief AI Officer (CAIO) and Authorizing Official, the AI risk owner, and operators. It is written to be testable: every commitment names the LG-* control that enforces it and the additive config point that realizes it.
>
> **Standards satisfied (primary).** ISO/IEC 42001 Clause 5 (Leadership) + Annex A.2 (AI policy) and A.3 (roles/authorities); NIST AI RMF **GOVERN** function; OMB **M-25-21** CAIO duties, high-impact-AI minimum practices, and human-oversight/fail-safe requirement. CUI floor is **NIST SP 800-171 r3 / CMMC Level 2**; 800-172 / CMMC L3 enhancements are annotated and never assumed as baseline.

---

## 1. Policy Statement and Responsible-Use Principles

**LG-GV-01** (establish and approve a top-management AI policy with responsible-use principles and a deviation/exception path).

Lliam-GOV management directs that the Lliam-GOV agent be operated only under explicit, signed authorization; only within an approved mission scope; only on approved in-boundary inference providers; with human oversight on every high-impact action; and with a complete, tamper-evident evidentiary record of its conduct. This policy is **directive** (it states the rules), **preventive** (its hard rules are wired into the startup authorization gate), and **detective** (its presence and currency are re-checked at every boot and on a schedule).

The following responsible-use principles are binding and are mapped, where technically enforced, to the realizing control:

| # | Principle | Enforcing control(s) |
|---|---|---|
| P1 | **Authorized operation only.** Lliam-GOV serves governed work only after a signed go/no-go authorization and a verified compliant baseline. | LG-GV-06, LG-GV-10 |
| P2 | **Bounded mission.** The agent acts only within documented intended use; prohibited uses (notably the `godmode` jailbreak skill) are denied by configuration. | LG-GV-02, LG-RM-04 |
| P3 | **Human oversight on high impact.** Destructive, irreversible, egress, spend, secret-access, and computer-use actions require an authenticated human approver. | LG-GV-05, LG-RM-05, LG-RM-08 |
| P4 | **Data residency / least egress.** CUI is routed only to approved in-boundary providers; offensive/dual-use capability is excluded. | LG-GV-09, LG-GV-03 |
| P5 | **Accountability and traceability.** Every consequential tool call is an access-control decision recorded to the audit ledger with the responsible principal. | LG-GV-05, LG-RM-08 |
| P6 | **Graduated, capability-preserving enforcement.** Controls govern without crippling: allow-by-policy for low-risk reads, HITL for high-risk actions, detect-and-log for the rest. | LG-RM-03, LG-RM-08 |
| P7 | **Continual improvement.** Posture is monitored continuously, reviewed by management on a fixed cadence, and re-authorized; residual risk is signed for. | LG-GV-07, LG-GV-08 |
| P8 | **Fail-safe.** A documented, tested kill-switch can suspend autonomy, cut egress, revoke credentials, and restore a known-good baseline. | LG-RM-09 |

**Realization (additive — no existing path renamed).** This policy is published as `docs/governance/ai-policy.md` (version-controlled, signed). The gov overlay `cli-config.gov.yaml` (loaded via the existing `HERMES_CONFIG` env var) carries a `governance:` block — `policy_id`, `policy_version`, `policy_approved_by`, `policy_review_date` — and register bindings under `governance.registers` (regulatory / authorization / waiver / deviation). `lliam_cli/security_audit_startup.py` is extended with the additive check `enforce_governance_artifacts_at_startup` that is a complete no-op on the low-side posture and **fails closed under strict posture** when `governance.policy_id` / `policy_version` / `policy_approved_by` are absent or placeholder-valued, or `policy_review_date` is past due. No existing Hermes/Lliam module, file, CLI command, or identifier is renamed or moved.

---

## 2. Scope

This policy governs the **Lliam-GOV AI Management System (AIMS)** and the **Lliam-GOV agent** it operates.

**In scope — the AIMS (management system).** The governance roles, authorities, RACI, policies, registers, impact assessments, authorization and re-authorization decisions, management reviews, and the evidence chain that establishes accountable, auditable AI operation. This is the ISO 42001 Clause 5 / Annex A.2–A.3 and AI RMF GOVERN layer.

**In scope — the agent (the system being governed).** The authorization boundary is **the agent itself** — a multi-provider, local-CLI inference agent — not a hosting platform. The governed runtime capabilities and their realized configuration are:

- Tool use: shell execution, file read/write/edit, web fetch/search, browser control, computer-use.
- The MCP client; the skills/plugins system (including `optional-skills/`); persistent memory.
- The ACP adapter and the desktop app.
- Inference routing across all configured providers and local servers (primary, fallback chain, Mixture-of-Agents reference/aggregator, auxiliary-task, and delegation paths).
- The audit ledger and encryption-at-rest posture.

**Inherited (referenced, not re-engineered).** The host operating system, network fabric, and physical facility are inherited from the underlying ATO boundary. The legal/regulatory/contractual obligations that frame scope (DFARS 252.204-7012, 800-171 r3, CMMC L2, OMB M-25-21) are maintained in the regulatory register and bound to enforced controls (**LG-GV-03**, `docs/governance/regulatory-register.yaml`, reconciled by `ci/governance-ci-gates/regulatory_reconciliation_gate.py`).

**Out of scope.** General-purpose, non-CUI use of the upstream Hermes Agent outside an authorized Lliam-GOV deployment; this policy applies once the gov overlay is selected via `HERMES_CONFIG` and a governance authorization is in force. The current authorization (`LG-ATO-2026-001`) covers a **single-operator demo/eval deployment with no CUI in scope** — the CUI posture floor is enforced fail-closed regardless.

---

## 3. Named Roles, Authorities, and RACI

**LG-GV-04** (assign named accountable roles and RACI) and **LG-GV-05** (bind roles to authenticated principals with separation of duties).

Each role below has a **single accountable owner**, named in the machine-readable `docs/governance/roles.yaml` (LG-GV-04) with the human-readable RACI in `docs/governance/roles-raci.md`. Bindings to authenticated principals live in `governance.role_bindings` in `cli-config.gov.yaml` and are enforced by the SoD gate (`ci/governance-ci-gates/sod_check.py`) at CI and startup: non-waivable separations (Approver ≠ Engineer; Auditor independent of all reviewed parties) can never be co-held; waivable separations may be co-held only via a tracked, owner-signed, expiring `sod_deviations` entry.

| Role | Authority and duties | OMB M-25-21 / ISO 42001 alignment |
|---|---|---|
| **Chief AI Officer (CAIO)** | Owns this policy and the AIMS. Approves intended-use and prohibited-use scope (LG-GV-02). Sole signer of high-impact-AI determinations (LG-RM-06) and of all waivers/determinations for non-baseline high-risk enablement (LG-GV-10). Convenes and chairs management review (LG-GV-08). Owns OMB/public reporting. | M-25-21 CAIO duties; ISO 42001 Cl. 5.1/5.2, A.2.2 |
| **Authorizing Official (Approver)** | Issues the go/no-go deployment authorization and signs the risk-acceptance record (LG-GV-06, `docs/governance/authorization-record.yaml`). Authenticated approver-of-record for high-impact runtime actions (LG-GV-05). | M-25-21 risk acceptance; ISO 42001 A.3.2 |
| **ISSO** | Owns the technical security posture and the gov config overlay. Maintains the SoA (LG-RM-04) and POA&M (LG-RM-07, issued at P4.2) and the authorization record (LG-GV-06). Runs continuous-authorization telemetry (LG-GV-07) and prepares the management-review input pack (LG-GV-08). | ISO 42001 A.3.2/A.3.3; CSF GV.RR |
| **AI Risk Owner** | Owns the risk-assessment method and registers (LG-RM-01, LG-RM-02), the capability×impact tiering matrix (LG-RM-03, `policy/tool-risk-policy.yaml`), and impact assessments (LG-RM-05). Recommends dispositions; the CAIO/Approver accept residual risk. | ISO 42001 6.1.x, A.3.2 |
| **Auditor** | Independent reviewer of impact assessments (LG-RM-05) and high-impact determinations (LG-RM-06); reconciles register-to-control bindings and SoA-to-running-config; verifies audit-ledger integrity. Independence is enforced by separation of duties (LG-GV-05). | ISO 42001 9.2; CSF GV.RR |
| **Kill-Switch Owner** | Named owner of the documented fail-safe; authorized to trip containment via `tools/interrupt.py` and execute the halt/rollback runbook (LG-RM-09, issued at P5.3). Named in `roles.yaml` and in incident POCs. | M-25-21 fail-safe; AI RMF GOVERN 1.7 |
| **Operator** | Runs authorized missions within scope; responds to HITL approval prompts within their granted role; may not self-approve high-risk actions (SoD). | ISO 42001 A.3.3 |

In the current eval deployment the acting **Engineer** is the Lliam-GOV NPE agent instance itself (`npe:lliam-gov`, LG-IA-02) — distinct from the human Approver, so Approver ≠ Engineer holds by construction. Co-held human roles are covered by the tracked deviations in `docs/governance/roles.yaml` (`sod_deviations`).

**Authenticated binding (LG-GV-05).** `agent/governance_audit.py` records the authenticated approver principal into each approval decision emitted through the approval seams (`tools/approval.py` / `tools/write_approval.py` / `acp_adapter/edit_approval.py`), and `security.require_authenticated_approver: true` makes an anonymous/non-interactive high-risk approval fail closed (couples to `security.deny_on_no_approver`). *Additive — no existing approval/auth identifier is renamed.*

---

## 4. Intended Use and Prohibited Use

**LG-GV-02** (document authorized mission scope, intended use, and prohibited uses) and **LG-GV-09** (GenAI acceptable-use realized as enforced allowlists).

### 4.1 Intended use (in-scope mission)

Lliam-GOV is authorized to perform agentic work — file, web, code, and MCP-mediated tasks, and inference across the approved in-boundary provider set — within the documented mission scope recorded in `docs/governance/intended-use.md`. The full core agent capability surface (file, web, code, MCP, providers) is **preserved**; only the prohibited and high-risk surfaces are constrained per the graduated model in §6.

### 4.2 Prohibited and unacceptable use

The following are prohibited and enforced by configuration, not merely by exhortation:

- **Jailbreak / safety-bypass.** The `godmode` skill (which overwrites `agent.system_prompt` and `prefill.json` to bypass model safety) and the `obliteratus` weight-abliteration skill are **mandatory must-disable** and are **never waivable** (`never_waivable` in `docs/governance/waiver-register.yaml`). `web-pentest`, `sherlock`, and `oss-forensics` are denied by default; each may be enabled only via a tracked CAIO waiver (LG-GV-10) with documented mission need.
- **Out-of-mission action.** Actions outside the documented intended-use scope.
- **Off-allowlist CUI egress.** Routing CUI to any provider/tool/skill not on the approved allowlist (LG-GV-09).
- **Unauthorized high-risk enablement.** Enabling any capability flagged high-risk without a valid CAIO waiver (LG-GV-10).

**Realization (additive).** `docs/governance/intended-use.md` is the source of truth for in/out scope and prohibited uses. Enforcement is via `skills.disabled` + `skills.deny_tags` + `skills.guard_agent_created: true` in `cli-config.gov.yaml`, the skills policy of record `policy/skills-allowlist.yaml` with the `tools/tool_policy.py` gate (refused at discovery, slash-command registration, and prompting), the provider allowlist `policy/provider-allowlist.yaml` enforced on all five routing paths (primary/fallback/MoA-reference/MoA-aggregator/auxiliary-delegation), and toolset pruning via `agent.disabled_toolsets` + `security.tool_denylist`. The startup waiver gate (`enforce_governance_artifacts_at_startup`) and the CI prohibited-skills gate (`ci/governance-ci-gates/prohibited_skills_gate.sh`) fail closed if a prohibited skill is enabled without a valid waiver. *No skill, tool, or provider path is renamed (PATH-FREEZE).*

---

## 5. Risk Tiering and High-Impact Determination

**LG-RM-01/02** (risk-assessment process and living agent-threat register), **LG-RM-03** (capability×impact tiering), **LG-RM-04** (Statement of Applicability), **LG-RM-05** (impact assessment with independent review), **LG-RM-06** (high-impact determination per M-25-21).

### 5.1 Risk method and registers

A repeatable AI/GenAI risk-assessment process (`docs/governance/risk-assessment-process.md`, issued at P4.2) produces comparable, prioritized results in `docs/governance/threat-risk-register.yaml` (P4.2), seeded from the live enabled-capability inventory. The register carries the six mandatory agent-threat classes — prompt injection, excessive agency, tool/MCP abuse, memory poisoning, provider exfiltration, and supply chain (LG-RM-02) — each with an owner, residual rating, and control linkage. Detection signals that already run (`agent/message_sanitization.py`, `tools/threat_patterns.py`, `tools/tirith_security.py`, `lliam_cli/mcp_security.py`, `agent/secret_scope.py`, `agent/redact.py`, `tools/skill_provenance.py`, `tools/skills_ast_audit.py`, `lliam_cli/security_advisories.py`) are referenced as evidence sources.

### 5.2 Capability × impact tiering

Every tool, provider, skill, and MCP server is assigned a `{capability_tier, impact_tier, disposition}` quadrant in **`policy/tool-risk-policy.yaml`** (LG-RM-03) — the single tiering matrix that the P2.1 policy-decision point (`tools/tool_policy.py`) consults at startup and at dispatch via the tool-guardrails chokepoint. Default tiers preserve low-risk reads as **allow**; only High/High items lose standing availability. `godmode` is hard-mapped **High/High ⇒ deny**. Inclusion/exclusion of every control is justified in the Statement of Applicability (`docs/governance/SoA.md`, issued at P4.2), with the godmode/offensive-skill exclusion recorded and CI-asserted.

### 5.3 High-impact determination (M-25-21)

Because Lliam-GOV can route inference off-boundary, execute shell/file/browser/computer-use tools, and (by default upstream packaging) ships an offensive jailbreak skill, several built-in use cases fall inside OMB M-25-21's **high-impact AI** presumption. Each tool/skill/workflow combination is determined and documented with a signature block in the P4.2 high-impact determination record: `{high_impact, determination_rationale, signed_acceptance_ref, independent_reviewer}`. Where a presumed-high-impact category is determined **not** high-impact, the CAIO is notified and the rationale recorded. A high-impact use case is refused enablement unless a signed risk-acceptance record is present (LG-GV-06 / LG-GV-10 startup gates), with the signer identity captured in the audit ledger.

---

## 6. Human Oversight and Graduated Enforcement

**LG-RM-08** (graduated, risk-based enforcement dispositions) with **LG-GV-05** (authenticated approver) and **LG-RM-05** (HITL action list); OMB M-25-21 human-oversight-with-fail-safe.

Human oversight is **mandatory on high-impact actions** and is realized through graduated, capability-preserving enforcement — never a blanket deny where a tiered control keeps the agent useful. The four dispositions in `policy/tool-risk-policy.yaml` are consumed by `tools/tool_policy.py` and enforced at the tool-dispatch chokepoint:

| Disposition | Applies to | Mechanism |
|---|---|---|
| **Allow** | Low-risk idempotent reads | Pass through unchanged |
| **Detect-and-log** | Medium-risk actions | Emit to the governance audit ledger (`agent/governance_audit.py`) |
| **Approval-gate (HITL)** | High-risk / irreversible / egress / spend / secret-access / computer-use | Route to the approval seams (`tools/approval.py` / `tools/write_approval.py` / `acp_adapter/edit_approval.py`); requires an **authenticated, role-appropriate** approver (LG-GV-05) |
| **Deny** | Excluded capabilities (e.g. godmode) | Refused at discovery/registration/dispatch |

A single `security.posture: strict` overlay in `cli-config.gov.yaml` coherently flips the documented fail-open guards to fail-closed (`tirith_fail_open=false`, website-policy allowlist mode, approvals `deny_on_no_approver`/`require_authenticated_approver`) so that, in the high-side posture, a missing approver context denies rather than auto-approves. *Capability impact is low by design: only high-impact/irreversible actions are gated and only excluded capabilities are denied; low- and medium-risk actions remain allow or detect-and-log.* No existing identifier is renamed.

---

## 7. Deviation / Exception Path (Named-Approver Sign-Off)

**LG-GV-01** (deviation/exception path) and **LG-GV-10** (CAIO-controlled waiver/determination register).

No deviation from this policy or the baseline is permitted by silent configuration change. Any non-baseline high-risk enablement — enabling an off-allowlist provider, computer-use in a CUI profile, a baseline-denied skill, or any other High/High capability — is permitted **only** if a matching, valid, unexpired waiver exists. `godmode` and `obliteratus` are never waivable.

**Process.**
1. The requestor documents the requested capability, justification, mission need, time-box, and compensating controls.
2. The AI Risk Owner assesses residual risk; the **CAIO is the sole signer** of the waiver.
3. The waiver is recorded in `docs/governance/waiver-register.yaml`: `{waiver_id, capability, justification, compensating_controls, signed_by (CAIO), granted/expires dates, omb_report_date}`. Lower-impact deviations not rising to a waiver are recorded in `docs/governance/deviation-register.yaml` (the LG-CH-08 register established at P0.7).
4. **Enforcement (fail-closed).** `enforce_governance_artifacts_at_startup` blocks any baseline-denied enablement unless a matching valid `waiver_id` exists and is unexpired; a placeholder or unsigned entry does not count. Annual recertification per the register header.

This path **preserves capability** by providing a tracked, justified, time-boxed route to high-risk function rather than a permanent denial. *Additive — no renames.*

---

## 8. Management Review and Continual Improvement

**LG-GV-07** (continuous authorization / cATO) and **LG-GV-08** (periodic management review and re-authorization); ISO 42001 Clause 9.3 / 10.2.

**Continuous authorization (LG-GV-07).** The audit emitter (`agent/governance_audit.py`) exports ISCM events to the sink configured at `monitoring.iscm_sink` (issued at P5.1). A periodic control-effectiveness check (P5.2) re-asserts the posture invariants — godmode-disabled, allowlist-enforced, encryption-on, audit-chain-intact — and emits a posture event. On a critical posture-break, containment is tripped via `tools/interrupt.py` and re-authorization is required (linking LG-GV-06 / LG-RM-09; P5.4).

**Management review (LG-GV-08).** At a fixed cadence, the CAIO chairs a management review using an input pack compiled from LG-GV-07 telemetry, `lliam_cli/security_audit.py` outputs, `lliam_cli/security_advisories.py`, and the internal-audit report. The review records control effectiveness, open POA&M items (LG-RM-07), incidents, and a **signed residual-risk acceptance** with an explicit **re-authorization decision** that updates `docs/governance/authorization-record.yaml` (LG-GV-06) and the SoA. The authorization record carries a hard expiry (`expires`) that the startup gate enforces — an overdue re-authorization fails closed under strict posture. Corrective actions feed the continual-improvement loop (ISO 42001 10.2).

---

## 9. Enforcement and Link to the Gov Config Overlay

**LG-GV-06** (go/no-go authorization gate) is the binding enforcement point for this policy. Before serving work under strict posture, `lliam_cli/security_audit_startup.py` (`enforce_governance_artifacts_at_startup`, wired on the gateway startup path alongside the control-plane, provider-allowlist, model-integrity, and audit-chain gates) verifies that: the policy identity (`governance.policy_id` / `policy_version` / `policy_approved_by`) is present and non-placeholder and `policy_review_date` is not past due; this policy file exists; `governance.authorization_id` matches a signed, unexpired, decision=authorized `docs/governance/authorization-record.yaml`; the regulatory register exists and carries obligations; and the waiver register exists with no unwaivered high-risk enablement. The CI reconciliation gate (`regulatory_reconciliation_gate.py`) additionally proves every regulatory obligation resolves to a real enforced config point.

**This policy is not advisory text — it is bound to running configuration.** Its identity lives in the `governance:` block of `cli-config.gov.yaml`, selected via the existing `HERMES_CONFIG` env var. The startup gate refuses to serve work under strict posture if the policy is absent, placeholder-valued, or past its review date. Every subordinate artifact named in this policy — roles/RACI (LG-GV-04, in force), regulatory register (LG-GV-03, in force), authorization record (LG-GV-06, in force), waiver register (LG-GV-10, in force), deviation register (LG-CH-08, in force), SoA/POA&M/risk registers (LG-RM-*, issued at P4.2), SSP (P4.3), and halt/rollback runbook (LG-RM-09, P5.3) — is referenced from this document and reconciled against running configuration at boot and in CI.

**Path-freeze attestation.** Every enforcement point above is realized by setting an existing env var / YAML key / CLI flag / policy file, or by adding a **new** additive file or module. No existing upstream or Lliam module, file, CLI command, tool name, or identifier is renamed, moved, or refactored by this policy or its overlay.

---

## 10. Control Coverage Map

| Policy section | LG-GV-* / LG-RM-* controls |
|---|---|
| §1 Policy statement & responsible-use principles | LG-GV-01 |
| §2 Scope (agent + AIMS) | LG-GV-02, LG-GV-03 |
| §3 Roles, authorities, RACI | LG-GV-04, LG-GV-05 |
| §4 Intended / prohibited use | LG-GV-02, LG-GV-09 |
| §5 Risk tiering & high-impact determination | LG-RM-01, LG-RM-02, LG-RM-03, LG-RM-04, LG-RM-05, LG-RM-06 |
| §6 Human oversight & graduated enforcement | LG-RM-05, LG-RM-08, LG-GV-05 |
| §7 Deviation / exception path | LG-GV-01, LG-GV-10 |
| §8 Management review & continual improvement | LG-GV-07, LG-GV-08, LG-RM-07 |
| §9 Enforcement & gov config overlay | LG-GV-06, LG-GV-01 |
| Fail-safe (referenced throughout) | LG-RM-09 |

---

## 11. Approval and Version Control

Signatures are recorded against the authenticated principals bound in `governance.role_bindings` (`cli-config.gov.yaml`) and enforced by the SoD gate. Co-held roles in the eval deployment are covered by the tracked deviations in `docs/governance/roles.yaml`.

| Role | Principal (role_bindings) | Approval | Date |
|---|---|---|---|
| Chief AI Officer (CAIO) — policy owner | jdavis@agency.mil | Approved | 2026-07-16 |
| Authorizing Official (Approver) | jdavis@agency.mil | Approved | 2026-07-16 |
| ISSO | jdavis@agency.mil | Approved | 2026-07-16 |

| Version | Date | Author | Change |
|---|---|---|---|
| 0.1 DRAFT | 2026-06-28 | Lliam-GOV Program | Initial top-management AI governance policy (governance package). |
| 1.0 | 2026-07-16 | Lliam-GOV Program | Adopted into the repo as the policy of record (P4.1 / AI-493); realizations reconciled to the enforced P0–P3 config points; signature block executed. |

> **Review cadence.** This policy is reviewed at each management review (LG-GV-08) and at minimum annually; `governance.policy_review_date` in `cli-config.gov.yaml` is updated on each re-approval and is enforced by the startup gate.

---

*Built on Hermes Agent (Nous Research, MIT). Governance overlay is additive and capability-preserving.*
