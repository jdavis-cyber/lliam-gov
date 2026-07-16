# AI Risk Assessment Process — Lliam-GOV

| Field | Value |
|---|---|
| Document | AI/GenAI Risk Assessment Process (LG-RM-01) |
| Owner | Lliam-GOV Program (AI Risk Owner accountable) |
| Classification | CUI//SP-PRIV (template — mark per instance) |
| Version | 1.0 |
| Date | 2026-07-16 |
| Review-by | 2027-07-16 (and at each management review, LG-GV-08) |

> **Purpose.** The repeatable, comparable AI/GenAI risk-assessment method required by **LG-RM-01**. It produces and maintains the living threat register (`docs/governance/threat-risk-register.yaml`, LG-RM-02), feeds the capability×impact tiering the PDP enforces (`policy/tool-risk-policy.yaml`, LG-RM-03), and drives the SoA (`docs/governance/SoA.md`, LG-RM-04), the impact assessments (`docs/governance/ai-impact-assessment.md`, LG-RM-05/06), and the POA&M (`docs/governance/poam.yaml`, LG-RM-07). Method scoring is keyed to the OWASP LLM Top-10, the OWASP Agentic Security Initiative (ASI) threat taxonomy, and MAESTRO layer analysis, over the program's Agentic Threat Model (16 enumerated threats, P1–P16).

## 1. Method

1. **Enumerate the capability surface.** Seed from the live enabled-capability inventory (`lliam_cli/security_audit.py` + `lliam_cli/inventory.py`, AI-BOM per LG-IN-02): every tool, toolset, skill, MCP server, provider route, and memory surface.
2. **Map threats.** For each surface, map applicable threats from the Agentic Threat Model and the six mandatory agent-threat classes (LG-RM-02): prompt injection, excessive agency, tool/MCP abuse, memory poisoning, provider exfiltration, supply chain. Cross-reference OWASP LLM/ASI ids.
3. **Rate inherent risk.** Qualitative Likelihood × Impact (Low / Med / High / Critical), assessed against the **as-shipped fork defaults** (fail-open postures), traceable to the threat model §19 rollup.
4. **Assign treatment.** Map each risk to its mitigating LG-* controls and their **additive** config points. Every treatment is graduated per **LG-RM-08** (allow → detect-and-log → HITL approval → deny) — never blanket denial; dispositions are recorded in the PDP tiering matrix `policy/tool-risk-policy.yaml` (LG-RM-03), the single matrix the P2.1 policy-decision point (`tools/tool_policy.py`) consults at every dispatch.
5. **Rate residual risk.** Re-rate with the cited primary controls operating (verified by the per-step evidence reports under `docs/governance/verification/`).
6. **Disposition and acceptance.** The AI Risk Owner recommends; the CAIO/Authorizing Official accept residual risk (signature block in `docs/governance/ai-impact-assessment.md` §11; go/no-go in `docs/governance/authorization-record.yaml`). Unmet/partial treatments are carried in `docs/governance/poam.yaml` with owner and milestone (LG-RM-07) — enforced by `soa_gate.py`, so nothing pending is silently declared.

## 2. Scales

| Rating | Likelihood | Impact |
|---|---|---|
| Low | Requires multiple unlikely preconditions | Recoverable nuisance, no CUI/PII exposure |
| Med | Plausible under normal operation | Bounded exposure or capability misuse |
| High | Expected if the control is absent | CUI/PII exposure, host compromise, or spend |
| Critical | Demonstrated/trivially reachable as shipped | Reportable spillage, RCE, durable backdoor, loss of accountability |

Rating = the standard L×I quadrant; residual assessed after primary controls only (compensating/monitoring controls noted but not credited).

## 3. Cadence and triggers

- **Scheduled:** at each phase verify gate during hardening; at management review (LG-GV-08) thereafter; annually at minimum.
- **Triggered:** on any new tool/skill/MCP/provider entering the baseline (supplier vetting, LG-TP-03); on a security advisory hit (`lliam_cli/security_advisories.py`); on an incident (LG-IR-05); on baseline drift (LG-CH-03); on a waiver request (LG-GV-10).
- **Register maintenance:** new advisories/inventory diffs open candidate register entries; ratings and acceptance reconcile to the SoA and POA&M in CI (`soa_gate.py`, `regulatory_reconciliation_gate.py`).

## 4. Outputs and evidence

| Output | Artifact | Control |
|---|---|---|
| Living threat register | `docs/governance/threat-risk-register.yaml` | LG-RM-02 |
| Capability×impact tiering (PDP-enforced) | `policy/tool-risk-policy.yaml` | LG-RM-03 |
| Statement of Applicability | `docs/governance/SoA.md` + `control-catalog.yaml` | LG-RM-04 |
| Impact assessment + signed acceptance | `docs/governance/ai-impact-assessment.md` | LG-RM-05 |
| High-impact determinations | `docs/governance/high-impact-determinations.yaml` | LG-RM-06 |
| POA&M | `docs/governance/poam.yaml` | LG-RM-07 |
| Halt/rollback runbook | `docs/governance/halt-rollback-runbook.md` | LG-RM-09 |

---

*Built on Hermes Agent (Nous Research, MIT). Governance overlay is additive and capability-preserving.*
