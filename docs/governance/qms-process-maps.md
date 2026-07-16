# QMS Process Maps & Quality Objectives — Lliam-GOV

| Field | Value |
|---|---|
| Document | AI Lifecycle QMS: process maps, quality objectives, nonconforming-output control (LG-QT-01/02/04/05/06/08/09) |
| Owner | ISSO (process); CAIO (management review) |
| Classification | CUI//SP-PRIV (template — mark per instance) |
| Version | 1.0 |
| Date | 2026-07-16 |
| Review-by | At each management review (LG-GV-08) |

> **Purpose.** The quality-management layer over the governed agent: each capability treated as a defined process with control points and a measured indicator (LG-QT-01), measurable quality objectives (LG-QT-02), nonconforming-output control (LG-QT-04), grounding and code-validation disciplines (LG-QT-05/06), provenance stamping (LG-QT-07), the internal-audit / management-review / continual-improvement cycle (LG-QT-08), and configuration management of the governance work products themselves (LG-QT-09). Traceability of every output to model/provider/prompt/approver (LG-QT-03) has been enforced since P1.2 via the audit chokepoint correlation ids.

## 1. Capability process maps (LG-QT-01)

Each capability is a defined process: **inputs → control points → outputs → measured indicator.** Control points are the real enforcement seams; indicators are computed from the audit ledger (`agent/governance_audit.py`).

| Process | Control points (in order) | Measured indicator |
|---|---|---|
| **File read/write/edit** | PDP class resolution (`tools/tool_policy.py`) → safe-root/denylist check (`agent/file_safety.py`) → path-traversal validation (`tools/path_security.py`) → ledger record | Out-of-root write denials per session; write-approval turnaround |
| **Shell / code execution** | PDP privileged-tier gate → sandbox (`terminal.backend: docker`) → dangerous/hardline pattern gate (`tools/approval.py`) → ledger record | Destructive-command HITL rate; sandbox escape findings (target 0) |
| **Web fetch / search (egress)** | Egress allowlist (`tools/egress_policy.py`) → SSRF/metadata floor (`tools/url_safety.py`) → website policy → taint gate → ledger record | First-seen-domain denials; egress-block false-positive rate |
| **Provider inference call** | Provider allowlist on all 5 routing paths (`lliam_cli/provider_allowlist.py`) → TLS verify → PII/CUI redaction (`agent/data_protection.py`) → ledger record | Non-allowlisted route attempts (target 0 silent); redaction recall |
| **MCP tool call** | MCP allowlist + scope check (`lliam_cli/mcp_security.py`) → schema validation (`tools/schema_sanitizer.py`) → PDP → ledger record | Schema-drift rejections; unvetted-server denials |
| **Memory write** | Poisoning scan (`security.memory_poisoning_defense`) → staged write-approval (`tools/write_approval.py`) → partition/TTL (`memory.governance`) → ledger record | Poisoned-write blocks; approval backlog age |
| **Skill load** | Allowlist + signature/AST audit (`tools/skill_provenance.py`, `tools/skills_ast_audit.py`) → prohibited-set denial → ledger record | Unsigned/prohibited load attempts (target 0 loads) |

## 2. Quality objectives (LG-QT-02)

Objectives are measurable from ledger + gate outputs; reviewed at management review; failing an objective opens a corrective action (§5).

| Objective | Metric | Target | Source |
|---|---|---|---|
| Capability preservation | **False-block rate** (legitimate in-scope actions denied) | < 2% of gated actions; zero on the capability-preservation corpus | Capability corpus runs (`tests/governance/test_p2_capability_corpus.py`, `test_p3_capability_corpus.py`) + override ledger events |
| Data protection | **Redaction recall** (secrets/PII masked before egress/persistence) | 100% on the redaction test corpus | Redaction suites + ledger sampling |
| Prohibited-capability integrity | **Jailbreak-block rate** (godmode/prohibited-skill activation attempts blocked) | 100% (build-stopping) | `ci/governance-ci-gates/prohibited_skills_gate.sh` + startup waiver gate |
| Accountability | **Audit completeness** (consequential actions with a chained record) | 100% — unrecorded action blocks (`audit.on_unrecorded`) | Chokepoint coverage tests (P1.2) + `audit.fail_closed` |
| Mission utility | **Task success** (capability-corpus tasks completing under governance) | 100% of the §6 corpus | Phase capability-preservation reports |

## 3. Nonconforming-output control (LG-QT-04)

A **nonconforming output** is: a CUI/PII-leak attempt, a guardrail bypass, a jailbreak activation, an unsafe tool call, or an output failing sink-side validation. Disposition is **block or quarantine, then record — never silent discard**:

1. **Block** at the enforcing seam (PDP deny/HITL, egress deny, redaction mask, sink validation LG-PI-09).
2. **Quarantine** staged artifacts (memory/skill writes held in the write-approval queue rather than persisted).
3. **Record** a `policy.violation` event to the hash-chained ledger with the correlation id — the nonconformity register of record.
4. **Correct**: recurring nonconformities open a corrective action at management review (§5); a critical one triggers the halt/rollback runbook (`docs/governance/halt-rollback-runbook.md`).

## 4. Grounding, code validation, and provenance (LG-QT-05/06/07)

- **Grounding (LG-QT-05).** Tool-driven decisions must trace to their inputs: outputs carry the correlation id chain to the tool results that grounded them (LG-QT-03 seam); consequential claims without a groundable source are flagged for operator review at the approval prompt (JIT rationale, LG-HO-08). Guardrail fitness is re-reviewed when the agent operates in a novel context (management-review input).
- **Agent-generated code (LG-QT-06).** Generated code never drives downstream execution directly: it executes only in the sandboxed backend (`terminal.backend: docker`), through the PDP privileged tier for `code_execution`, with destructive patterns HITL-gated — validation is enforced in the backend, not the prompt.
- **Provenance / synthetic-content disclosure (LG-QT-07).** AI-generated artifacts carry the disclosure of record (`docs/governance/ai-disclosure-notice.md`); governance artifacts stamp their generating step (the `[additive @ P#.#]` convention and per-step verification reports), and every artifact traces to its session via ledger correlation ids.

## 5. Internal audit, management review, continual improvement (LG-QT-08)

- **Internal audit.** The independent auditor role (SoD-enforced, LG-GV-05) reviews: ledger integrity (`verify_chain()`), register-to-control reconciliation (the CI gate battery), and a sample of approval decisions. Cadence: each phase gate during hardening; quarterly thereafter.
- **Management review (LG-GV-08).** The CAIO chairs on cadence with the input pack: quality-objective metrics (§2), nonconformity register (§3), POA&M status, incidents, advisories. Output: signed residual-risk acceptance + re-authorization decision updating `docs/governance/authorization-record.yaml`.
- **Continual improvement.** Corrective actions from audits/reviews/nonconformities feed the change record (`docs/governance/change-record.md`) and, where they change controls, the SoA/catalog (ISO 42001 10.2).

## 6. Configuration management of governance work products (LG-QT-09)

Every governance work product is version-controlled in this repo and guarded by real CM gates:

- **Baselines:** signed phase tags (`gov-P<N>-good`); the approved baseline pin in `docs/governance/authorization-record.yaml`.
- **Configuration audits (automated):** `ci/governance-ci-gates/baseline_drift_gate.py` (overlay vs critical-key baseline), `ci/governance-ci-gates/path_freeze_gate.py` (frozen paths), `ci/governance-ci-gates/soa_gate.py` (SoA ↔ catalog ↔ POA&M), `ci/governance-ci-gates/ssp_reconciliation_gate.py` (SSP ↔ repo), `ci/governance-ci-gates/regulatory_reconciliation_gate.py` (obligations ↔ enforcement), `ci/governance-ci-gates/fairness_gate.py` (fairness state ↔ evaluations).
- **Change control:** deviations via `docs/governance/deviation-register.yaml` (LG-CH-08); dependency changes via `docs/governance/change-record.md`.

---

*Built on Hermes Agent (Nous Research, MIT). Governance overlay is additive and capability-preserving.*
