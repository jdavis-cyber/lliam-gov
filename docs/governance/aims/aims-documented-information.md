# Lliam-GOV — AIMS Documented Information (ISO/IEC 42001:2023)

**Status:** documented-information set for the Lliam-GOV governance overlay, authored
on the clean Hermes v2026.6.5 rebuild (2026-06-16). This document is the overlay's
contribution to the **Katmai ISO/IEC 42001 AI Management System (AIMS)**. Management-
system clauses that are organization-level (scope, leadership commitment, internal
audit, management review, continual-improvement cadence) remain owned by the Katmai
AIMS program; this document supplies the AI-system-specific documented information and
cross-references the controls realized in code.

This file satisfies the documented-information requirement of **Clause 7.5** and indexes
the Annex A documented information below.

---

## A.6.1.2 — Objectives for responsible development of AI systems

Lliam-GOV is a governance overlay over the Hermes agent. Its responsible-AI objectives:

1. **Attributable operation.** Every governed action is bound to an OS-level principal;
   root execution is refused under the production profile. *(principal binding — SP
   800-171 3.1.1/3.1.2; ISO 27001 A.8.5.)*
2. **Tamper-evident accountability.** All tool dispatch, session lifecycle, and gateway
   authorization events are written to an append-only, hash-chained audit log that fails
   closed. *(SP 800-171 3.3.x.)*
3. **Bounded autonomy.** Self-modifying actions (skill creation, memory writes) are
   staged for human approval, never auto-applied, under the self-modification gate.
   *(A.6.2.4.)*
4. **Least authority.** Tool dispatch is capability-gated; egress is allowlisted and
   TLS-enforced fail-closed; the dashboard/desktop backend is loopback-only.
5. **Data protection.** CUI is marked and its access audited; persisted credentials,
   state, and backups are encrypted at rest with key rotation.

Objectives are measurable via the control matrix (`evidence/control-matrix.csv`) and the
adversarial harnesses (`evidence/phase5/{chaos,pentest}`).

## A.3.2 — Roles, responsibilities, and authorities (RACI)

| Activity | Responsible | Accountable | Consulted | Informed |
|---|---|---|---|---|
| AIMS program / scope | Katmai AIMS PM | Katmai leadership | Overlay maintainer | Operators |
| Governance overlay design + code | Overlay maintainer (Jerome Davis) | Katmai AIMS PM | Security reviewer | Operators |
| Control matrix + evidence | Overlay maintainer | Katmai AIMS PM | Auditor | Katmai leadership |
| Privileged operations (audit verify, key rotation, self-mod approval) | Designated operator (home-owner ACL) | Overlay maintainer | — | Auditor |
| Incident response / fail-closed events | On-call operator | Overlay maintainer | Katmai AIMS PM | Leadership |

Privileged-operation authority is enforced technically by the home-ownership ACL
(`lliam_gov/security/privileged_access.py`, SP 800-171 3.3.9).

## A.5.2 — AI system impact assessment

- **System:** Hermes coding/agent assistant operated under the Lliam-GOV overlay, single-
  tenant, loopback-only UI, operated by a designated operator on a controlled host.
- **Affected parties:** the operating organization and the operator; no end-user PII
  pipeline. CUI may be processed and is marked + access-audited.
- **Principal risks & mitigations:**
  - *Unattributable / privileged action* → principal binding + production-root refusal.
  - *Undetected misuse* → append-only hash-chained audit (fail-closed).
  - *Unbounded self-modification* → human-approval gate (stage, never apply).
  - *Data exfiltration* → egress allowlist + TLS enforcement; loopback-only backend.
  - *CUI exposure at rest* → encryption of state, credentials, and backups; key rotation.
- **Residual risk:** inherited upstream dependency CVEs (see
  `evidence/sbom/dependency-review-2026-06-16.md`, tracked) and FIPS-validated crypto,
  which completes on a FIPS-OpenSSL host (SP 800-171 3.13.11). Disposition: operator/Katmai.

## A.7.4 — Quality of data for AI systems / A.4.3 — Data resources

Lliam-GOV does not train or fine-tune models; it governs an agent that consumes the
operator's prompts, repository files, and configured tool outputs at inference time.
- **Data resources:** operator inputs, workspace files, credential/auth state, audit log,
  CUI-marked paths. All persisted sensitive resources are encrypted at rest with a
  keyring-anchored key (`lliam_gov/security/key_manager.py`).
- **Integrity:** the audit log is hash-chained and tamper-evident; tool error text is
  sanitized before re-entering model context.
- **Provenance:** the agent base is pinned to upstream Hermes v2026.6.5 (`3c231eb`); the
  SBOM (`evidence/sbom/cyclonedx-2026-06-16.json`) records the dependency closure.

---

## Clause 7.5 — Documented information index

| AIMS area | Documented information | Location |
|---|---|---|
| AI-system objectives | this document, §A.6.1.2 | `docs/governance/aims/aims-documented-information.md` |
| Roles / authorities | this document, §A.3.2 | same |
| Impact assessment | this document, §A.5.2 | same |
| Data resources / quality | this document, §A.7.4 | same |
| Control realization + state | control matrix | `evidence/control-matrix.csv`, `docs/governance/control-matrix.md` |
| Operating evidence | audit/chaos/pentest artifacts | `evidence/audit/`, `evidence/phase5/` |
| Supply chain | SBOM + dependency review | `evidence/sbom/` |
| Provider boundary threat model | design doc | `docs/governance/provider-boundary-threat-model.md` |
| Rebuild lineage | status + attribution | `docs/governance/rebuild-status.md`, `NOTICE` |

**Organization-owned (Katmai AIMS program), referenced not duplicated here:** Clause 4
(context/scope), Clause 5 (leadership), Clause 6 (planning), Clause 8 (operational
control of the live AIMS), Clause 9 (monitoring, internal audit, management review),
Clause 10 (continual improvement). These are management-system activities whose operating
evidence accrues over the AIMS operating cycle.
