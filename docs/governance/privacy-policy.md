# PII Processing & Privacy Policy — Lliam-GOV

| Field | Value |
|---|---|
| Document | PII Processing & Privacy Policy (LG-PF-01/02/03/05) |
| Owner | AI Risk Owner (`governance.role_bindings.ai_risk_owner`); CAIO approves |
| Classification | CUI//SP-PRIV (template — mark per instance) |
| Version | 1.0 |
| Date | 2026-07-16 |
| Review-by | 2027-07-16 and at each management review (LG-GV-08) |

> **Purpose.** The PII processing policy of record for the Lliam-GOV agent: what PII may be processed, on what authority, where it may route, how it is minimized, retained, and disposed of, and which actions require human approval. Companion notices: `docs/governance/ai-disclosure-notice.md` (LG-PF-04). Enforcement points are the real config keys cited per section.

## 1. Authorized PII processing (LG-PF-01)

- **Authorized PII.** PII incidental to the authorized mission scope (`docs/governance/intended-use.md`) — e.g., names/contacts inside documents under analysis. **Special-category PII** (SSN, financial/health identifiers, biometrics) is not an authorized processing target; when encountered it is redacted by the CUI/PII pattern pack before provider egress.
- **Authorized providers/regions.** PII may reach only allowlisted in-boundary providers (`policy/provider-allowlist.yaml`, LG-MP-01/03 — residency + no-train vetting preconditions); local inference preferred for high sensitivity (`security.local_provider_preference`).
- **Minimization.** PII is redacted from provider context by default (`privacy.redact_pii: true`; `security.data_protection.cui_redaction: true` for the extended pattern pack) — the agent processes the minimum PII the task needs, and reasoning traces are scrubbed before egress (`agent/think_scrubber.py`, LG-DP-09).
- **Retention & disposal.** PII is excluded from persistent memory (`memory.governance.exclude_pii: true`, LG-MC-05); tool-result spill expires on TTL (`security.data_protection.result_retention_ttl_seconds`, LG-DP-11) with secure purge (LG-MC-06).

## 2. Lawful basis and purpose limitation (LG-PF-02)

PII processing is bound to the documented authority of the active, authorized mission (the go/no-go authorization `LG-ATO-2026-001` + `docs/governance/intended-use.md`); the lawful basis for any production deployment is the sponsoring organization's authority to operate the mission the data belongs to. Purpose limitation is enforced structurally: memory is partitioned per session/identity with context reset between unrelated tasks (`memory.governance.partition_per_session` / `reset_context_between_tasks`, LG-MC-02/07), so PII ingested for one task is not reusable across sessions. Cross-source PII aggregation or re-identification is not an authorized purpose (gated, §4).

## 3. Redaction in provider context (LG-PF-03)

`privacy.redact_pii: true` (flipped from the permissive shipped default at P0.2) masks PII before provider egress; the extended CUI/PII pattern pack (`security.data_protection.cui_redaction`, LG-DP-04, `agent/data_protection.py`) adds SSN/DOB/CUI-line/biometric patterns; secret redaction is always-on (`security.redact_secrets`, LG-DP-03). Redaction-on-write in the audit ledger is unconditional (LG-AU-05).

## 4. Consent-requiring and rights-affecting actions (LG-PF-05)

The following route to an authenticated human approver (the HITL gate, LG-HO-01) and are never autonomous:

- Any action that would **aggregate PII across sources** or attempt re-identification.
- Any **rights-affecting** output concerning an individual (eligibility, adverse characterization, employment-relevant conclusions) — additionally out of the authorized eval scope entirely (no person-affecting use cases; see `docs/governance/bias-risk-register.yaml` header and the LG-RM-06 determinations).
- **Disclosure of PII to any external sink** — the egress allowlist (LG-NE-01) plus the DLP taint gate (`security.data_protection.dlp_taint_gate`, LG-DP-10) escalate egress from a PII/CUI-exposed session to HITL.

Individuals affected by an AI-driven decision have the appeal/human-handoff channel (LG-HO-09; surfaced in the disclosure notice).

## 5. Enforcement summary

| Commitment | Config point | Control |
|---|---|---|
| PII redaction to providers | `privacy.redact_pii` | LG-PF-03 |
| Extended CUI/PII pattern pack | `security.data_protection.cui_redaction` | LG-DP-04 |
| No PII in persistent memory | `memory.governance` (`exclude_pii`) | LG-MC-05 |
| Purpose limitation across sessions | `memory.governance` (`partition_per_session`) | LG-MC-02 |
| PII spill TTL + secure purge | `security.data_protection.result_retention_ttl_seconds` | LG-DP-11 |
| Rights-affecting actions gated | `security.deny_on_no_approver` + PDP HITL tiers | LG-PF-05 / LG-HO-01 |
| Residency-safe routing | `policy/provider-allowlist.yaml` | LG-MP-01/03 |
| Disclosure + recourse | `docs/governance/ai-disclosure-notice.md` | LG-PF-04 / LG-HO-09 |

---

*Built on Hermes Agent (Nous Research, MIT). Governance overlay is additive and capability-preserving.*
