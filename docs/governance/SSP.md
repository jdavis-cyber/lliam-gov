# System Security Plan (SSP) — Lliam-GOV · CUI / CMMC Level 2

| Field | Value |
|---|---|
| Document | System Security Plan (LG-IN-07) — NIST SP 800-171 r3 / CMMC L2 |
| System | Lliam-GOV — governance-hardened fork of Hermes Agent (Nous Research, MIT) |
| Owner | ISSO (`governance.role_bindings.isso`) |
| Classification | CUI//SP-PRIV (template — mark per instance) |
| Version | 1.0 |
| Date | 2026-07-16 |
| Traceability | `docs/governance/traceability-171r3.yaml` (machine-readable; CI-reconciled by `ci/governance-ci-gates/ssp_reconciliation_gate.py`) |
| Review-by | At each re-authorization and management review (LG-GV-08) |

## 1. System Identification

Lliam-GOV is a multi-provider, local-CLI autonomous inference agent (non-person entity) operated under the strict governance overlay `cli-config.gov.yaml`, selected via the existing `HERMES_CONFIG` env var. The authorization boundary is the agent itself (see `docs/governance/boundary-scope.md`); host OS, network fabric, and facility are inherited. The current authorization is `LG-ATO-2026-001` (`docs/governance/authorization-record.yaml`): single-operator demo/eval, **no CUI in scope**, with the SP 800-171 r3 / CMMC L2 posture floor enforced fail-closed regardless.

## 2. Control Scope, Methodology, Inheritance

- **Scope.** All 17 800-171 r3 families. Each family below states the requirement intent, the implementation as actually enforced at the current build (P0–P4), the implementing LG-* controls (traceable to `docs/governance/control-catalog.yaml`), the real config points, and the evidence artifact.
- **Reconciliation discipline.** Every family's config points are machine-verified against the repo by the SSP reconciliation gate; the per-step evidence reports live under `docs/governance/verification/`. Work not yet landed is carried on `docs/governance/poam.yaml` — never claimed here.
- **Inheritance.** Families 03.02 (org training), 03.07 (host O&M), 03.09 (personnel screening), and 03.10 (facility) are inherited from the hosting/sponsoring boundary; the agent-side overlap each contributes is stated in place.
- **Capability preservation.** No family is satisfied by blanket-deny: enforcement is graduated per `policy/tool-risk-policy.yaml` (LG-RM-08).

## 3. Control Implementation by 800-171 r3 Family

### 03.01 — Access Control

**Requirement intent.** Limit system access; least privilege; separation of duties; information-flow control; privileged-function control.

**Implementation.** Every tool call is mediated by the per-call policy-decision point (`tools/tool_policy.py`, active since P2.1) at the tool-dispatch seam, resolving each call against the capability×impact matrix `policy/tool-risk-policy.yaml` — allow / detect-log / HITL / deny, with privileged functions forced to HITL and deny terminal. Least functionality: `computer_use`/`browser` toolsets disabled in the baseline (`agent.disabled_toolsets` + `security.tool_denylist`); file writes confined to the safe-root allowlist plus the sensitive-path denylist (`agent/file_safety.py`); path traversal blocked fail-closed (`tools/path_security.py`). Zero-standing-privilege JIT grants and per-turn/per-session mutating-call budgets throttle autonomy (`security.max_mutating_calls`). Non-interactive high-risk approvals fail closed (`security.deny_on_no_approver`, `security.require_authenticated_approver`); separation of duties is enforced on role bindings by `ci/governance-ci-gates/sod_check.py` (LG-GV-05). Information flow: classification-driven handling + scoped secrets (`agent/secret_scope.py`) + DLP taint gating.

**Implementing controls.** LG-AZ-01..12, LG-HO-01/02, LG-GV-05, LG-IA-03, LG-DP-01/10.
**Config points.** `security.tool_denylist`, `security.deny_on_no_approver`, `security.require_authenticated_approver`, `security.max_mutating_calls`; `policy/tool-risk-policy.yaml`; `tools/tool_policy.py`.
**Evidence.** `docs/governance/verification/P2.1-report.md` (100%-mediation), `P2.2-report.md` (HITL fail-closed), `P0.4-report.md` (least privilege).

### 03.02 — Awareness and Training

**Requirement intent.** Role-based security awareness and training.

**Implementation.** **Inherited/organizational** — delivered through the sponsoring organization's training program; the training register lands with the TP domain at P4.5 (POAM-P4-SDLC). The agent contributes the named-role RACI (`docs/governance/roles.yaml`, `roles-raci.md`) and just-in-time risk rationale at approval prompts (`tools/hitl_oversight.py`, LG-HO-08) countering automation bias.

**Implementing controls.** LG-TP-01 (P4.5), LG-GV-04, LG-HO-08.
**Config points.** `docs/governance/roles.yaml`, `docs/governance/roles-raci.md`; `tools/hitl_oversight.py`.
**Evidence.** `docs/governance/verification/P1.6-report.md` (roles/SoD); training register at P4.5.

### 03.03 — Audit and Accountability

**Requirement intent.** Create, protect, retain audit records; trace actions to individuals; respond to audit failure.

**Implementation.** Append-only hash-chained ledger (`prev_hash` + sha256 JSONL) in `agent/governance_audit.py` writing to `$HERMES_HOME/logs/agent-audit.log` (LG-AU-01). The tool-dispatch path is the single audit chokepoint (`agent/governance_audit_hooks.py` wired at both dispatch executors + the direct function-call funnel, `audit.chokepoint_required`, LG-AU-02); the auditable event set and record schema are pinned in the `audit:` block (LG-AU-03/04); redaction-on-write is unconditional (LG-AU-05); UTC millisecond timestamps + monotonic sequence (LG-AU-06); the ledger lives outside the workspace on the write-denylist (LG-AU-07); chain integrity verifies at startup and in CI/cron (`ci/governance-ci-gates/audit_chain_gate.py`, `audit_chain_cron.sh`, LG-AU-08); audit-write failure blocks gated actions (`audit.fail_closed`, LG-AU-09); ACP + dashboard-auth events unify into one accountability record with the authenticated principal (LG-AU-10) and the full delegation chain (LG-IA-10).

**Implementing controls.** LG-AU-01..10, LG-IA-10.
**Config points.** `audit.ledger_enabled`, `audit.fail_closed`, `audit.chokepoint_required`; `agent/governance_audit.py`, `agent/governance_audit_hooks.py`; `ci/governance-ci-gates/audit_chain_gate.py`.
**Evidence.** `docs/governance/verification/P1.1-report.md`, `P1.2-report.md`, `P1.3-report.md`; `audit_chain_selftest.py` PASS.

### 03.04 — Configuration Management

**Requirement intent.** Baseline configurations; least functionality; change control; disable nonessential functions.

**Implementation.** The version-controlled overlay `cli-config.gov.yaml` is the documented secure baseline (LG-CH-01), pinned to signed tags; `security.posture: strict` coherently flips all fail-open guards fail-closed via `lliam_cli/posture_resolver.py` (LG-CH-02); running config validates against `docs/governance/baseline-critical-keys.yaml` with fail-closed critical drift (`ci/governance-ci-gates/baseline_drift_gate.py`, LG-CH-03). Least functionality: offensive skills denied (`skills.disabled` + `deny_tags`, LG-CH-04) with the CI build-stop (`ci/governance-ci-gates/prohibited_skills_gate.sh`, LG-CH-06); sandboxed execution backend (LG-CH-05); permissive defaults flipped strict (write approvals, PII redaction, no lazy installs — LG-CH-07). Deviations require the tracked register (`docs/governance/deviation-register.yaml`, LG-CH-08); critical posture findings block under strict (`security.posture_findings_blocking`, LG-CH-09). Machine-readable AI-BOM/SBOM inventory reconciles per build (`ci/governance-ci-gates/generate_bom.py`, LG-IN-02/03); the path-freeze manifest guards frozen paths (`ci/governance-ci-gates/path-freeze-manifest.yaml`).

**Implementing controls.** LG-CH-01..09, LG-IN-02/04.
**Config points.** `security.posture`, `security.posture_findings_blocking`, `skills.disabled`; `lliam_cli/posture_resolver.py`; `ci/governance-ci-gates/baseline_drift_gate.py`; `docs/governance/deviation-register.yaml`.
**Evidence.** `docs/governance/verification/P0.1-report.md` .. `P0.7-report.md`, `P3.4-report.md` (BOM).

### 03.05 — Identification and Authentication

**Requirement intent.** Identify/authenticate users, processes, devices; manage authenticators; MFA.

**Implementation.** Profiles and provider credentials are managed accounts reconciled at startup against `security.accounts` (LG-IA-01); each runtime instance carries a distinct NPE identity bound to config+skills+model hash (`agent/agent_identity.py` + `docs/governance/agent_identity.yaml`, LG-IA-02) injected into every audit record; per-profile fail-closed credential isolation via `agent/secret_scope.py` contextvar scoping (LG-IA-03); secrets resolve from managed sources (`agent/secret_sources/bitwarden.py`, `lliam_cli/secret_prompt.py`, LG-IA-04); authenticator lifecycle with no-default-credentials enforced at startup (`security.no_default_credentials`, LG-IA-05). Operators authenticate on dashboard/ACP (`security.require_operator_auth`, LG-IA-06) with MFA-capable auth asserted for network binds (`security.require_mfa`, LG-IA-07); provider/MCP endpoints authenticate over verified TLS (`security.require_tls` + `agent/ssl_guard.py`, LG-IA-08); device enrollment gates computer-use (LG-IA-09); a network-accessible API server without `API_SERVER_KEY` refuses to start (`security.api_server_key_required`, LG-IA-11, enforced by `enforce_control_plane_auth_at_startup`).

**Implementing controls.** LG-IA-01..11.
**Config points.** `security.accounts`, `security.no_default_credentials`, `security.api_server_key_required`, `security.require_operator_auth`, `security.require_tls`; `agent/agent_identity.py`, `agent/secret_scope.py`.
**Evidence.** `docs/governance/verification/P1.4-report.md`, `P1.5-report.md`.

### 03.06 — Incident Response

**Requirement intent.** Operational incident-handling; track/report incidents; test IR capability.

**Implementation.** Anchored by the interrupt/halt primitive (`tools/interrupt.py`) and the documented halt/rollback procedure (`docs/governance/halt-rollback-runbook.md`, LG-RM-09): halt → preserve forensics from the hash-chained ledger → contain (credential rotation, tool-class disable) → restore the signed-tag baseline → fail-closed re-validation before autonomy resumes. Runaway loops are bounded now (`tool_loop_guardrails.hard_stop_enabled`, LG-AZ-12); the kill-switch owner is named (LG-GV-04). **The executed kill-switch test, circuit-breaker automation, IR runbook severity triage, and the DIBNet 72-hour reporting procedure land at P5.3 (AI-501) — carried as POAM-P5-IR**, with the tamper-evident evidence trail (LG-AU-01/08) already operating as the interim detection/reconstruction basis.

**Implementing controls.** LG-IR-01..09 (P5.3), LG-RM-09 (partial), LG-AZ-12, LG-GV-04.
**Config points.** `tool_loop_guardrails.hard_stop_enabled`; `tools/interrupt.py`; `docs/governance/halt-rollback-runbook.md`.
**Evidence.** `docs/governance/verification/P4.2-report.md` (runbook); halt-test evidence at P5.3.

### 03.07 — Maintenance

**Requirement intent.** Perform/control maintenance; control maintenance tools and personnel.

**Implementation.** **Inherited** — host OS patching, hardware service, and off-site sanitization are the hosting platform's O&M. The agent-side overlap is software-maintenance discipline: hash-pinned installs (`security.require_hashed_install`), no runtime lazy installs (`security.allow_lazy_installs: false`), dependency changes through the change record (`docs/governance/change-record.md`) and supply-chain CI gates (family 03.17).

**Implementing controls (overlap).** LG-SS-01/02/07, LG-CH-08.
**Config points.** `security.require_hashed_install`, `security.allow_lazy_installs`; `docs/governance/change-record.md`.
**Evidence.** `docs/governance/verification/P0.6-report.md`; inherited host O&M records.

### 03.08 — Media Protection

**Requirement intent.** Protect media containing CUI; sanitize before disposal/reuse; markings.

**Implementation.** The agent's media are its digital stores (workspace, memory, spill, checkpoints — mapped in `docs/governance/boundary-scope.md` §3). Access limited by write confinement + the sensitive-path denylist; CUI/PII masked by the redaction engine and pattern pack in logs, tool output, terminal stdout, and file reads (`security.data_protection.cui_redaction`, `privacy.redact_pii`, `security.redact_secrets`, LG-DP-03/04 via `agent/data_protection.py`); marking preservation enforced on the data-protection path (LG-DP-02); tool-result retention TTL provides sanitization-equivalent secure deletion of expired spill (`security.data_protection.result_retention_ttl_seconds`, LG-DP-11) with secure purge of memory partitions (LG-MC-06); at-rest encryption over CUI/audit blobs (`security.data_protection.at_rest_encryption`, LG-DP-07 — FIPS-validated modules carried as POAM-FIPS).

**Implementing controls.** LG-DP-02/03/04/07/11, LG-AU-05, LG-MC-05/06.
**Config points.** `security.data_protection.cui_redaction`, `security.data_protection.at_rest_encryption`, `security.data_protection.result_retention_ttl_seconds`, `privacy.redact_pii`; `agent/data_protection.py`.
**Evidence.** `docs/governance/verification/P2.4-report.md`.

### 03.09 — Personnel Security

**Requirement intent.** Screen individuals; protect CUI during personnel actions.

**Implementation.** **Inherited/organizational** — screening by the sponsoring organization. Agent-side enforcement of personnel actions: roles bound to authenticated principals (`governance.role_bindings`) with SoD checked by `ci/governance-ci-gates/sod_check.py`; accounts de-provisioned via the managed-account lifecycle (`security.accounts`, `lliam_cli/secrets_cli.py`); removal from role bindings immediately revokes approval/oversight authority and is ledger-recorded.

**Implementing controls (overlap).** LG-GV-04/05, LG-IA-01/05.
**Config points.** `governance.role_bindings`, `security.accounts`; `ci/governance-ci-gates/sod_check.py`.
**Evidence.** `docs/governance/verification/P1.6-report.md`; inherited screening records.

### 03.10 — Physical Protection

**Requirement intent.** Limit physical access; protect/monitor the facility.

**Implementation.** **Inherited** — provided entirely by the facility/host boundary. The agent's adjacent contribution is the execution-surface host inventory (`docs/governance/boundary-scope.md` §4, LG-IN-06) recording which hosts run the agent and that no computer-use host is enrolled.

**Implementing controls (overlap).** LG-IN-06 (inventory only).
**Config points.** `docs/governance/boundary-scope.md`.
**Evidence.** Inherited facility records; host inventory (this step).

### 03.11 — Risk Assessment

**Requirement intent.** Assess risk; scan for vulnerabilities; remediate flaws.

**Implementation.** AI/system risk runs through the RM domain: the repeatable method (`docs/governance/risk-assessment-process.md`, LG-RM-01) and the living 17-risk register (`docs/governance/threat-risk-register.yaml`, LG-RM-02), with signed acceptance (P4.2) and unmet items on `docs/governance/poam.yaml`. Technical vulnerability management: blocking OSV.dev scanning (`tools/osv_check.py` + `ci/governance-ci-gates/osv_gate.py`, threshold `security.supply_chain.osv_fail_on: high`, LG-SS-02); compromised-package advisories checked at startup (`lliam_cli/security_advisories.py`, LG-SS-03); the prohibited-skills preflight (LG-CH-06).

**Implementing controls.** LG-RM-01/02, LG-SS-02/03, LG-CH-06.
**Config points.** `security.supply_chain`; `tools/osv_check.py`, `lliam_cli/security_advisories.py`; `docs/governance/threat-risk-register.yaml`.
**Evidence.** `docs/governance/verification/P3.4-report.md` (OSV gate), `P4.2-report.md` (risk layer).

### 03.12 — Security Assessment and Monitoring

**Requirement intent.** Assess controls periodically; POA&M; ongoing monitoring (ISCM); authorize the system.

**Implementation.** The control set is assessed against this SSP with the machine traceability matrix (`docs/governance/traceability-171r3.yaml`) reconciled in CI (`ci/governance-ci-gates/ssp_reconciliation_gate.py`); the SoA reconciles to the 188-control catalog (`ci/governance-ci-gates/soa_gate.py`, LG-RM-04); gaps track to closure on `docs/governance/poam.yaml` (LG-RM-07) and the deviation register (LG-CH-08). **System authorization** is the fail-closed go/no-go startup gate: `governance.authorization_id` must match a signed, unexpired, decision=authorized `docs/governance/authorization-record.yaml` (LG-GV-06, P4.1), with the CAIO waiver gate for any high-risk enablement (LG-GV-10). **ISCM streaming, control-effectiveness verification, and the cATO re-authorization loop land at P5.1/P5.2/P5.4 — carried as POAM-P5-MON / POAM-P5-EVAL / POAM-P5-CATO**; the interim compensating posture is hard authorization expiry + verify-on-startup + the local gate battery before every push.

**Implementing controls.** LG-GV-06/10, LG-IN-07, LG-RM-04/07, LG-CH-08 (operating); LG-GV-07/08, LG-MO-05..10 (P5).
**Config points.** `governance.authorization_id`; `docs/governance/authorization-record.yaml`, `docs/governance/poam.yaml`; `ci/governance-ci-gates/soa_gate.py`, `ci/governance-ci-gates/ssp_reconciliation_gate.py`.
**Evidence.** `docs/governance/verification/P4.1-report.md`, `P4.2-report.md`; this SSP + gate runs.

### 03.13 — System and Communications Protection

**Requirement intent.** Boundary protection; deny-by-default traffic; protect CUI in transit and at rest; prevent unauthorized transfer.

**Implementation.** Deny-by-default egress for governed sessions at the application layer: destination allowlist (`security.egress.mode: allowlist` + `policy/egress-allowlist.yaml` consumed by `tools/egress_policy.py`, LG-NE-01) with first-seen domains denied; the SSRF/private-IP/link-local/cloud-metadata floor is unconditional (`tools/url_safety.py`, `security.allow_private_urls: false`, LG-NE-02); website policy runs allowlist-mode fail-closed (`security.website_policy.mode`, `tools/website_policy.py`, LG-NE-03); the squid isolation enclave is the connection-level mirror (`deploy/docker-compose.gov.override.yml`, LG-NE-04 — production rollout carried as POAM-EGRESS-ENCLAVE); air-gap mode forces local-only providers (`security.egress.mode: deny_all`, LG-NE-06). In transit: verified TLS on all transports (LG-DP-06). At rest: `security.data_protection.at_rest_encryption` (LG-DP-07). Transfer/DLP: think-scrubbing of reasoning before egress (LG-DP-09) and the CUI taint gate escalating egress to HITL (`security.data_protection.dlp_taint_gate`, LG-DP-10). Sandbox isolation: `terminal.backend: docker` (LG-CH-05).

**Implementing controls.** LG-NE-01..06, LG-DP-06/07/09/10, LG-CH-05.
**Config points.** `security.egress.mode`, `security.egress.fail_closed`, `security.website_policy.mode`, `security.data_protection.dlp_taint_gate`, `terminal.backend`; `policy/egress-allowlist.yaml`, `tools/egress_policy.py`, `tools/url_safety.py`, `deploy/docker-compose.gov.override.yml`.
**Evidence.** `docs/governance/verification/P2.5-report.md`, `P0.4-report.md`.

### 03.14 — System and Information Integrity

**Requirement intent.** Flaw remediation; malicious-code protection; monitor for attacks; validate input.

**Implementation.** Zero-trust input posture (`security.input_trust`, `policy/input-trust-policy.yaml`, LG-PI-01) with always-on sanitize/delimit incl. control-char/invisible/bidi scrubbing (`agent/message_sanitization.py`, LG-PI-02); tool/MCP schemas validated and rejected on failure before binding (`security.schema_validation`, `tools/schema_sanitizer.py`, LG-PI-03); injection/promptware detection routes to approval (`tools/threat_patterns.py`, `tools/injection_defense.py`, LG-PI-04/06); the malicious-content scanner fails closed (`security.tirith_fail_open: false`, `tools/tirith_security.py`, LG-PI-05); the approval guard is hardened against embedded-"APPROVE" coercion (`security.smart_approval_guard`, LG-PI-07); inbound AI-generated/low-credibility content is screened detect-and-log (`security.inbound_screening`, LG-PI-08); sink-side output validation guards shell/file/browser sinks (LG-PI-09). Memory-poisoning defense scans before persistent writes (`security.memory_poisoning_defense`, LG-MC-01). Runaway containment: hard-stop + mutating budgets (LG-AZ-10/12). Flaw remediation couples to 03.11's OSV pipeline. **Trajectory-level drift detection and continuous attack monitoring land P5.1 (POAM-P5-MON).**

**Implementing controls.** LG-PI-01..09, LG-MC-01, LG-AZ-10/12, LG-SS-03 (operating); LG-MO-01..06 (P5.1).
**Config points.** `security.tirith_fail_open`, `security.input_trust`, `security.schema_validation`, `security.memory_poisoning_defense`; `tools/tirith_security.py`, `agent/message_sanitization.py`, `tools/injection_defense.py`.
**Evidence.** `docs/governance/verification/P0.5-report.md`, `P2.3-report.md`.

### 03.15 — Planning

**Requirement intent.** Develop/maintain the SSP; rules of behavior.

**Implementation.** This document is the SSP (LG-IN-07), version-controlled with the machine traceability matrix and a CI reconciliation gate that fails on SSP-vs-repo drift. The authorized boundary/scope statement is `docs/governance/boundary-scope.md` (LG-IN-01) with the asset/CUI maps (LG-IN-04/05). Rules of behavior are the signed AI policy (`docs/governance/ai-policy.md`, LG-GV-01) and the intended-use / prohibited-use statement (`docs/governance/intended-use.md`, LG-GV-02, godmode enumerated as prohibited and enforced), with the GenAI acceptable-use realized as the enforced provider/tool/skill allowlists (LG-GV-09) and the obligations register bound to controls (`docs/governance/regulatory-register.yaml`, LG-GV-03).

**Implementing controls.** LG-IN-01/05/07, LG-GV-01/02/03/09.
**Config points.** `governance.policy_id`; `docs/governance/SSP.md`, `docs/governance/boundary-scope.md`, `docs/governance/ai-policy.md`, `docs/governance/intended-use.md`.
**Evidence.** `docs/governance/verification/P4.1-report.md`, this step's report.

### 03.16 — System and Services Acquisition

**Requirement intent.** Security engineering; external system services; unsupported components.

**Implementation.** The dominant external services are inference providers and MCP servers. Provider governance: the approved allowlist (`policy/provider-allowlist.yaml`) enforced fail-closed across primary/fallback/MoA/auxiliary/delegation in `lliam_cli/provider_allowlist.py` + the runtime resolve seam, with residency/no-train vetting per provider and model cards required for eligibility (`docs/governance/model-cards/model-cards.yaml`, LG-MP-01..05). Model integrity: signed manifest + attestation, unsafe serialization banned (`model_manifest.yaml`, LG-MP-06/07). MCP/skill supply chain: deny-by-default allowlist with least-privilege scopes and TLS (`policy/mcp-allowlist.yaml`, `security.mcp_allowlist_enforce`, LG-SC-05/07); suppliers vetted via `docs/governance/supplier-vetting-register.md` (LG-TP-03).

**Implementing controls.** LG-MP-01..08, LG-SC-05/07, LG-TP-03, LG-CH-04.
**Config points.** `security.provider_allowlist_enforce`, `security.mcp_allowlist_enforce`; `policy/provider-allowlist.yaml`, `policy/mcp-allowlist.yaml`; `lliam_cli/provider_allowlist.py`.
**Evidence.** `docs/governance/verification/P3.1-report.md`, `P3.2-report.md`, `P3.3-report.md`.

### 03.17 — Supply Chain Risk Management

**Requirement intent.** SCRM plan; protect against supply-chain risk; provenance.

**Implementation.** Dependencies pinned with hash verification (`pyproject.toml` pins + `uv.lock` resolved hashes; `security.require_hashed_install`; `ci/governance-ci-gates/deps_hash_gate.sh`, LG-SS-01); blocking OSV scanning (`ci/governance-ci-gates/osv_gate.py`, LG-SS-02); supply-chain CI gates block `.pth`/base64-exec/install-hook shapes (`ci/governance-ci-gates/supply_chain_gate.py`, LG-SS-04); SBOM + machine-readable AI-BOM generated and reconciled to baseline per build (`ci/governance-ci-gates/generate_bom.py`, LG-SS-05, LG-IN-02/03); end-to-end artifact provenance via signed skill attestation + the signed model manifest with no self-verifying shipped secret (LG-SS-06, LG-MP-07); runtime lazy installs disabled (`security.allow_lazy_installs: false`, LG-SS-07). Provenance registers: `docs/governance/dependency-pinning.md`, `docs/governance/supplier-vetting-register.md`.

**Implementing controls.** LG-SS-01..07, LG-IN-02/03, LG-MP-07.
**Config points.** `security.require_hashed_install`, `security.supply_chain`; `ci/governance-ci-gates/supply_chain_gate.py`, `ci/governance-ci-gates/generate_bom.py`, `ci/governance-ci-gates/osv_gate.py`; `model_manifest.yaml`.
**Evidence.** `docs/governance/verification/P0.6-report.md`, `P3.4-report.md`.

## 4. Family Coverage Summary

| Family | Title | Status | Pending items (POA&M) |
|---|---|---|---|
| 03.01 | Access Control | Implemented | — |
| 03.02 | Awareness & Training | Inherited (org) + agent overlap | Training register → POAM-P4-SDLC |
| 03.03 | Audit & Accountability | Implemented | — |
| 03.04 | Configuration Management | Implemented | — |
| 03.05 | Identification & Authentication | Implemented | — |
| 03.06 | Incident Response | Implemented (procedure) | Tested kill-switch + IR automation → POAM-P5-IR |
| 03.07 | Maintenance | Inherited + agent overlap | — |
| 03.08 | Media Protection | Implemented | FIPS modules → POAM-FIPS |
| 03.09 | Personnel Security | Inherited + agent overlap | — |
| 03.10 | Physical Protection | Inherited | — |
| 03.11 | Risk Assessment | Implemented | — |
| 03.12 | Security Assessment & Monitoring | Implemented (authorization gate) | ISCM/cATO → POAM-P5-MON/EVAL/CATO |
| 03.13 | System & Communications Protection | Implemented | Network-layer enclave rollout → POAM-EGRESS-ENCLAVE |
| 03.14 | System & Information Integrity | Implemented | Runtime monitors → POAM-P5-MON |
| 03.15 | Planning | Implemented | — |
| 03.16 | System & Services Acquisition | Implemented | — |
| 03.17 | Supply Chain Risk Management | Implemented | — |

## 5. Assessor Notes

- **Reconciled-to-enforcement by construction.** Every family's config points are machine-verified against the repo in CI; a citation of a nonexistent key, file, or module fails the build. Pending work is on the POA&M, never claimed.
- **Single chokepoint claim is testable.** 100% of tool/skill/MCP execution is mediated and audited at the dispatch seam (LG-AZ-01/LG-AU-02) — the P2.1/P1.2 mediation reports are the proof artifacts.
- **Path-freeze is auditable.** Every config point is an existing key set by the overlay or a new additive file/module/CI check; `ci/governance-ci-gates/path_freeze_gate.py` guards frozen paths per release.

---

*Built on Hermes Agent (Nous Research, MIT). Governance overlay is additive and capability-preserving.*
