# Control Assurance & Shared-Responsibility Proof — LLIAM-GOV in a CUI Enclave

| Field | Value |
|---|---|
| Document | Independent, code-verified control-assurance + shared-responsibility statement for an adopting CUI enclave (CMMC L2 / NIST SP 800-171) |
| Audience | The adopting organization's ISSO and, if needed, their C3PAO assessor |
| Basis | Direct source-code verification of every claimed control against the runtime that enforces it (not a paperwork review). File:line citations throughout. |
| Method | Five independent reviewers traced each 800-171 family's controls to the code that enforces them and classified each as **enforced-at-runtime**, **scaffolded**, **paperware**, **inherited**, or **policy-artifact**, with a runnable test per control. |
| Honesty stance | This document deliberately under-claims. Anything an assessor could test and find non-operable is marked as such, so a hands-on test confirms this document rather than contradicting it. |
| Date | 2026-07-18 |
| Status | Assurance snapshot at `main` — pairs with the POA&M (`poam.yaml`); several items below require POA&M reconciliation before an authorization decision relies on them. |

---

## 0. How to read this (plain language)

LLIAM-GOV is an AI agent that runs **inside** your already-authorized CUI enclave. It is not a security boundary and does not replace one. The right mental model is a **tenant inside your boundary**:

- **The agent guards what it *does*** — every tool call is checked against policy before it runs, every action is written to a tamper-evident log, it refuses to reach non-approved networks or install software at runtime, it redacts CUI/PII, and it won't start if its governance paperwork is missing or expired.
- **Your enclave guards *where it lives*** — the network perimeter/firewall (SC-7), FIPS-validated disk encryption, physical facility access, host OS patching, and screening the people who operate it.

This document proves three things you can independently test:

1. **What the agent actually enforces today** (Part D), each with a test command.
2. **What is *not* the agent's job** and is correctly your enclave's (Part A) — so you don't double-count or mis-assign controls.
3. **That adding the agent does not open a new hole in a control you already own** (Part C — the non-invalidation argument).

**The single most important thing to verify first:** almost every agent-side control is *conditional on the agent booting in "strict" posture* (the `cli-config.gov.yaml` overlay). The default config does **not** select it. If strict posture is not active, the overlay gates are no-ops. See Part B.

---

## 1. Scope & boundary

Per `docs/governance/boundary-scope.md`, the authorization boundary is **the agent itself** — its tool execution, MCP client, skills, memory, inference routing, and audit ledger. Host OS, network fabric, and physical facility are **inherited** from your enclave. This is the correct architecture: software running inside a boundary must not claim controls it cannot physically enforce (it cannot lock a door, encrypt a disk at the hardware level, or screen a person).

**Framework note (important):** this repo maps controls to **NIST SP 800-171 Rev 3** (families 03.01–03.17). **CMMC Level 2 is assessed against Rev 2 (110 practices across 14 domains).** The two align cleanly for the 14 CMMC domains; families **03.15 (Planning), 03.16 (System & Services Acquisition), 03.17 (Supply Chain)** are Rev 3 / 800-53 additions **outside the CMMC L2 110** — treat them as defense-in-depth, not assessed practices. Part F is the bridge table.

---

## Part A — Shared responsibility: what is, and is NOT, the agent's job

This is the "what belongs to the network/environment, not the software" answer. Family-level split (verified against `traceability-171r3.yaml`, `shared-responsibility-matrix.yaml`, `boundary-scope.md`):

| 800-171 family | Owner | Why | What YOUR enclave must provide |
|---|---|---|---|
| 03.02 Awareness & Training | **Inherited (yours)** | Training humans is an organizational program; software can't deliver it | Role-based security training + completion records |
| 03.07 Maintenance | **Inherited (yours)** + thin agent overlap | Host/hardware O&M is the platform's | OS/firmware patching, maintenance-tool & personnel control, media sanitization. *(Agent's only maintenance surface — runtime dependency install — is locked off; see LG-SS-07.)* |
| 03.09 Personnel Security | **Inherited (yours)** + agent access-consequence overlap | Screening people is HR, not software | Personnel screening & position-sensitivity records. *(Agent enforces the access consequences via role bindings + SoD.)* |
| 03.10 Physical Protection | **Inherited (yours)** | Facility access/environmental controls have no software actuator | Physical access control, visitor logs, environmental protection, facility ATO |
| 03.13 System & Communications Protection | **Hybrid** | The perimeter is yours; the agent adds an app-layer overlay | **Network boundary / firewall (SC-7)** and the connection-level egress enclave (tracked as `POAM-EGRESS-ENCLAVE`, open). Agent adds deny-by-default app-layer egress + SSRF floor. |
| 03.08 Media Protection | **Hybrid** | Disk/media protection is the enclave's | **FIPS-validated data-at-rest encryption** (tracked as `POAM-FIPS`, open) + physical media sanitization. Agent adds redaction + retention purge of its own digital spill. |
| 03.05 Identification & Authentication | **Hybrid** | The identity provider is yours | **MFA / IdP.** Agent authenticates operators to its control plane and does non-person-entity (agent) identity; it does not issue credentials or perform MFA. |
| 03.01 AC · 03.03 AU · 03.04 CM · 03.06 IR · 03.11 RA · 03.12 CA · 03.14 SI | **Agent-enforced** (with the POA&M gaps in Part E) | These are the governed in-boundary surface | You provide the enclave; the agent enforces policy-mediated tool dispatch, the audit ledger, config/drift control, injection defense, etc. |
| 03.15 PL · 03.16 SA · 03.17 SR | **Agent + process** (outside CMMC L2 110) | Rev 3 additions; defense-in-depth | Planning/acquisition/supply-chain governance docs + CI gates |

**Plain-language summary you can hand your assessor:** *A piece of software cannot lock a server-room door, encrypt a physical disk at the hardware level, run a background check, or defend a network perimeter — those are the enclave's responsibility, and the agent is designed to **inherit** them rather than pretend to provide them. Four families are formally marked "inherited" for exactly this reason; three more (network protection, at-rest encryption, MFA) are shared, where the agent adds a software layer on top of the enclave's foundation. The agent cannot weaken any of these — it has no ability to unscreen a person, unlock a door, or turn off your firewall.*

---

## Part B — Preconditions (must be true, or the agent-side controls are not live)

An assessor should verify each of these as a configuration check **before** testing any agent control. If any is false, the controls that depend on it are inert:

| # | Precondition | If false… | How to check |
|---|---|---|---|
| B1 | **Strict posture is booted** — the process runs under `cli-config.gov.yaml` (via `LLIAM_CONFIG`/`HERMES_CONFIG`). The default `cli-config.yaml` sets only a model. | Every overlay gate (PDP, allowlists, DLP, fail-closed approval) is a **no-op**. | Confirm the service unit sets the env var; boot and confirm startup gates fire. |
| B2 | **`HERMES_WRITE_SAFE_ROOT` is set** to the CUI workspace. | File-write confinement **fails open** — the agent may write outside the workspace (only a static denylist remains). `.env.gov.example` ships it as an unfilled placeholder. | `test_safe_root_unset_allows_all` proves the fail-open; verify the deployed env sets it. |
| B3 | **`TIRITH_FAIL_OPEN` is NOT set** in the environment. | The command-security check can **fail open** (auto-allow) even under strict posture — env overrides the coercion (`tirith_security.py:86`). | Inspect the service environment; must be unset or `0`. |
| B4 | **The egress enclave is deployed** (`docker-compose.gov.override.yml` + squid allowlist). | Raw-socket / SDK egress that bypasses the app funnels is **not** caught at the connection layer (`POAM-EGRESS-ENCLAVE`, open). | Confirm the gateway container has no default route; egress only via squid. |
| B5 | **Enclave provides FIPS FDE, SC-7 firewall, MFA/IdP.** | The Hybrid controls (03.08/03.13/03.05) are not fully covered. | Your enclave's own ATO evidence. |
| B6 | **The CUI-serving entrypoint is the gateway.** | The full startup gate battery runs only on the gateway path; the bare CLI, MCP server, and batch runner do **not** run all startup gates. | Confirm operators reach the agent via the gateway, not an ungated entrypoint. |

---

## Part C — Non-invalidation argument (the core proof)

The specific ways introducing an AI agent could break your CMMC posture, and — for each — the enforced control that closes it, the test, and the honest residual.

### C1 — CUI exfiltration to a non-approved model/provider (the #1 risk)
- **Closed by:** provider allowlist enforced at the single `resolve_runtime_provider` chokepoint across all five inference paths (`lliam_cli/provider_allowlist.py:153`, consumed `runtime_provider.py:1901`), with CUI residency + no-train + TLS enforced for CUI-tagged content (`provider_allowlist.py:202-220`); **plus** deny-by-default egress at all five outbound funnels (`tools/egress_policy.py:296`, wired at `chat_completion_helpers.py:168`, `web_tools.py:969`, `browser_tool.py:2491`, `mcp_tool.py:2029`, `model_tools.py:1031`); **plus** CUI taint → HITL escalation on tainted egress (`tool_policy.py:836`, `egress_policy.py:266`).
- **Test:** `pytest tests/governance/test_p3_capability_corpus.py` (non-allowlisted provider blocked, all-paths routing, CUI-eligibility) + `pytest tests/tools/test_egress_policy.py`.
- **Residual:** requires B1 (strict) and B4 (enclave) — a plugin that opens its **own socket** bypasses the app funnels and is caught only by the squid enclave.

### C2 — An action that isn't audited
- **Closed by:** the tool-dispatch chokepoint writes a sealed, redacted, hash-chained record **before** the tool runs, at both executor paths and the inline path (`tool_executor.py:483` & `:1052`, `model_tools.py:1318`), fail-closed on high-risk write failure (`governance_audit.py:754`).
- **Test:** `pytest tests/agent/test_governance_audit.py tests/test_handle_function_call_governance.py`.
- **Residual (disclose):** the audit chain is **unkeyed SHA-256** — tamper-evident against accident and the agent's own file tools, but forge-able by anyone with direct file-write access, and it cannot detect whole-file truncation without an external anchor (not yet implemented). The MCP server's `messages_send`/`permissions_respond` bypass the chokepoint (`mcp_serve.py:741`) — an audit-coverage gap.

### C3 — Writing CUI outside the approved workspace
- **Closed by:** write-safe-root allowlist + sensitive-path denylist + traversal-safe path resolution (`agent/file_safety.py`, `tools/path_security.py:15`).
- **Test:** `pytest tests/tools/test_file_write_safety.py`.
- **Residual:** **fails open if `HERMES_WRITE_SAFE_ROOT` is unset** (precondition B2) — treat as a required config check, not an assumed control.

### C4 — Pulling malicious code at runtime
- **Closed by:** runtime dependency install is **refused** under strict posture (`tools/lazy_deps.py:420,727`, `allow_lazy_installs:false`); CI supply-chain gates (AST scanner, OSV scan, SBOM) block on merge.
- **Test:** `pytest tests/tools/test_lazy_deps.py::TestAllowLazyInstalls::test_disabled_via_config_raises`; `python ci/governance-ci-gates/supply_chain_gate.py .`; `.github/workflows/osv-scanner.yml`.
- **Residual:** the *cited* keys `require_hashed_install` and `security.supply_chain.osv_fail_on` have **no runtime reader** — the real enforcement is the CI gates + the lazy-install lock; do not represent the config flags as controls.

### C5 — Prompt-injection driving the agent to exfiltrate or act
- **Closed by:** untrusted content sanitized (`message_sanitization.py`), injection classified and **side-effecting** actions (egress/exec/send) escalated to HITL rather than auto-run (`injection_defense.py` → `tool_policy.py:816`), schema validation rejects malformed tool schemas (`input_integrity.py:146`).
- **Test:** `pytest tests/tools/test_injection_defense.py`.
- **Residual:** depends on B1/B3.

### C6 — Secret leakage
- **Closed by:** per-profile credential scoping (`agent/secret_scope.py`) + mandatory redaction-on-write in the ledger and logs (`governance_audit.py:313`, `agent/redact.py`).
- **Test:** `pytest tests/agent/test_secret_scope.py` + inspect a ledger record for a secret-bearing tool arg.

### C7 — Emergency containment (stop the agent during an incident)
- **Status: GAP — disclose.** The kill-switch mechanism is real and its enforcement seams are wired, **but `killswitch.engage()` has no production trigger** (no CLI command, signal handler, or endpoint calls it; its only caller, the cATO loop, is itself never called). So "immediately suspend all execution and inference" is **not operable** today.
- **Interim mitigation (real, testable):** the operator stops the process / `lliam-gov gateway stop`, and per-turn runaway-loop caps **are** enforced (`tool_guardrails.py`, LG-AZ-12 — genuinely wired). Recovery-on-restart re-runs the startup gate battery fail-closed.
- **Action:** wire an operator/automated trigger before relying on IR automation; keep `POAM-P5-IR` **open** (see Part E).

---

## Part D — Control-by-control assurance (by family)

Legend: **E** = enforced-at-runtime (live, fail-closed) · **S** = scaffolded (exists + unit-tested, not wired to a production trigger/path) · **P** = paperware (no runtime reader / doc-only enforcement claim) · **I** = inherited · **DOC** = policy artifact (a document control, appropriately a document).

### 03.03 Audit & Accountability — **strong, with an honest tamper-evidence caveat**
| Control | Status | Proof (runtime) | Test |
|---|---|---|---|
| LG-AU-01 hash-chained ledger | E | `governance_audit.py:653,166` | `test_governance_audit.py::test_chain_is_valid_and_monotonic` |
| LG-AU-02 single audit chokepoint | E | `tool_executor.py:483,1052`; `model_tools.py:1318` | `test_handle_function_call_governance.py` |
| LG-AU-04 standardized record | E | `governance_audit.py:585` | `::test_record_schema_required_fields` |
| LG-AU-05 redaction on write | E | `governance_audit.py:620` (`force=True`) | `::test_redaction_covers_all_freeform_fields` |
| LG-AU-06 UTC ms + monotonic | E | `governance_audit.py:630,687` | `::test_chain_is_valid_and_monotonic` |
| LG-AU-07 ledger path-confined | E | `governance_audit.py:175` | `::test_configured_ledger_path_outside_home_logs_is_refused` |
| LG-AU-08 startup chain verify | E | `security_audit_startup.py:924` ← `gateway/run.py:18551` | `test_audit_chain_startup.py::test_strict_block_raises_on_tamper` |
| LG-AU-09 fail-closed on write fail | E | `governance_audit.py:754`; `governance_audit_hooks.py:296` | `::test_fail_closed_blocks_high_risk_on_write_failure` |
| LG-AU-10 operator-subject binding | S | dashboard-auth feed live; `set_operator_subject` has no prod caller | unit only |
| LG-IA-10 delegation chain | S | actor bound; subject/delegation never populated in prod | unit only |
| *key* `audit.chokepoint_required` | P | no reader (mechanism hardcoded, so control holds) | n/a |

**Honest caveat for the assessor:** unkeyed SHA-256 (no HMAC/external anchor) — forge-able by an actor with file-write access; whole-file truncation undetectable internally (deviation `LG-AU-08-R1`). Recommend an HMAC key or external anchor before relying on the ledger for adversarial tamper-evidence.

### 03.01 Access Control — **core mediation enforced; two real gaps**
| Control | Status | Proof | Test |
|---|---|---|---|
| LG-AZ-01 policy decision point at dispatch | E | `tool_policy.py:971` ← `tool_executor.py:455,1035`, `model_tools.py:1295` | `test_tool_policy_pdp.py::test_executor_seams_invoke_pdp_gate_and_turn_reset` |
| LG-AZ-05 path-traversal confinement | E | `path_security.py:15` | `test_file_write_safety.py::test_safe_root_does_not_override_static_deny` |
| LG-AZ-06/07/10/12 privilege tiering, JIT grant, mutation budgets, denial-of-wallet | E | `tool_policy.py:850,502,874,887` | `test_tool_policy_pdp.py`, `test_p2_capability_corpus.py` |
| LG-HO-01/02 HITL + non-interactive fail-closed deny | E | `approval.py:1620,1643`; `hitl_oversight.py:64` | `test_tool_policy_pdp.py::test_pdp_gate_blocks_hitl_pending_approval` |
| LG-DP-01 CUI classification → egress escalation | E | `data_protection.py:136` ← `model_tools.py:903`; `tool_policy.py:835` | `test_data_protection.py` |
| **LG-AZ-04 write confinement** | **E but FAILS OPEN if `HERMES_WRITE_SAFE_ROOT` unset** | `file_safety.py:165,85` | `test_file_write_safety.py::test_safe_root_unset_allows_all` (proves the hole) — **precondition B2** |
| LG-AZ-02 tool denylist | S | skill-deny live; `tool_denied()` reader (`tool_policy.py:411`) has **no caller** | skill path only |
| LG-GV-05 authenticated-approver binding | P | `security.require_authenticated_approver` has no reader; approver identity not bound into the live record | CI/doc only |

### 03.05 Identification & Authentication — **NPE identity + TLS + control-plane key enforced; human-auth keys are paperware**
| Control | Status | Proof | Test |
|---|---|---|---|
| LG-IA-02 agent (NPE) identity into every record | E | `agent_identity.py` ← `governance_audit_hooks.py:168` | `test_agent_identity.py` |
| LG-IA-03 per-profile secret scoping | E | `secret_scope.py` ← `runtime_provider.py:16` | `test_secret_scope.py` |
| LG-IA-08 TLS forced (control-plane, provider, MCP) | E | `posture_resolver.py:59`; `provider_allowlist.py:217`; `mcp_allowlist.py:235` | `test_mcp_allowlist.py` |
| LG-IA-11 no network listener without a key | E | `posture_resolver.py:57`; `security_audit_startup.py:675` | `test_control_plane_auth.py` |
| LG-IA-06 `require_operator_auth` | P | **no runtime reader** — anonymous operator not blocked by code | none — **inherited to your IdP** |
| LG-IA-07 `require_mfa` | P | **no runtime reader** — MFA is your IdP's job | none — **inherited** |
| *key* `security.accounts` | P | no reader | none |

### 03.13 System & Communications Protection — **the CUI-exfil heart; genuinely enforced at the app layer**
| Control | Status | Proof | Test |
|---|---|---|---|
| LG-NE-01 deny-by-default egress (5 funnels) | E | `egress_policy.py:296` + 5 sites (see C1) | `test_egress_policy.py` |
| LG-NE-02 SSRF/private/metadata floor | E | `egress_policy.py:194`; `url_safety.py:214` | `test_url_safety.py` |
| LG-NE-06 air-gap `deny_all` | E | `egress_policy.py:178` | `test_egress_policy.py` |
| LG-DP-06 TLS-only egress | E | `egress_policy.py:225` | manual: `http://` allowlisted host → deny |
| LG-DP-10 CUI DLP taint-gate | E | `model_tools.py:903`; `tool_policy.py:836`; `egress_policy.py:266` | `test_p2_capability_corpus.py` |
| LG-NE-03 per-surface website scoping | E (via egress_policy) | `egress_policy.py:255` | manual |
| LG-NE-04/05 connection-level egress enclave | S | `docker-compose.gov.override.yml` + squid — **operator-deployed, not code-enforced** (`POAM-EGRESS-ENCLAVE`) | manual: curl non-allowlisted IP from agent container → squid 403 |
| *keys* `website_policy.mode`, `dlp_taint_gate` | P | decoy keys — enforcement rides on `security.posture:strict`, not these | n/a |

### 03.14 System & Information Integrity — **injection defense enforced; one env fail-open hole**
| Control | Status | Proof | Test |
|---|---|---|---|
| LG-PI-02 sanitize/delimit untrusted content | E | `message_sanitization.py` ← `conversation_loop.py:925` | (add unit test — none present) |
| LG-PI-03 schema validation reject-on-fail | E | `input_integrity.py:146` ← `model_tools.py:534` | manual: bind malformed MCP schema → reject |
| LG-PI-04/06 injection → HITL escalation | E | `injection_defense.py` ← `tool_policy.py:785,816` | `test_injection_defense.py` |
| LG-PI-05 command security fail-closed | **E with env fail-open hole** | `posture_resolver.py:49`; `approval.py:1686` — but `TIRITH_FAIL_OPEN` env overrides (`tirith_security.py:86`) | `test_tirith_security.py` — **precondition B3** |

### 03.08 Media Protection — **redaction enforced; at-rest encryption is inherited**
| Control | Status | Proof | Test |
|---|---|---|---|
| LG-AU-05 / LG-DP-03 redaction on write | E | `governance_audit.py:313`; `agent/redact.py` | `test_governance_audit.py::test_redaction_covers_all_freeform_fields` |
| LG-DP-04 CUI/PII pattern pack | E (via posture) | `data_protection.py:124` ← `memory_governance.py:140` | `test_data_protection.py` |
| **LG-DP-07 at-rest encryption** | **P (agent) / I (enclave)** | `encrypt_at_rest` exists but has **zero production callers**; real protection is enclave FDE (`POAM-FIPS`, open) | verify enclave FIPS FDE separately |
| LG-DP-02 marking preservation on write | S | markings detected, not re-applied on write | — |
| LG-DP-11 output masking + retention purge | S | TTL accessor reads config; no purge consumer wired | — |

### 03.04 Configuration Management — **posture flip enforced; the "startup drift check" does not exist**
| Control | Status | Proof | Test |
|---|---|---|---|
| LG-CH-01/02 hardened overlay + strict coercion on live load | E | `config.py:6270,6289`; `posture_resolver.py:137` | `test_control_plane_auth.py::test_raw_config_still_blocks_when_merged_is_strict` |
| LG-CH-04 least-functionality skill/tool disable | E | `tool_policy.py:156,342` | `test_tool_policy_nested_deny.py` |
| LG-CH-06 godmode/prohibited-skill block | E (startup + CI) | `security_audit_startup.py:1268`; `governance-gates.yml:49` | `test_p41_governance_artifacts.py` |
| LG-CH-09 unauth-API RCE blocked | E (partial) | `security_audit_startup.py:697` ← `gateway/run.py:18464` | `test_security_audit_startup.py::test_api_server_network_no_key_flags` |
| **LG-CH-03 startup drift check** | **S (CI-only)** | `baseline-critical-keys.yaml` read **only** by `baseline_drift_gate.py` — **no runtime/startup reader**. Runtime/home-config drift on a deployed box is not caught at startup. | `python ci/governance-ci-gates/baseline_drift_gate.py` (validates the committed overlay, not a live process) |
| LG-CH-08 deviation approval linkage | P | `deviation-register.yaml` has no code consumer | drift is hard-blocked in CI or silently allowed regardless of the register |

### 03.06 Incident Response — **loop caps enforced; kill-switch/containment/breaker NOT operable**
| Control | Status | Proof | Test / assessor result |
|---|---|---|---|
| LG-AZ-12 runaway-loop hard stop | **E** | `tool_guardrails.py:243` ← `tool_executor.py:432,1023` | genuinely wired — **PASSES** |
| LG-IR-01 kill-switch halts exec+inference | **S** | seams wired (`governance_audit_hooks.py:265`, `runtime_provider.py:1878`) but `engage()` has **no prod caller** | `test_p53_killswitch.py` tests the mechanism in isolation — a live incident test **finds nothing trips it** |
| LG-IR-02 containment / disable tool classes | S | `class_contained()` reachable only via un-triggered `engage()` | isolation only |
| LG-IR-03 auto-trip circuit breaker | **P** | `circuit_breaker.conditions/action` config has **no reader** | nothing watches the conditions |
| LG-IR-08 recovery to known-good | S / partial | `recover_and_reenable()` fail-closed but no prod caller; startup gate chain is live | isolation + live startup chain |
| LG-RM-09 halt/rollback plan | DOC | runbook exists; describes automation not yet wired | manual read |

### 03.12 Security Assessment & Monitoring — **ATO gate enforced; monitors half-dead**
| Control | Status | Proof | Test |
|---|---|---|---|
| LG-GV-06 go/no-go ATO gating at startup | E | `security_audit_startup.py:1207` | manual: mismatched `authorization_id` → startup blocks |
| LG-GV-10/RM-04 SoA reconciliation | E (via CI pytest) | `soa_gate.check_soa` run in `test_p42_risk_soa.py:88` | `test_p42_risk_soa.py::test_soa_gate_passes_on_repo` |
| LG-IN-07 SSP reconciliation | E (via CI pytest) | `ssp_reconciliation_gate.check_ssp` in `test_p43_ssp.py:60` | `test_p43_ssp.py::test_ssp_gate_passes_on_repo` |
| LG-RM-07 POA&M registry | E (artifact + CI) | `poam.yaml` validated `test_p42_risk_soa.py:114` | `::test_poam_items_have_owner_milestone_and_valid_status` |
| LG-MO-01 runaway monitor | E | `runtime_monitors._check_runaway` on `tool.dispatch` | live |
| LG-MO-04 policy-violation monitor | E | `_check_policy` on emitted events | live |
| **LG-MO-02 egress-anomaly monitor** | **S (dead)** | keys on `provider.call`/`mcp.call` — **no code emits these**; tool.dispatch fallback has a `tool.`-prefix mismatch | injecting an egress anomaly yields **silence** |
| **LG-MO-03 supplier/schema-drift monitor** | **S (dead)** | keys on `mcp.load`/`skill.load` — never emitted | silence |
| **LG-MO-05 ISCM/SIEM sink** | **S (misconfigured)** | `iscm_sink.py:141` doesn't expand `$HERMES_HOME` → writes to a literal `./$HERMES_HOME/...` | SIEM never receives events |
| LG-PF-08/09 output monitor (PII/CUI egress block) | S | `output_monitor.scan_output` called only from tests | cannot block in prod |

*Note the doc-vs-wiring nuance an assessor should be told:* `soa_gate.py`/`ssp_reconciliation_gate.py`/`osv_gate.py` are **not invoked by a workflow step**; SoA/SSP are enforced because the **pytest suite runs the gate function against the real repo** (drift → red CI), while `osv_gate.py` is genuinely dead (real OSV enforcement is `osv-scanner.yml`).

### 03.11 Risk Assessment · 03.15 Planning · 03.16 SA · 03.17 Supply Chain
| Control | Status | Proof | Test |
|---|---|---|---|
| LG-GV-01 governance-artifacts startup gate | E | `security_audit_startup.py:1097` | `test_p41_governance_artifacts.py::test_placeholder_policy_identity_blocks` |
| LG-SS-07 no runtime dependency install | E | `lazy_deps.py:420,727` | `test_lazy_deps.py::TestAllowLazyInstalls::test_disabled_via_config_raises` |
| LG-SS-04/05 supply-chain AST gate + SBOM/AI-BOM | E (CI) | `supply_chain_gate.py`, `generate_bom.py` | `test_supply_chain_gates.py::*` |
| LG-SS-02 OSV scanning | E (via `osv-scanner.yml`) — **but** `osv_gate.py` dead & `osv_fail_on` unread | `osv-scanner.yml`; `osv_check.py` (MCP-launch malware, fail-open) | `test_osv_check.py` |
| LG-MP-01/02/03/06 provider vetting/allowlist | E | `provider_allowlist.py:153,202`; `runtime_provider.py:1901,1914` | `test_p3_capability_corpus.py::*` |
| LG-SC-05/07 MCP allowlist + least privilege | E | `mcp_allowlist.py:189` ← `mcp_tool.py:3263` | `test_mcp_allowlist.py` |
| LG-SS-03 compromised-package detection | E (detect) / non-blocking | `security_advisories.detect_compromised()` ← `gateway/run.py:5947` | `test_security_advisories.py` — detect-and-log, not enforced ack |
| LG-SS-06 model provenance/attestation | S (template) | verifier real; `model_manifest.yaml` ships placeholder signature/hashes | must provision signing key before relying |
| SSP.md / boundary-scope.md / ai-policy.md | DOC (filled) | real filled instances | reconciliation gates |
| **intended-use.md** | DOC (**DRAFT — pending approval**) | `intended-use.md:8` | **ratify before ATO reliance** |
| *keys* `require_hashed_install`, `security.supply_chain.osv_fail_on` | P | no readers (real enforcement = CI gates + lazy-install lock) | n/a |

### 03.02 / 03.07 / 03.09 / 03.10 — **Inherited (yours).** See Part A. The agent's only overlaps: SoD gate (`sod_check.py:190`, real reader) and the runtime dependency-install lock (`allow_lazy_installs:false`). The agent cannot perform, nor weaken, physical/personnel/facility controls.

---

## Part E — Honest gap register + POA&M reconciliation

The controls above marked **S** or **P** must not be relied on for an authorization decision until wired or re-scoped. Critically, several POA&M items are marked **closed** but the underlying controls are **not operable** — an assessor reading the POA&M will find this. Recommended reconciliation:

| POA&M item | Current | Reality (verified) | Recommendation |
|---|---|---|---|
| POAM-P5-IR | closed | Kill-switch/containment/breaker have no production trigger (C7) | **Reopen** — wire an operator/automated engage path; document interim mitigation (process stop + loop caps) |
| POAM-P5-MON | closed | LG-MO-02/03 dead (no event source); ISCM sink writes to a bogus path; output monitor test-only | **Reopen** — emit the events the monitors consume, fix `$HERMES_HOME` expansion, wire `output_monitor` |
| POAM-P5-CATO | closed | `run_cato_cycle` has no caller — cATO/auto-suspend never runs | **Reopen or re-scope** as "mechanism delivered, production-wiring pending" |
| POAM-FIPS | open ✓ | Correctly open — at-rest encryption is enclave FDE | Keep open; satisfied by your enclave's FIPS FDE evidence |
| POAM-EGRESS-ENCLAVE | open ✓ | Correctly open — squid enclave is operator-deployed | Keep open; deploy per B4 |

**Additional honest disclosures for the package:** unkeyed audit chain (add HMAC/anchor); `LG-CH-03` runtime drift check absent (add a startup baseline comparison); `intended-use.md` is DRAFT (ratify); several config keys are decoys with no reader (`require_operator_auth`, `require_mfa`, `accounts`, `website_policy.mode`, `cui_redaction`, `dlp_taint_gate`, `require_hashed_install`, `osv_fail_on`, `audit.chokepoint_required`) — either wire readers or relabel them "config-of-record, enforced elsewhere" so an assessor testing the key isn't misled.

---

## Part F — CMMC L2 (800-171 Rev 2) ↔ this repo (Rev 3) bridge

| CMMC L2 domain (Rev 2) | Rev 3 family here | Assurance posture (this doc) |
|---|---|---|
| AC | 03.01 | Enforced core; 2 gaps (AZ-04 fail-open, GV-05 approver binding) |
| AT | 03.02 | **Inherited (yours)** |
| AU | 03.03 | Enforced; unkeyed-chain caveat |
| CM | 03.04 | Enforced posture flip; CH-03 drift + CH-08 deviation gaps |
| IA | 03.05 | Enforced NPE/TLS/key; MFA/operator-auth **inherited** |
| IR | 03.06 | Loop caps enforced; **kill-switch not operable (gap)** |
| MA | 03.07 | **Inherited (yours)** + lazy-install lock |
| MP | 03.08 | Redaction enforced; **at-rest encryption inherited (FIPS)** |
| PS | 03.09 | **Inherited (yours)** + SoD overlap |
| PE | 03.10 | **Inherited (yours)** |
| RA | 03.11 | Enforced supply/OSV (via CI); process docs |
| CA | 03.12 | ATO gate enforced; **monitors half-dead (gap)** |
| SC | 03.13 | App-layer egress enforced; **perimeter/enclave inherited** |
| SI | 03.14 | Injection defense enforced; tirith env fail-open (B3) |
| *(no CMMC L2 equiv)* | 03.15/16/17 | Defense-in-depth beyond the 110 |

---

## Appendix — Independent test battery (run this yourself)

```bash
# 0. Preconditions
#    Confirm strict posture (B1), HERMES_WRITE_SAFE_ROOT set (B2),
#    TIRITH_FAIL_OPEN unset (B3), egress enclave deployed (B4).

# 1. Governance CI gates (fail-closed)
python ci/governance-ci-gates/go_no_go_gate.py            # release/ATO gate → GO/NO-GO
python ci/governance-ci-gates/soa_gate.py                 # SoA ↔ catalog reconcile
python ci/governance-ci-gates/ssp_reconciliation_gate.py  # SSP ↔ config reconcile
python ci/governance-ci-gates/baseline_drift_gate.py      # committed-overlay drift
python ci/governance-ci-gates/sod_check.py                # separation of duties
python ci/governance-ci-gates/supply_chain_gate.py .      # install-artifact block
bash   ci/governance-ci-gates/deps_hash_gate.sh           # pinned + hashed deps

# 2. Enforced-control tests (the controls you can rely on)
scripts/run_tests.sh tests/governance/test_p3_capability_corpus.py   # provider/MCP allowlist, all paths
scripts/run_tests.sh tests/tools/test_egress_policy.py tests/tools/test_url_safety.py  # egress + SSRF
scripts/run_tests.sh tests/agent/test_governance_audit.py            # audit ledger
scripts/run_tests.sh tests/tools/test_tool_policy_pdp.py             # policy decision point
scripts/run_tests.sh tests/tools/test_file_write_safety.py           # write confinement (+ the fail-open proof)
scripts/run_tests.sh tests/tools/test_injection_defense.py           # prompt-injection → HITL

# 3. The honest negatives — confirm the gaps yourself
#    - Engage an incident and confirm inference does NOT stop (kill-switch gap, C7).
#    - Inject an egress anomaly and confirm NO monitor alert fires (LG-MO-02 dead).
#    - Unset HERMES_WRITE_SAFE_ROOT and confirm writes escape the workspace (B2).
```

*This document is an assurance snapshot, not an authorization. It is designed so that every "enforced" claim is independently reproducible and every gap is disclosed before an assessor finds it — which is the posture that lets an adopting enclave trust the rest.*
