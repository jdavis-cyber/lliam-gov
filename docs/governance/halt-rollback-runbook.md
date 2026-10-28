# Halt / Rollback Runbook — Lliam-GOV

| Field | Value |
|---|---|
| Document | Halt / Rollback Runbook (LG-RM-09) |
| Owner | Kill-Switch Owner (`governance.role_bindings.killswitch_owner`) |
| Classification | CUI//SP-PRIV (template — mark per instance) |
| Version | 1.0 (documented at P4.2; executed halt/restore test lands P5.3 — POAM-P5-IR) |
| Date | 2026-07-16 |

> **Purpose.** The documented fail-safe required by **LG-RM-09** and OMB M-25-21's human-oversight-with-fail-safe practice: how to promptly suspend Lliam-GOV's autonomy, contain an incident, restore the last known-good baseline, and re-validate before autonomy resumes. The kill-switch and containment automation (LG-IR-01/02/03) and the monthly halt-test evidence land at P5.3 (AI-501); this runbook is the procedure of record they implement.

## 1. Triggers

Execute this runbook on any of: critical posture-break (LG-GV-07 telemetry / LG-MO-08 effectiveness check), audit-chain verification failure (LG-AU-08), suspected prompt-injection-driven action chain, provider spillage indication, runaway loop that survives the hard-stop (LG-AZ-12), or operator/CAIO discretion.

## 2. Halt (suspend autonomy)

1. **In-session hard stop.** Trip the interrupt primitive — `tools/interrupt.py` — which suspends tool execution and inference egress for the session (LG-IR-01). From the CLI, terminate the gateway process (`lliam-gov gateway stop`); the duplicate-instance guard prevents silent restarts.
2. **Deny re-entry.** Leave `security.posture: strict` in force; if compromise of the overlay itself is suspected, revoke the go/no-go: set `decision: halted` in `docs/governance/authorization-record.yaml` — the LG-GV-06 startup gate then refuses to serve work fail-closed on any restart.
3. **Cut egress.** Disable network for the sandbox (docker network disconnect) and/or the host per enclave procedure; the egress allowlist (LG-NE-01/03) remains deny-by-default regardless.
4. **Freeze state.** Do NOT purge memory/checkpoints yet — preserve forensic state first (§3).

## 3. Preserve forensics (before any cleanup)

1. Copy the hash-chained audit ledger (`$HERMES_HOME/logs/agent-audit.log`) and session/trajectory state to write-once storage with SHA-256 manifests (LG-IR-04 chain of custody).
2. Run `verify_chain()` (`agent/governance_audit.py`) over the copy and record the PASS/FAIL — the integrity-verified chain is the reconstruction basis (LG-IR-07).

## 4. Contain

1. Rotate/revoke provider and MCP credentials touched by the affected session (LG-IR-02); the managed-account inventory (`security.accounts`, LG-IA-01) enumerates them.
2. Disable implicated tool classes / skills via `skills.disabled` + `security.tool_denylist` additions (graduated: narrowest effective disable, not blanket).
3. If DFARS-covered CUI may be affected: start the 72-hour DIBNet reporting clock and follow the external-reporting matrix (LG-IR-06; procedure completes at P5.3).

## 5. Rollback to known-good baseline

1. Check out the last signed good tag (`gov-P<N>-good`) in the deployment checkout; the approved baseline pin is recorded in `docs/governance/authorization-record.yaml` (`baseline.git_tag` / `git_commit`).
2. Restore config from the version-controlled overlay (`cli-config.gov.yaml`) — writes never target the overlay, so it is authoritative; discard the mutable home config if suspect.
3. Restore memory/checkpoints from the last pre-incident snapshot; purge entries written by the affected session (LG-MC-06 secure purge).
4. Rotate any remaining session credentials.

## 6. Re-validate before autonomy resumes (fail-closed)

1. Re-run the startup gate chain — posture audit, control-plane auth, provider allowlist, model integrity, governance artifacts, and `verify_chain()` — all must PASS (LG-GV-06 / LG-AU-08; `lliam_cli/security_audit_startup.py`).
2. Run the governance CI gates locally (`ci/governance-ci-gates/`): audit_chain_selftest, sod_check, baseline_drift_gate, prohibited_skills_gate, regulatory_reconciliation_gate, soa_gate, path_freeze_gate.
3. Restore `decision: authorized` (re-authorization by the Authorizing Official with CAIO concurrence — LG-GV-06/08) only after 1–2 pass and the incident record (LG-IR-05) is filed.
4. Record the halt→restore cycle in the journal/evidence tree; the P5.3 scheduled kill-switch test repeats this cycle on cadence and must show **clean full-capability restore** (no lingering deny state).

## 7. Roles

| Step | Accountable |
|---|---|
| Trip halt / containment | Kill-Switch Owner |
| Forensic preservation & chain verify | ISSO |
| External reporting decision | CAIO |
| Re-authorization to resume | Authorizing Official (Approver) |

---

*Built on Hermes Agent (Nous Research, MIT). Governance overlay is additive and capability-preserving.*
