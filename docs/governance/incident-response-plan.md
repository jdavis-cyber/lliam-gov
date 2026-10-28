# Agentic Incident Response Plan — Lliam-GOV

| Field | Value |
|---|---|
| Document | Agentic Incident Response Plan (LG-IR-01..09, LG-RM-09) |
| Owner | ISSO (IR Lead); Kill-Switch Owner; CAIO (reporting) |
| Classification | CUI//SP-PRIV (template — mark per instance) |
| Version | 1.0 |
| Date | 2026-07-16 |
| Review-by | At each management review (LG-GV-08) and after any incident |

> **Purpose.** The operational incident-response capability for the Lliam-GOV agent: detection, triage, containment (kill-switch), forensics, recovery to a known-good signed baseline, and reporting. The kill-switch and recovery authority is the additive `agent/killswitch.py`, wired fail-safe at the tool-dispatch chokepoint (`agent/governance_audit_hooks.predispatch_gate`) and the inference-resolution seam (`lliam_cli/runtime_provider.resolve_runtime_provider`). Companion: `docs/governance/halt-rollback-runbook.md`. Additive — no existing path renamed.

## 1. Purpose, scope, authority

Scope is the governed agent (SSP boundary). Authority: the **Kill-Switch Owner** (`governance.role_bindings.killswitch_owner`) may engage containment unilaterally; only the **Authorizing Official (Approver)** re-enables autonomy after recovery. In the single-operator eval deployment these roles are co-held per the tracked deviations in `docs/governance/roles.yaml`.

## 2. Roles (RACI)

| Activity | Kill-Switch Owner | ISSO (IR Lead) | CAIO | Approver | Auditor |
|---|:--:|:--:|:--:|:--:|:--:|
| Engage kill-switch / containment | **R/A** | R | I | I | I |
| Forensic preservation | C | **R/A** | I | I | C |
| Severity triage | C | **R/A** | C | I | I |
| External reporting decision | I | R | **A** | I | I |
| Re-enable autonomy | I | R | C | **A** | I |
| Incident reconstruction / RCA | I | **R/A** | I | I | C |

## 3. Detection & triage

Detections converge on the hash-chained ledger (`agent/governance_audit.py`, LG-AU-01) and stream to the ISCM/SIEM sink (`agent/iscm_sink.py`, LG-MO-05). The runtime monitors (`agent/runtime_monitors.py`, LG-MO-01..06) raise the alerts that open an incident: runaway loop, egress anomaly / first-seen domain, provider/MCP drift, goal-drift/policy-violation, correlated per-session risk timeline with near-real-time notification to named staff. The control-effectiveness verifier (`control_effectiveness.py`, LG-MO-08) and output monitor (`agent/output_monitor.py`, LG-PF-08/09) add posture-break and PII/CUI-leak detection.

### Severity (CUI exposure × irreversibility) — LG-IR-05

| Severity | Definition | Activation |
|---|---|---|
| **SEV-1 Critical** | Confirmed CUI exposure outside the approved boundary and/or an irreversible high-impact action executed. | Immediate **global** kill-switch; DFARS 72-hour clock starts; CAIO engaged. |
| **SEV-2 High** | Probable CUI exposure, a reversible high-impact action, or a containment-defeating posture change. | Kill-switch + targeted containment; reporting clock evaluated. |
| **SEV-3 Medium** | No confirmed CUI exposure; bounded, reversible, low-impact, or auto-contained. | Quarantine + investigate; ISSO review. |
| **SEV-4 Low** | Anomaly with no CUI nexus and no agency to act. | Log; tune thresholds; no containment. |

**Triage rule:** when CUI exposure is uncertain, classify **up** until forensics prove otherwise. Irreversibility is judged at the sink (shell mutation, out-of-workspace write, outbound send, credential use).

## 4. Containment — LG-IR-01/02/03

**Forensics-first (LG-IR-04):** a copy-only forensic snapshot (§6) precedes any state-mutating containment so evidence is not destroyed.

- **Kill-switch (LG-IR-01).** `agent.killswitch.engage(reason, actor)` suspends **all tool execution** (the tool-dispatch chokepoint returns a halt `ToolGuardrailDecision`) **and all inference** (every routing path resolves through `resolve_runtime_provider`, which raises `KillSwitchEngaged`). State is durable (a file under the agent home, outside the write-safe-root), survives threads/process, and cannot be cleared by an ordinary agent write. Operator path: the Kill-Switch Owner invokes `engage`; a critical monitor alert may auto-engage (P5.4 cATO). Backed by the existing per-thread `tools/interrupt.py` for in-flight stop.
- **Agentic containment (LG-IR-02).** `engage(..., contain_classes=[...])` contains named tool classes while preserving low-risk reads; force HITL via `security.deny_on_no_approver` + write-approval; revoke/rotate secrets via `lliam_cli/secrets_cli.py` + per-profile `agent/secret_scope.py`; drop the offending provider from `policy/provider-allowlist.yaml` so no path can re-route.
- **Circuit-breaker / network disconnect (LG-IR-03).** A critical condition (egress violation, CUI taint, loop/budget exhaustion) flips egress to deny-all (`security.egress.mode: deny_all`, `tools/url_safety.py` floor) and auto-invokes the kill-switch, then escalates to the Watch role and the SIEM feed. Legitimate long-running work is exempted via budget overrides so the breaker does not throttle normal operation.

## 5. Containment selection by incident type

| Type | Kill-switch | Tool-class disable | Cred revoke | Provider cutoff | Net disconnect | Memory quarantine |
|---|:--:|:--:|:--:|:--:|:--:|:--:|
| Injection→action | ● | ● (force HITL) | — | — | ○ | ○ |
| Tool abuse | ● | ● | — | — | ○ | — |
| CUI exfil | ● | — | ○ | ● | ● | — |
| MCP/skill compromise | ○ | ● | ○ | — | ○ | ● |
| godmode/jailbreak | ● | ● | — | — | — | — |
| Memory poison | ○ | — | — | — | — | ● |
| Credential exposure | ● | — | ● | ○ | ○ | — |
| Audit tampering | ● | — | — | — | ● | ● |
| Runaway/wallet | ● (hard-stop) | ○ | — | ○ | ○ | — |

## 6. Forensics & chain of custody — LG-IR-04 / LG-IR-07

Before containment mutates state, preserve (copy-only) the pre-incident checkpoint, raw tool I/O, the trajectory, and a copy of the LG-AU-01 audit segment to an evidence root **outside the agent's writable reach** (`tools/path_security.py`-confined). Each bundle is stamped with the collector principal, UTC timestamp, and SHA-256 (chain of custody). **Reconstruction (LG-IR-07):** rebuild from the **integrity-verified** ledger — run `agent.governance_audit.verify_chain()` **before** relying on the record; if verification fails, treat as audit tampering (SEV-1/2) and reconstruct from the last verified segment. RCA is captured per the corrective-action loop (`docs/governance/secure-development.md` §7).

## 7. Eradication & recovery — LG-IR-08

Recovery returns the agent to a known-good signed baseline before autonomy resumes; the agent stays halted and credentials cycle until baseline validation passes.

1. **Eradicate** the root cause (poisoned memory/skill, rogue MCP entry, offensive skill, injection-bearing artifact); purge poisoned state (secure purge, LG-MC-06); confirm godmode disabled and the allowlist enforced.
2. **Restore to baseline** — check out the last signed tag (`gov-P<N>-good`, recorded in `docs/governance/authorization-record.yaml`); re-apply the version-controlled overlay; restore a clean checkpoint.
3. **Rotate** all in-scope secrets.
4. **Re-verify** — `verify_chain()` PASS **and** the control-effectiveness verifier (LG-MO-08) green (godmode disabled, allowlists, encryption, posture=strict, baseline match).
5. **Re-enable autonomy (the single gated action)** — `agent.killswitch.recover_and_reenable(baseline_tag, actor, verify_ok=<verify_chain PASS>)`. This is **fail-closed**: a broken chain (`verify_ok=False`) keeps the halt; a clean chain clears the halt + containment **entirely**, restoring full capability with no residue. The re-enable is an Authorizing-Official decision recorded to the ledger (`killswitch.activate` / recover).

**Evidence:** Recovery-to-Baseline Record (restored checkpoint id, memory-purge log, rotated-credential IDs, passing chain-integrity + effectiveness report, autonomy re-enable approval).

## 8. Reporting & timelines — LG-IR-06 / LG-IR-09

| Obligation | Trigger | Timeline | Path |
|---|---|---|---|
| **DFARS 252.204-7012 cyber incident report** | A cyber incident affecting CUI (exfil, action on CUI, audit tamper with CUI nexus). | **Within 72 hours** of discovery, to **DoD via DIBNet** (medium-assurance cert). | Reporting POC files; ISSO validates. |
| **Agency / CAIO notification** | Any SEV-1/SEV-2; any high-impact-AI adverse event (M-25-21). | ≤ 24h internal; concurrent with DIBNet for CUI. | CAIO. |
| **Privacy / PII breach** | PII confirmed in the exposure. | Per agency privacy policy. | Legal-Privacy POC. |
| **Recovery communication (LG-IR-09)** | Containment, recovery, re-enable. | On each state change. | Stakeholder comms; each notification (recipient, timestamp, content hash) recorded to the ledger. |

Preserve evidence regardless of the reporting decision (DFARS media-preservation / ≥ 90-day retention — satisfied by the §6 evidence bundle in the path-confined evidence root).

## 9. Scheduled kill-switch test (LG-RM-09 / the FINAL-gate requirement)

A scheduled kill-switch drill (P5.3 test corpus `tests/governance/test_p53_killswitch.py`; recurring on the assurance cron) proves the cycle **halts then cleanly restores full capability**: engage → confirm tool + inference halted → recover with `verify_ok=True` → confirm full capability restored with **no lingering halt or false auto-suspension on steady state**. A recovery attempt with `verify_ok=False` must keep the halt (fail-closed).

## 10. Control-coverage map

| Control | Realization |
|---|---|
| LG-IR-01 kill-switch (tool + inference halt) | `agent/killswitch.py` wired at `predispatch_gate` + `resolve_runtime_provider` |
| LG-IR-02 containment (tool-class disable / HITL / revoke) | `killswitch.engage(contain_classes=...)`, `deny_on_no_approver`, `secrets_cli`, allowlist drop |
| LG-IR-03 circuit-breaker / net disconnect | breaker → `killswitch.engage` + egress deny-all |
| LG-IR-04 forensic preservation + custody | copy-only snapshot to path-confined evidence root; SHA-256 custody stamp |
| LG-IR-05 runbook + severity triage | §3 severity matrix; §5 selection table |
| LG-IR-06 external reporting (DFARS 72h) | §8 reporting matrix |
| LG-IR-07 reconstruction / RCA | `verify_chain()` + trajectory join |
| LG-IR-08 recovery to signed baseline | `killswitch.recover_and_reenable` fail-closed on chain break |
| LG-IR-09 recovery communication | §8 stakeholder comms; ledger-recorded notifications |
| LG-RM-09 documented, tested fail-safe | this plan + `halt-rollback-runbook.md` + the P5.3 drill |

---

*Built on Hermes Agent (Nous Research, MIT). Governance overlay is additive and capability-preserving.*
