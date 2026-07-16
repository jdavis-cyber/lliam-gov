# Management Review & Continuous Re-Authorization (cATO) — Lliam-GOV

| Field | Value |
|---|---|
| Document | Management-review record + cATO re-authorization (LG-GV-07/08) |
| Owner | CAIO (chairs); ISSO (prepares input pack) |
| Classification | CUI//SP-PRIV (template — mark per instance) |
| Version | 1.0 · 2026-07-16 |
| Cadence | Quarterly + on any posture-break auto-suspend |

> **Purpose.** The management-review record that re-authorizes continued autonomous operation with a signed residual-risk sign-off (LG-GV-08), and the continuous-authorization (cATO) loop that ties re-authorization to ISCM telemetry with posture-break auto-suspend (LG-GV-07).

## 1. Continuous authorization loop (LG-GV-07)

The cATO evaluator (`agent/cato_loop.py`) consumes the recurring control-effectiveness result (`control_effectiveness.py`, LG-MO-08) and the runtime-monitor alerts (`agent/runtime_monitors.py`, LG-MO-01..06). On a **real posture-break** — a control-effectiveness failure (godmode re-enabled, allowlist off, encryption/audit/monitoring off, posture not strict) or a critical alert — it **auto-suspends** autonomy via the kill-switch (`agent/killswitch.py`, LG-IR-01) and flags that re-authorization is required. On steady state it is a **complete no-op** — no suspension on low/medium alert noise (no false auto-suspensions).

Re-enable after an auto-suspend follows the IR recovery path (LG-IR-08): `verify_chain()` PASS + control-effectiveness green + an Authorizing-Official decision recorded to the ledger.

## 2. Management review (LG-GV-08)

At each cadence the CAIO chairs a review using the input pack:

- Quality-objective metrics (`governance_metrics.py`, LG-MO-09) — event/severity counts, deny rate, alert counts.
- Control-effectiveness report (`control_effectiveness.py`, LG-MO-08).
- Scheduled red-team results (`scheduled_redteam.py`, LG-MO-07).
- Open POA&M items (`poam.yaml`, LG-RM-07); incidents (IR plan); advisories.
- The portable attestation export (`attestation_export.py`, LG-TP-07) for reciprocity.

The review records control effectiveness, incidents, corrective actions, and a **signed residual-risk acceptance** with an explicit **re-authorization decision** that updates `authorization-record.yaml` (LG-GV-06) — including refreshing the `expires` date. An overdue review or an expired authorization fails the startup gate closed (LG-GV-06).

## 3. Review record (current)

| Field | Value |
|---|---|
| Review date | 2026-07-16 (initial / baseline) |
| Chair | CAIO — jdavis@agency.mil |
| Control status | 188 controls: 188 Implemented · 0 Partial · 0 Planned (post-P5.4) — see `control-catalog.yaml` |
| Posture | Effective (control-effectiveness verifier green) |
| Open POA&M | POAM-FIPS, POAM-EGRESS-ENCLAVE (deployment-tier; interim compensating controls in force) |
| Incidents since last review | None (eval; no CUI in scope) |
| Residual-risk decision | Accepted for the authorized eval scope (per `ai-impact-assessment.md` §11) |
| Re-authorization | Continued — authorization `LG-ATO-2026-001` remains in force to its 2027-01-16 expiry |
| Next review | 2026-10-16 (quarterly) or on any auto-suspend |

---

*Built on Hermes Agent (Nous Research, MIT). Governance overlay is additive and capability-preserving.*
