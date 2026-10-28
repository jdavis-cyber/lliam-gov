# Autonomy Level & Intervention Tier Classification — Lliam-GOV

| Field | Value |
|---|---|
| Document | Autonomy (L0–L5) + Intervention-Tier (T1–T5) classification with kill-switch test cadence (LG-TP-05) |
| Owner | ISSO; Kill-Switch Owner |
| Classification | CUI//SP-PRIV (template — mark per instance) |
| Version | 1.0 · 2026-07-16 |
| Review-by | At each management review (LG-GV-08) |

> **Purpose.** Classifies the Lliam-GOV agent's authorized autonomy level and the human-intervention tiers that bound it, and sets the scheduled, recorded kill-switch test cadence (LG-TP-05). The classification is what an assessor uses to judge whether the human-oversight controls (HO domain) match the granted autonomy.

## 1. Autonomy levels (L0–L5)

| Level | Definition | Lliam-GOV posture |
|---|---|---|
| **L0** | No autonomy — human performs every action. | — |
| **L1** | Assisted — agent suggests, human executes. | — |
| **L2** | Supervised — agent executes low-risk reads; human approves any mutation. | Available (conservative mission profile) |
| **L3** | **Conditional autonomy — agent acts within a bounded envelope; high-impact/irreversible/egress actions require HITL.** | **Authorized operating level** (the graduated-enforcement model: allow reads → detect-and-log medium → HITL high-risk → deny excluded) |
| **L4** | High autonomy — agent acts unattended within scope; human intervenes on exception. | Not authorized for CUI without additional compensating controls |
| **L5** | Full autonomy — no routine human oversight. | **Prohibited** for a CUI-processing agent |

**Authorized level: L3.** The agent executes bounded work autonomously but every high-impact/irreversible/egress/spend/secret-access/computer-use action routes to an authenticated human approver (LG-HO-01, LG-GV-05); the non-interactive path is fail-closed deny (LG-HO-02). Raising the level requires a new impact determination (LG-RM-06) + CAIO authorization.

## 2. Intervention tiers (T1–T5)

| Tier | Intervention | Mechanism |
|---|---|---|
| **T1** | Observe — telemetry only, no action. | ISCM stream (LG-MO-05) + session risk timeline (LG-MO-06) |
| **T2** | Prompt — human approval required to proceed. | HITL approval gates (LG-HO-01) |
| **T3** | Constrain — contain named tool classes / force HITL mid-session. | `killswitch.engage(contain_classes=...)` (LG-IR-02) |
| **T4** | Halt — suspend all tool execution + inference. | Kill-switch (LG-IR-01, `agent/killswitch.py`) |
| **T5** | Recover — restore to a signed baseline before re-enable. | `killswitch.recover_and_reenable` fail-closed on chain break (LG-IR-08) |

Tier escalation is driven by severity (IR plan §3): SEV-3 → T2/T3, SEV-2 → T3/T4, SEV-1 → T4/T5. The cATO loop (LG-GV-07) auto-escalates to T4 on a real posture-break.

## 3. Scheduled kill-switch test cadence (LG-TP-05)

| Test | Cadence | Evidence |
|---|---|---|
| Kill-switch halt→clean-restore drill | Monthly (and on any control change) | `tests/governance/test_p53_killswitch.py` + the recorded drill on `scheduled_assurance_cron.sh` |
| Fail-closed recovery (broken chain keeps halt) | Monthly | P5.3 test corpus |
| No-false-suspension (steady-state no-op) | Monthly | P5.4 cATO steady-state test |

Each drill records: engage timestamp + actor, confirmation that tool execution and inference both halted, recovery with `verify_chain` PASS, and confirmation that **full capability was restored with no residue**. A failed drill is a nonconformity (corrective-action loop, `docs/governance/secure-development.md` §7).

---

*Built on Hermes Agent (Nous Research, MIT). Governance overlay is additive and capability-preserving.*
