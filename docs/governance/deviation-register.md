# Lliam-GOV — Deviation / Exception Register (LG-CH-08)

| Field | Value |
|---|---|
| Document | Deviation / Exception Register |
| Owner | Lliam-GOV Program |
| Classification | CUI//SP-PRIV (template — mark per instance) |
| Control | LG-CH-08 (require approval + record for any baseline deviation) |
| Status | 0.1 DRAFT |

The hardened gov baseline is **most-restrictive-config with documented
exceptions**. Any deviation from it — re-enabling a disabled toolset/skill, adding
a provider, loosening a fail-closed key, or any value that the baseline-drift gate
(LG-CH-03) or a CI governance gate would otherwise block — REQUIRES an approved,
recorded entry here **before** it takes effect. This preserves capability (a
sanctioned path to enable a mission feature) without weakening the baseline
silently. Every entry is also recorded into the hash-chained audit ledger once
Phase 1 lands (LG-HO-10).

## How to record a deviation
1. Add a row to the table below (and the machine-readable
   [`deviation-register.yaml`](deviation-register.yaml) consumed by the gates).
2. Bind an **authenticated approver** (a `dashboard_auth` principal once Phase 1
   is live; until then, the named ISSO/CAIO).
3. State the **exact config key / capability** it overrides, the **justification**,
   the **scope** (which profile — never the CUI profile for never-eligible items),
   and a hard **expiry** (re-review by date).
4. Re-run the affected gate to confirm the deviation is honored, and link any POA&M.

## Never eligible (no deviation may enable these for a CUI profile)
- `godmode` (jailbreak / safety-bypass) — **MANDATORY must-disable** (LG-SC-01)
- `obliteratus` (weight-abliteration / uncensoring) — **MANDATORY must-disable**
- `approvals.mode: off`, `HERMES_YOLO_MODE`, hardline/sudo-stdin blocks — terminal denies (LG-HO-03)

## Deviation log

| ID | Date | Overridden key / capability | Scope (profile) | Justification | Approver | Expiry | POA&M |
|---|---|---|---|---|---|---|---|
| — | 2026-06-30 | _none_ | — | _No deviations. Baseline is fully strict as of Phase 0 (P0.7)._ | — | — | — |

---
*Built on Hermes Agent (Nous Research, MIT). Governance overlay is additive and capability-preserving.*
