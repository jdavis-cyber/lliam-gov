# Deployment tiers & AIMS scope (AI-338)

Distinguishes the deployment contexts so the AIMS asset inventory and control
matrix can treat them differently. A control that is "accepted risk" for a
personal demo may be "must-fix" for an enterprise deployment.

| Tier | Definition | Backend source | Signing | Posture | AIMS treatment |
|---|---|---|---|---|---|
| **T0 — Personal demo / eval** | Single operator on their own Mac, from source or an unsigned local build | dev checkout or local bootstrap | unsigned (right-click-open) | governed-demo profile (`~/.lliam-gov`, 0700) | In scope **today**; documented as demo install in the asset inventory |
| **T1 — Enterprise deployment candidate** | Distributed signed app to managed endpoints | **signed release source — DECISION PENDING** (Jerome) | Developer ID + Authenticode **PENDING certs** | full posture guard incl. Windows — **PENDING parked work** | Candidate; control matrix rows flagged "enterprise-gated" |
| **T2 — Katmai scoped deployment** | Any future Katmai-boundary use | per Katmai authorization | required | required + Katmai controls | **Not authorized**; placeholder pending Jerome's scoping decision |

## AIMS asset inventory deltas (proposed)

- Add Lliam-GOV **desktop app** as an asset distinct from the **backend/agent**
  and the **provider CLIs** (external, third-party, not Lliam-GOV assets).
- Tag each asset with its tier availability: backend + provider adapters are
  T0-ready; the **signed installer** is T1-gated; Katmai use is T2 (unauthorized).

## Control-matrix deltas (proposed)

The machine-readable matrix (`evidence/control-matrix.csv`) should gain a tier
column so a row can read "satisfied @T0, enterprise-gated @T1". Rows whose
evidence is decision-gated (signing, update-trust, Windows posture) are marked
**enterprise-gated** and cross-referenced to the owning Linear issue.

> This file is the **proposal**; applying the deltas into
> `evidence/control-matrix.csv` + the AIMS inventory is a governance edit that
> should land with Jerome's sign-off (the matrix already notes it is pending his
> written Phase-2 sign-off).

## Provider CLIs are not Lliam-GOV assets

Claude Code, Codex, and Gemini/Antigravity CLIs are **third-party tools the user
installs and authenticates**. They are out of the Lliam-GOV asset boundary; the
inventory lists them as *external dependencies with their own trust and update
lifecycle*. See `provider-approvals.md`.
