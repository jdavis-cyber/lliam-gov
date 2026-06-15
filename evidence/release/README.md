# Lliam-GOV — deployable-release evidence package (AI-338)

Auditor-readable index for treating Lliam-GOV as a **governed deployable AI
application**, not just a local demo build. This is the AEP-style evidence
overlay for a *release* (the existing `evidence/phase5/aep/` covers the
audit-log AEP; this package references and extends it).

> **Status: scaffold / draft.** The structure and collection rules are defined
> and wired; several artifacts are **PENDING** the decision-gated work
> (signing certs, GitHub Actions, real-machine QA). Run
> `python3 scripts/collect-release-evidence.py` to print the current
> PRESENT/PENDING manifest.

## Release under evidence

| Field | Value |
|---|---|
| Product | Lliam-GOV desktop (multi-provider, CLI-backed inference) |
| Desktop app version | `0.15.1` (`apps/desktop/package.json`) |
| Epic | [AI-326] Ship Lliam-GOV as a deployable multi-provider desktop app |
| Foundation | PR #47 (desktop app + provider picker) |
| Provider families | Claude Code CLI, Codex CLI, Gemini/Antigravity CLI |

## Evidence inventory (required for a governed release)

| # | Evidence artifact | Stable path | Status |
|---|---|---|---|
| 1 | Threat model (provider boundary, T1–T8) | `docs/governance/provider-boundary-threat-model.md` | ✅ present (AI-334, PR #59) |
| 2 | Architecture / data-flow + provider-boundary notes | `docs/governance/provider-boundary-threat-model.md` §2, `docs/operate/managed-backend-bootstrap.md` | ✅ present (AI-334/AI-330) |
| 3 | SBOMs (CycloneDX, Python + Node) | `evidence/sbom/cyclonedx-*.json` | ✅ present |
| 4 | Dependency review + audit policy | `evidence/sbom/dependency-review-2026-06-12.md`, `docs/governance/dependency-audit-policy.md` | ✅ present (AI-337, PR #62) |
| 5 | Signing / notarization records | `evidence/release/signing/` | ⛔ **PENDING certs** (AI-331; Jerome) |
| 6 | Artifact checksums (`SHA256SUMS`) | `evidence/release/checksums/` | ⛔ **PENDING build** (AI-331/332; Actions offline) |
| 7 | QA matrix + smoke results | `docs/operate/` + `evidence/release/qa/` | ⏳ **PENDING** (AI-335; Mac lane proven) |
| 8 | Release-readiness gate output | `scripts/release-readiness.py` (run at tag time) | ✅ present (AI-337) |
| 9 | Deployment-tier distinction + AIMS asset/control update | `evidence/release/deployment-tiers.md` | ✅ present (this PR) |
| 10 | Approved providers + obligations outside Lliam-GOV | `evidence/release/provider-approvals.md` | ✅ present (this PR) |
| 11 | Residual risks & accepted limitations | `evidence/release/residual-risks.md` | ✅ present (this PR) |
| 12 | Audit-log AEP (hash-chained) | `evidence/phase5/aep/`, `lliam_gov/security/aep_export.py` | ✅ present |

## Change provenance (PRs in this deployability epic)

| Issue | What | PR |
|---|---|---|
| AI-327/328/329 | Provider contract, adapters, first-run UX | #47–#57 |
| AI-334 | Provider subprocess/credential/logging boundary | #59 |
| AI-330 | Location-independent managed-backend bootstrap | #60 |
| AI-336 | Deployment / provider / troubleshooting docs | #61 |
| AI-337 | Repo hygiene + release-readiness gates | #62 |
| AI-338 | This evidence package | (this PR) |

## How this package is collected

`scripts/collect-release-evidence.py` walks the inventory above, checks each
stable path, and emits:

- a human summary (PRESENT / PENDING per item), and
- `evidence/release/manifest.json` — a machine-readable snapshot with SHA-256
  of each present artifact, suitable for attaching to a release tag and for the
  governance overlay.

It deliberately **does not fabricate** pending artifacts — signing records,
checksums, and QA results stay PENDING until the gating work lands, so the
manifest always reflects true release readiness.

## Decision-gated to "complete"

Items 5, 6, 7 cannot be finalized here:
- **Signing/notarization** — Apple Developer ID + Windows Authenticode certs (Jerome).
- **Checksums / provenance** — require a real CI build; **GitHub Actions offline** until next month (AI-332).
- **QA matrix results** — AI-335 (Mac lane proven; Windows blocked on parked posture-guard).
- **Backend-distribution source** decision feeds the update-trust evidence.

See `residual-risks.md` for the accepted-limitations register.
