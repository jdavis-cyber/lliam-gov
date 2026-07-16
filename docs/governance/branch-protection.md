# Branch Protection — `main` (LG-SD-04)

| Field | Value |
|---|---|
| Document | Branch-protection configuration of record (LG-SD-04) |
| Owner | ISSO (`governance.role_bindings.isso`) |
| Repo | `jdavis-cyber/lliam-gov` |
| Version | 1.0 · 2026-07-16 |

> Branch protection is a GitHub server-side setting, not a repo file; this document is the configuration of record and the evidence artifact. It pairs with `.github/CODEOWNERS` to enforce peer review + independent challenge on governance-sensitive changes.

## Required settings on `main`

| Setting | Value | Rationale |
|---|---|---|
| Require a pull request before merging | On | No direct pushes to `main` (all hardening lands via one PR per phase) |
| Require review from Code Owners | On | LG-SD-04 — governance-config/skill/prompt/policy changes reviewed by the owner |
| Required approving reviews | ≥ 1 | Peer review; independent challenge (auditor role) on high-impact governance changes |
| Dismiss stale approvals on new commits | On | Re-review after post-review changes |
| Require status checks to pass | On (when CI credits available) | The governance gate battery must be green |
| Require branches up to date before merging | On | Merge against current baseline |
| Require signed commits | Recommended | Author attribution integrity |
| Include administrators | On | The owner is not exempt from review |
| Restrict who can push | Owner only | Least privilege on the protected branch |

## Local gate battery (the CI substitute — no CI credits, July 2026)

Because GitHub Actions do not run on PRs for this repo, the required-status-check
role is fulfilled by running the full gate battery locally before every push
(recorded in each phase's verification report):

- `scripts/run_tests_parallel.py` (full suite, isolated per file; diffed vs the
  characterized 60-fail/21-file noise floor)
- `ci/governance-ci-gates/`: `audit_chain_selftest.py`, `sod_check.py`,
  `baseline_drift_gate.py`, `supply_chain_gate.py`, `prohibited_skills_gate.sh`,
  `regulatory_reconciliation_gate.py`, `soa_gate.py`,
  `ssp_reconciliation_gate.py`, `fairness_gate.py`, `go_no_go_gate.py`, and
  `path_freeze_gate.py --base gov-P<N-1>-good --head HEAD`

When CI credits are restored, `.github/workflows/governance-gates.yml` runs the
same battery as required status checks.
