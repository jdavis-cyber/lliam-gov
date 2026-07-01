# Lliam-GOV — Dependency Change Record (LG-SS-01)

| Field | Value |
|---|---|
| Document | Dependency Change Record (pin bumps) |
| Owner | Lliam-GOV Program |
| Classification | CUI//SP-PRIV (template — mark per instance) |
| Control | LG-SS-01 (pin + hash verification; change-controlled pins) |

Any change to a pinned dependency — editing `pyproject.toml` and regenerating
`uv.lock` — MUST be recorded here before merge, with CODEOWNERS review on the gov
baseline branch. This is the auditable trail for why the supply-chain baseline
moved.

**How to record a pin bump**
1. Edit the pin in `pyproject.toml` (keep the `<next_major` upper bound).
2. Regenerate the hashed lock: `uv lock` (then verify `uv sync --locked`).
3. Add a row below: date, package, old→new version, reason (CVE/feature/compat),
   approver, and the OSV/`hermes security audit` result for the new version.
4. Re-run the supply-chain CI gate (upper-bound + audit) and confirm green.

| Date | Package | Old → New | Reason | Approver | OSV/audit result |
|---|---|---|---|---|---|
| 2026-06-30 | — | — | _Baseline established at P0.6: pyproject `==`/bounded pins + `uv.lock` (1798 sha256 hashes) committed as the pinned baseline. No bump — this row records the baseline._ | Lliam-GOV Program | clean (baseline) |
