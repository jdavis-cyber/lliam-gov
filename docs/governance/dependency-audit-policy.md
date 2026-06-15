# Dependency audit policy — Python & Node (AI-337)

How Lliam-GOV reviews, accepts, and documents third-party dependency risk for a
deployable release. Pairs with the supply-chain evidence in `evidence/sbom/`.

## Scope & tooling

| Ecosystem | Manifest / lock | Audit tool | Cadence |
|---|---|---|---|
| Python | `pyproject.toml` / `uv.lock` | `uv pip audit` (OSV) + CycloneDX SBOM | per release + on dependency bump |
| Node (root) | `package.json` / `package-lock.json` | `npm audit --workspaces=false` | per release + on bump |
| Node (desktop) | `apps/desktop/package.json` | `npm audit` in `apps/desktop` | per release + on bump |
| Node (web / tui) | workspace manifests | `npm run audit:web` / `audit:tui` | per release |

SBOMs (CycloneDX) for Python and Node are generated into `evidence/sbom/` and
attached to the release evidence package (AI-338).

## Severity policy

| Severity | Action |
|---|---|
| Critical / High | **Block release** until fixed, upgraded, or granted a documented, time-boxed exception (below). |
| Moderate | Fix within the next release cycle; document if carried. |
| Low / informational | Track; batch-fix on the next dependency bump. |

A finding is only "fixed" when the lockfile is updated and re-audited clean.

## Exceptions register

Any High/Critical carried into a release MUST have an entry here with an owner
and an expiry. No silent waivers.

| ID | Package / advisory | Severity | Reason carried | Owner | Expires | Evidence |
|---|---|---|---|---|---|---|
| _none open_ | — | — | — | — | — | — |

> Historical residual-risk notes live under `evidence/sbom/` (e.g.
> `dependency-residual-2026-06-12-ai321.md`). New exceptions are added here AND
> cross-referenced from the release evidence package.

## Owners

| Surface | Owner |
|---|---|
| Python deps / `uv.lock` | @jdavis-cyber |
| Node deps (root/desktop/web/tui) | @jdavis-cyber |
| SBOM generation & evidence | @jdavis-cyber |
| Exception approval | @jdavis-cyber |

## Automation status — FLAG

Continuous audit workflows exist (`.github/workflows/osv-scanner.yml`,
`supply-chain-audit.yml`) but **GitHub Actions is offline until next month**, so
audits are currently run **locally** as part of release readiness. Re-enable the
workflows as the enforcing gate once Actions is restored.
