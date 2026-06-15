# Managed backend bootstrap — marker & install-stamp semantics (AI-330)

How a packaged Lliam-GOV desktop app finds, bootstraps, and trusts its Python
backend — and why the app bundle is safe to move to `/Applications`.

## Two locations, deliberately separate

| Concept | Where | Lifecycle |
|---|---|---|
| **App bundle** | wherever the user put it (`/Applications/Lliam-GOV.app`, a download folder, a dev `apps/desktop/release/…`) | disposable; may move; replaced by updates |
| **HERMES_HOME** | user home: `~/.lliam-gov` (macOS/Linux) / `%LOCALAPPDATA%\lliam-gov` (Windows) | persistent user data root |
| **Managed backend root** | `HERMES_HOME/lliam-gov` (`resolveManagedBackendRoot(HERMES_HOME)`) | the canonical mutable backend install |

The managed backend root is derived **only** from `HERMES_HOME`, never from the
app bundle path. Moving the bundle therefore cannot change where the backend
lives or whether it is bootstrapped — that is the location-independence
guarantee. (`apps/desktop/electron/bootstrap-marker.cjs`,
`bootstrap-marker.test.cjs`.)

## Backend resolution order (`resolveHermesBackend`)

1. `HERMES_DESKTOP_HERMES_ROOT` override → a developer checkout (no bootstrap).
2. **Local source root** — only when launched from a checkout ancestor (dev
   server, or a packaged app still sitting under the repo during local testing).
   A bundle copied to `/Applications` has no such ancestor and falls through.
3. **Bootstrap-complete managed root** — `isBootstrapComplete()` true → spawn
   the managed backend directly.
4. Existing `lliam-gov` CLI on PATH (used, but not "owned" — no marker written).
5. pip-installed `hermes_cli` via system Python (likewise not owned).
6. Otherwise → `bootstrap-needed` sentinel → the bootstrap runner installs.

Steps 1–2 keep **developer checkout behavior** working; steps 3–6 are the
packaged/managed path.

## Install stamp (`APP_ROOT/build/install-stamp.json`, schema v1)

Written at build time. Pins the commit/branch the app was built and tested
against:

```json
{ "schemaVersion": 1, "commit": "<sha>", "branch": "<name>", "source": "...", "dirty": false }
```

The bootstrap runner passes this pin to `install.sh` / `install.ps1`
(`-Commit` / `--commit`) so first launch clones the **exact** ref the binary was
tested with, not a moving branch tip.

## Bootstrap-complete marker (`<managed root>/.lliam-gov-bootstrap-complete`, schema v1)

```json
{
  "schemaVersion": 1,
  "pinnedCommit": "<7..40 hex sha>",
  "pinnedBranch": "<branch>|null",
  "completedAt": "<ISO 8601>",
  "desktopVersion": "<app version>"
}
```

`isBootstrapComplete()` trusts the managed backend iff:

- the marker validates (`validateMarker`: right schema + plausible `pinnedCommit`), **and**
- a runnable venv exists (`HERMES_HOME/lliam-gov/venv`). An interrupted install
  can leave a marker without a venv; requiring the venv forces a repair instead
  of spawning a dead backend.

### Staleness is informational, not blocking

The marker attests "bootstrap succeeded at least once" — it is **not** re-checked
against the live HEAD, because users update via the in-app update path or
`lliam-gov update`, which legitimately move HEAD. When the marker's
`pinnedCommit` differs from the current build's install stamp, the backend is
classified **stale** but still runs; the app logs "update available". States:

| `classifyBackend` | Meaning | Runnable? |
|---|---|---|
| `missing` | no/unreadable marker | no → bootstrap |
| `wrong-schema` | unknown schema version | no → bootstrap |
| `invalid` | malformed `pinnedCommit` | no → bootstrap |
| `no-venv` | valid marker, venv absent | no → repair |
| `stale` | valid + venv, commit ≠ stamp | **yes** (update available) |
| `ready` | valid + venv, matches stamp / no stamp | **yes** |

## First-launch bootstrap source — FLAG (Jerome's decision)

The bootstrap runner currently fetches the installer at the pinned SHA from
**`raw.githubusercontent.com/jdavis-cyber/lliam-gov/<sha>/scripts/…`**, with a
fallback to an already-installed agent checkout. The **backend-distribution
source** for a private/production release — signed GitHub Releases vs a
self-hosted artifact host — is **undecided** and intersects the egress
allowlist. This module is source-agnostic; only the URL/verification in
`bootstrap-runner.cjs::downloadInstallScript` changes once that call is made.
Signature/checksum verification of the fetched installer is **pending** that
decision plus signing certs (AI-331).

## Test coverage

- `bootstrap-marker.test.cjs` (21): location-independence of the managed root,
  marker validation, staleness vs stamp, classification (missing / wrong-schema
  / invalid / no-venv / stale / ready), payload round-trip.
- `bootstrap-runner.test.cjs`: installer resolution (local → cache → download →
  installed-agent fallback), stage dispatch, cancellation.
- **Pending real-machine verification** (tracked in AI-335 QA matrix):
  packaged-from-repo, packaged-moved-to-`/Applications` on a clean account,
  missing/stale backend, failed bootstrap. Mac lane is the proven path; Windows
  lane is blocked on the parked posture-guard work.
