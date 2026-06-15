# Packaging, signing, release CI & in-app update (AI-331 / AI-332 / AI-333)

Scaffold status for the three release-automation issues. Everything that can be
built **without** signing certs, GitHub Actions, or the backend-distribution
decision is in place; the hard dependencies are flagged per item. **No
architectural or procurement calls are made here.**

## AI-331 — Packaging & signing (mostly configured; cert-gated)

The electron-builder config already lives in `apps/desktop/package.json` `build`:

| Aspect | Present | Gated on |
|---|---|---|
| App identity | `appId com.jdaviscyber.lliam-gov`, `productName Lliam-GOV`, `executableName`, `icon` | — |
| Artifact naming | `Lliam-GOV-${version}-${os}-${arch}.${ext}` | — |
| macOS | `dmg`+`zip`, `hardenedRuntime: true`, entitlements, `afterSign` notarize hook | ⛔ **Apple Developer ID cert** (Jerome) |
| Windows | `nsis`+`msi`, metadata; `signAndEditExecutable: false` | ⛔ **Authenticode cert** (Jerome) |
| Linux | `AppImage`+`deb`+`rpm`, maintainer/category | — (artifacts unsigned by norm) |
| Install stamp | `extraResources` ships `build/install-stamp.json` | — |

**Remaining = certs only.** When certs exist: set `signAndEditExecutable: true`,
provide signing secrets (see CI), and the existing `notarize.cjs` hook completes
Developer ID notarization. `scripts/release-readiness.py` already warns while
signing is off.

## AI-332 — Release CI (scaffolded; Actions offline)

`.github/workflows/release.yml.disabled` is a ready-to-run matrix workflow
(macOS arm64/x64, Windows, Linux) that: installs deps, runs the scoped Python +
desktop platform tests + typecheck, runs the release-readiness gate, builds
artifacts via the existing electron-builder config, emits **SHA256SUMS** and
**CycloneDX SBOMs**, and uploads artifacts. Signing steps read `secrets.*` and
**degrade to unsigned** when secrets are absent (so it never hard-fails on
missing certs).

- **Activate** by renaming `release.yml.disabled` → `release.yml` once GitHub
  Actions is restored.
- **Publish** target (signed GitHub Release vs self-hosted) is a placeholder —
  it is the **backend-distribution-source decision (Jerome, AI-330)**.

## AI-333 — In-app update / rollback / channels (scaffolded logic)

`apps/desktop/electron/update-channels.cjs` (pure, unit-tested — 13 cases):

- **Channels:** `dev-local` (never auto-updates), `beta`, `stable`,
  `emergency-rollback`.
- **`resolveChannel`** from env (`LLIAM_UPDATE_CHANNEL`) / config / packaged-ness.
- **`isUpdateOffered`** — forward-only for beta/stable; `emergency-rollback`
  permits a **downgrade** (incident rollback).
- **`verifyArtifactTrust`** — **fails closed**: refuses any artifact without a
  signature (when the channel requires one) and without a verified checksum, so
  no unsigned/unverified update is ever applied.

What is intentionally NOT built (decision-gated):
- The actual **download + signature/checksum verification** implementation —
  needs the distribution-source decision (AI-330) + signing certs (AI-331).
- The update **UI** (current/available version, channel, SHA display) wires
  these helpers into `main.cjs` + renderer — follow-up once trust is real.

## Decision-gated summary (owner: Jerome)

| Need | Blocks |
|---|---|
| Apple Developer ID + Windows Authenticode certs | AI-331 signing/notarization; trusted updates (AI-333) |
| GitHub Actions restoration | AI-332 release CI run, checksums/provenance, SBOM publication |
| Backend-distribution-source decision | release publish target (AI-332), update source (AI-333), egress allowlist (AI-330) |
