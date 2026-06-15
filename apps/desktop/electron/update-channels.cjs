'use strict'

/**
 * update-channels.cjs (AI-333 scaffold)
 *
 * Pure, Electron-free release-channel + update-compatibility logic so the
 * channel model is unit-testable without booting Electron (main.cjs wires the
 * UI/IO around it). This is the SCAFFOLD: it defines channels, channel
 * resolution, version-compatibility, and rollback decisions. The actual
 * download + **source/signature verification** is deliberately NOT implemented
 * here — it depends on the backend-distribution-source decision (Jerome) and
 * signing certs (AI-331). See `verifyArtifactTrust` below, which is an explicit
 * stub that fails closed.
 */

const CHANNELS = Object.freeze({
  // Local developer build / checkout. Never auto-updates.
  'dev-local': { rank: 0, autoUpdate: false, requiresSignature: false },
  // Pre-release testing.
  beta: { rank: 1, autoUpdate: true, requiresSignature: true },
  // Default production channel.
  stable: { rank: 2, autoUpdate: true, requiresSignature: true },
  // Forced downgrade channel for incident response.
  'emergency-rollback': { rank: 3, autoUpdate: true, requiresSignature: true },
})

const DEFAULT_CHANNEL = 'stable'

/** Resolve the active channel from env/config, falling back to stable. */
function resolveChannel({ env = {}, config = {}, isPackaged = true } = {}) {
  const requested = env.LLIAM_UPDATE_CHANNEL || config.channel
  if (!isPackaged) return 'dev-local'
  if (requested && Object.prototype.hasOwnProperty.call(CHANNELS, requested)) {
    return requested
  }
  return DEFAULT_CHANNEL
}

function channelInfo(channel) {
  return CHANNELS[channel] || null
}

/** Minimal semver parse → [major, minor, patch]; ignores pre-release tags. */
function parseSemver(v) {
  const m = /^(\d+)\.(\d+)\.(\d+)/.exec(String(v || '').trim())
  if (!m) return null
  return [Number(m[1]), Number(m[2]), Number(m[3])]
}

/** -1 if a<b, 0 if equal, 1 if a>b; null if either unparseable. */
function compareSemver(a, b) {
  const pa = parseSemver(a)
  const pb = parseSemver(b)
  if (!pa || !pb) return null
  for (let i = 0; i < 3; i += 1) {
    if (pa[i] !== pb[i]) return pa[i] < pb[i] ? -1 : 1
  }
  return 0
}

/**
 * Decide whether `candidate` is an offer-able update over `current` on a
 * channel. Stable/beta only move forward; emergency-rollback permits a
 * *downgrade* (the whole point of an incident rollback).
 */
function isUpdateOffered({ current, candidate, channel }) {
  const cmp = compareSemver(current, candidate)
  if (cmp === null) return false
  if (channel === 'emergency-rollback') return cmp !== 0 // allow up or down
  if (channel === 'dev-local') return false // never auto-update dev
  return cmp < 0 // forward-only for beta/stable
}

/**
 * Trust gate for an update artifact. **Stub — fails closed.** Real
 * implementation requires the distribution-source decision + signing certs.
 * Returns { trusted:false, reason } until those land so no unsigned/unverified
 * artifact is ever applied.
 */
function verifyArtifactTrust({ channel, hasSignature = false, checksumOk = false } = {}) {
  const info = channelInfo(channel)
  if (!info) return { trusted: false, reason: 'unknown channel' }
  if (info.requiresSignature && !hasSignature) {
    return { trusted: false, reason: 'signature required but signing not yet provisioned (AI-331; certs pending)' }
  }
  if (!checksumOk) {
    return { trusted: false, reason: 'checksum not verified (release CI / SHA256SUMS pending — AI-332)' }
  }
  return { trusted: true, reason: 'ok' }
}

module.exports = {
  CHANNELS,
  DEFAULT_CHANNEL,
  resolveChannel,
  channelInfo,
  parseSemver,
  compareSemver,
  isUpdateOffered,
  verifyArtifactTrust,
}
