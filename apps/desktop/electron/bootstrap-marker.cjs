'use strict'

/**
 * bootstrap-marker.cjs (AI-330)
 *
 * Pure, Electron-free helpers for the managed-backend bootstrap boundary so the
 * marker + install-stamp semantics are independently unit-testable (main.cjs
 * delegates to these and adds the Electron/fs glue).
 *
 * Two location concepts:
 *   - The packaged app bundle lives wherever the user put it (e.g.
 *     /Applications/Lliam-GOV.app). It is disposable and may move.
 *   - The MANAGED BACKEND ROOT is derived ONLY from HERMES_HOME (the user's
 *     Lliam-GOV home), never from the app bundle path. That is what makes the
 *     app location-independent: moving the bundle does not change where the
 *     backend lives or whether it is bootstrapped.
 *
 * Marker schema (version 1) — written under <managed root>/.lliam-gov-bootstrap-complete:
 *   {
 *     schemaVersion: 1,
 *     pinnedCommit:  "<7..40 hex SHA>",   // commit install.* was driven against
 *     pinnedBranch:  "<branch>" | null,
 *     completedAt:   "<ISO 8601>",
 *     desktopVersion:"<app version>"      // forensics only
 *   }
 */

const path = require('node:path')

const MARKER_SCHEMA_VERSION = 1
const MIN_COMMIT_LEN = 7

/**
 * Resolve the managed backend root from HERMES_HOME alone. Location-independent
 * by construction: identical regardless of where the app bundle sits.
 */
function resolveManagedBackendRoot(hermesHome) {
  if (!hermesHome) throw new Error('resolveManagedBackendRoot: hermesHome is required')
  return path.join(hermesHome, 'lliam-gov')
}

/** Absolute path of the bootstrap-complete marker for a managed root. */
function markerPathFor(managedRoot) {
  return path.join(managedRoot, '.lliam-gov-bootstrap-complete')
}

/**
 * Validate a parsed marker object against the current schema. Pure boolean —
 * matches the historical inline check in main.cjs exactly (schema version +
 * a plausible pinnedCommit). Does NOT check the venv (that's an fs concern the
 * caller layers on) or commit freshness (see classifyBackend / staleness).
 */
function validateMarker(marker, schemaVersion = MARKER_SCHEMA_VERSION) {
  if (!marker || typeof marker !== 'object') return false
  if (marker.schemaVersion !== schemaVersion) return false
  if (typeof marker.pinnedCommit !== 'string' || marker.pinnedCommit.length < MIN_COMMIT_LEN) {
    return false
  }
  return true
}

/**
 * Is the marker valid but pinned to a different commit than the install stamp
 * the current app build expects? "Stale" is informational: by design the app
 * still runs a stale-but-valid managed backend (users update via in-app update
 * / `lliam-gov update`, which legitimately moves HEAD). Surfacing it lets the
 * UI/logs explain "an update is available" and lets tests assert the case.
 */
function isMarkerStale(marker, installStamp) {
  if (!validateMarker(marker)) return false
  if (!installStamp || !installStamp.commit) return false
  return marker.pinnedCommit !== installStamp.commit
}

/**
 * Classify the managed backend into a single state for resolution/diagnostics.
 *
 * @returns one of:
 *   'missing'     — no marker / unreadable
 *   'wrong-schema'— marker present but a schema version we don't understand
 *   'invalid'     — marker present, right schema, but malformed pinnedCommit
 *   'no-venv'     — marker valid but the runnable venv is absent (needs repair)
 *   'stale'       — valid + venv, but pinned to a different commit than the stamp
 *   'ready'       — valid + venv + (matches stamp or no stamp to compare)
 */
function classifyBackend({ marker, installStamp = null, hasVenv = true, schemaVersion = MARKER_SCHEMA_VERSION } = {}) {
  if (!marker || typeof marker !== 'object') return 'missing'
  if (marker.schemaVersion !== schemaVersion) return 'wrong-schema'
  if (typeof marker.pinnedCommit !== 'string' || marker.pinnedCommit.length < MIN_COMMIT_LEN) {
    return 'invalid'
  }
  if (!hasVenv) return 'no-venv'
  if (installStamp && installStamp.commit && marker.pinnedCommit !== installStamp.commit) {
    return 'stale'
  }
  return 'ready'
}

/** A managed backend is runnable (skip bootstrap) iff classify says ready or stale. */
function isRunnable(state) {
  return state === 'ready' || state === 'stale'
}

/** Build the marker payload to persist after a successful bootstrap. */
function buildMarkerPayload({ pinnedCommit = null, pinnedBranch = null, desktopVersion = null, now = null } = {}) {
  return {
    schemaVersion: MARKER_SCHEMA_VERSION,
    pinnedCommit: pinnedCommit || null,
    pinnedBranch: pinnedBranch || null,
    completedAt: now || new Date().toISOString(),
    desktopVersion: desktopVersion || null
  }
}

module.exports = {
  MARKER_SCHEMA_VERSION,
  MIN_COMMIT_LEN,
  resolveManagedBackendRoot,
  markerPathFor,
  validateMarker,
  isMarkerStale,
  classifyBackend,
  isRunnable,
  buildMarkerPayload
}
