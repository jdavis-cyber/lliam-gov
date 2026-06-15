'use strict'

const assert = require('node:assert/strict')
const test = require('node:test')
const path = require('node:path')

const {
  MARKER_SCHEMA_VERSION,
  resolveManagedBackendRoot,
  markerPathFor,
  validateMarker,
  isMarkerStale,
  classifyBackend,
  isRunnable,
  buildMarkerPayload
} = require('./bootstrap-marker.cjs')

const SHA = 'a'.repeat(40)
const OTHER_SHA = 'b'.repeat(40)

function validMarker(extra = {}) {
  return {
    schemaVersion: MARKER_SCHEMA_VERSION,
    pinnedCommit: SHA,
    pinnedBranch: 'main',
    completedAt: '2026-06-15T00:00:00.000Z',
    desktopVersion: '1.2.3',
    ...extra
  }
}

// ── location-independence ─────────────────────────────────────────────────────
test('managed backend root depends only on HERMES_HOME, not the app bundle path', () => {
  const home = '/Users/x/.lliam-gov'
  const fromRepo = resolveManagedBackendRoot(home)
  const fromApplications = resolveManagedBackendRoot(home)
  // Same HERMES_HOME → same managed root regardless of where the app launched.
  assert.equal(fromRepo, fromApplications)
  assert.equal(fromRepo, path.join(home, 'lliam-gov'))
})

test('different HERMES_HOME yields different managed roots', () => {
  assert.notEqual(resolveManagedBackendRoot('/a'), resolveManagedBackendRoot('/b'))
})

test('resolveManagedBackendRoot requires hermesHome', () => {
  assert.throws(() => resolveManagedBackendRoot(''), /hermesHome is required/)
})

test('marker path sits inside the managed root', () => {
  const root = resolveManagedBackendRoot('/home/.lliam-gov')
  assert.equal(markerPathFor(root), path.join(root, '.lliam-gov-bootstrap-complete'))
})

// ── marker validation ─────────────────────────────────────────────────────────
test('validateMarker accepts a well-formed marker', () => {
  assert.equal(validateMarker(validMarker()), true)
})

test('validateMarker rejects missing / non-object', () => {
  assert.equal(validateMarker(null), false)
  assert.equal(validateMarker(undefined), false)
  assert.equal(validateMarker('nope'), false)
})

test('validateMarker rejects wrong schema version', () => {
  assert.equal(validateMarker(validMarker({ schemaVersion: 999 })), false)
})

test('validateMarker rejects short / non-string pinnedCommit', () => {
  assert.equal(validateMarker(validMarker({ pinnedCommit: 'abc' })), false)
  assert.equal(validateMarker(validMarker({ pinnedCommit: 1234567 })), false)
})

// ── staleness vs install stamp ────────────────────────────────────────────────
test('isMarkerStale true when marker commit differs from stamp', () => {
  assert.equal(isMarkerStale(validMarker(), { commit: OTHER_SHA }), true)
})

test('isMarkerStale false when commits match', () => {
  assert.equal(isMarkerStale(validMarker(), { commit: SHA }), false)
})

test('isMarkerStale false with no stamp (nothing to compare)', () => {
  assert.equal(isMarkerStale(validMarker(), null), false)
})

// ── classification (maps to AI-330 backend states) ────────────────────────────
test('classifyBackend: missing marker', () => {
  assert.equal(classifyBackend({ marker: null }), 'missing')
})

test('classifyBackend: wrong schema', () => {
  assert.equal(classifyBackend({ marker: validMarker({ schemaVersion: 2 }) }), 'wrong-schema')
})

test('classifyBackend: invalid pinnedCommit', () => {
  assert.equal(classifyBackend({ marker: validMarker({ pinnedCommit: 'x' }) }), 'invalid')
})

test('classifyBackend: valid marker but no venv → needs repair', () => {
  assert.equal(classifyBackend({ marker: validMarker(), hasVenv: false }), 'no-venv')
})

test('classifyBackend: stale (valid + venv, commit differs from stamp)', () => {
  const state = classifyBackend({ marker: validMarker(), installStamp: { commit: OTHER_SHA }, hasVenv: true })
  assert.equal(state, 'stale')
  assert.equal(isRunnable(state), true) // stale still runs (update via in-app path)
})

test('classifyBackend: ready (matches stamp)', () => {
  const state = classifyBackend({ marker: validMarker(), installStamp: { commit: SHA }, hasVenv: true })
  assert.equal(state, 'ready')
  assert.equal(isRunnable(state), true)
})

test('classifyBackend: ready when there is no stamp to compare', () => {
  assert.equal(classifyBackend({ marker: validMarker(), installStamp: null, hasVenv: true }), 'ready')
})

test('missing / no-venv are not runnable (force bootstrap/repair)', () => {
  assert.equal(isRunnable('missing'), false)
  assert.equal(isRunnable('no-venv'), false)
  assert.equal(isRunnable('invalid'), false)
})

// ── payload ───────────────────────────────────────────────────────────────────
test('buildMarkerPayload stamps current schema + provided fields', () => {
  const p = buildMarkerPayload({
    pinnedCommit: SHA,
    pinnedBranch: 'main',
    desktopVersion: '9.9.9',
    now: '2026-06-15T12:00:00.000Z'
  })
  assert.equal(p.schemaVersion, MARKER_SCHEMA_VERSION)
  assert.equal(p.pinnedCommit, SHA)
  assert.equal(p.pinnedBranch, 'main')
  assert.equal(p.desktopVersion, '9.9.9')
  assert.equal(p.completedAt, '2026-06-15T12:00:00.000Z')
  // Round-trips through validateMarker.
  assert.equal(validateMarker(p), true)
})

test('buildMarkerPayload tolerates missing fields (null, not undefined)', () => {
  const p = buildMarkerPayload({})
  assert.equal(p.pinnedCommit, null)
  assert.equal(p.pinnedBranch, null)
  assert.equal(typeof p.completedAt, 'string')
})
