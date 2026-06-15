'use strict'

const assert = require('node:assert/strict')
const test = require('node:test')

const {
  CHANNELS,
  DEFAULT_CHANNEL,
  resolveChannel,
  channelInfo,
  compareSemver,
  isUpdateOffered,
  verifyArtifactTrust,
} = require('./update-channels.cjs')

test('defines the four release channels', () => {
  assert.deepEqual(
    Object.keys(CHANNELS).sort(),
    ['beta', 'dev-local', 'emergency-rollback', 'stable']
  )
})

test('resolveChannel: dev when not packaged', () => {
  assert.equal(resolveChannel({ isPackaged: false }), 'dev-local')
})

test('resolveChannel: env override wins when valid', () => {
  assert.equal(resolveChannel({ env: { LLIAM_UPDATE_CHANNEL: 'beta' } }), 'beta')
})

test('resolveChannel: invalid override falls back to stable', () => {
  assert.equal(resolveChannel({ env: { LLIAM_UPDATE_CHANNEL: 'nope' } }), DEFAULT_CHANNEL)
})

test('resolveChannel: config channel honored', () => {
  assert.equal(resolveChannel({ config: { channel: 'emergency-rollback' } }), 'emergency-rollback')
})

test('compareSemver orders correctly', () => {
  assert.equal(compareSemver('1.0.0', '1.0.1'), -1)
  assert.equal(compareSemver('2.0.0', '1.9.9'), 1)
  assert.equal(compareSemver('1.2.3', '1.2.3'), 0)
  assert.equal(compareSemver('x', '1.0.0'), null)
})

test('stable offers only forward updates', () => {
  assert.equal(isUpdateOffered({ current: '1.0.0', candidate: '1.0.1', channel: 'stable' }), true)
  assert.equal(isUpdateOffered({ current: '1.0.1', candidate: '1.0.0', channel: 'stable' }), false)
  assert.equal(isUpdateOffered({ current: '1.0.0', candidate: '1.0.0', channel: 'stable' }), false)
})

test('dev-local never auto-updates', () => {
  assert.equal(isUpdateOffered({ current: '1.0.0', candidate: '9.9.9', channel: 'dev-local' }), false)
})

test('emergency-rollback allows downgrade', () => {
  assert.equal(isUpdateOffered({ current: '1.2.0', candidate: '1.1.0', channel: 'emergency-rollback' }), true)
})

test('verifyArtifactTrust fails closed without signature', () => {
  const r = verifyArtifactTrust({ channel: 'stable', hasSignature: false, checksumOk: true })
  assert.equal(r.trusted, false)
  assert.match(r.reason, /signature/)
})

test('verifyArtifactTrust fails closed without checksum', () => {
  const r = verifyArtifactTrust({ channel: 'stable', hasSignature: true, checksumOk: false })
  assert.equal(r.trusted, false)
  assert.match(r.reason, /checksum/)
})

test('verifyArtifactTrust passes when both present', () => {
  const r = verifyArtifactTrust({ channel: 'stable', hasSignature: true, checksumOk: true })
  assert.equal(r.trusted, true)
})

test('channelInfo returns null for unknown channel', () => {
  assert.equal(channelInfo('bogus'), null)
})
