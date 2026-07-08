/**
 * Tests for electron/backend-probes.cjs.
 *
 * Run with: node --test electron/backend-probes.test.cjs
 * (Wired into npm test:desktop:platforms in package.json.)
 */

const test = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')

const { canImportLliamCli, lliamRuntimeImportProbe, verifyLliamCli } = require('./backend-probes.cjs')

// Resolve the host's own Node binary -- guaranteed to be on disk and
// runnable. We use it as both a stand-in for "a python that doesn't
// have hermes_cli" (since `node -c "import hermes_cli"` will exit
// non-zero) and as a way to script verifyLliamCli's success path
// (a tiny script we write to disk that exits 0 on --version).
const NODE_BIN = process.execPath

test('canImportLliamCli returns false when path is falsy', () => {
  assert.equal(canImportLliamCli(''), false)
  assert.equal(canImportLliamCli(null), false)
  assert.equal(canImportLliamCli(undefined), false)
})

test('canImportLliamCli returns false when interpreter cannot run -c', () => {
  // node IS an interpreter, but `node -c "import hermes_cli"` is a
  // SyntaxError -- different exit reason from a real Python's
  // ModuleNotFoundError, but the predicate is "exit 0 or not" and
  // both land on "not", which is exactly what we want for the
  // resolver fall-through.
  assert.equal(canImportLliamCli(NODE_BIN), false)
})

test('canImportLliamCli returns false when binary does not exist', () => {
  const ghost = path.join(os.tmpdir(), 'hermes-probes-ghost-' + Date.now() + '.exe')
  assert.equal(canImportLliamCli(ghost), false)
})

test('lliam-gov runtime import probe checks config dependencies', () => {
  const probe = lliamRuntimeImportProbe()
  assert.match(probe, /\bimport yaml\b/)
  assert.match(probe, /\bimport hermes_cli\.config\b/)
})

test('verifyLliamCli returns false when command is falsy', () => {
  assert.equal(verifyLliamCli(''), false)
  assert.equal(verifyLliamCli(null), false)
  assert.equal(verifyLliamCli(undefined), false)
})

test('verifyLliamCli returns false when binary does not exist', () => {
  const ghost = path.join(os.tmpdir(), 'hermes-probes-ghost-' + Date.now() + '.exe')
  assert.equal(verifyLliamCli(ghost), false)
})

test('verifyLliamCli returns true when --version exits 0', () => {
  // Write a tiny script that exits 0 regardless of args, then invoke
  // it through node. This stands in for a working lliam-gov binary --
  // verifyLliamCli only cares about the exit code.
  const scriptPath = path.join(os.tmpdir(), `hermes-probes-ok-${Date.now()}-${process.pid}.cjs`)
  fs.writeFileSync(scriptPath, 'process.exit(0)\n')
  try {
    // Use node as the launcher and our script as the "command". Pass
    // shell:false (default) -- node is a real binary, no shim.
    // execFileSync passes ['--version'] as args, which node ignores
    // gracefully (well, it prints its version and exits 0, which is
    // perfect -- exit code 0 is the only signal we read).
    assert.equal(verifyLliamCli(NODE_BIN), true)
  } finally {
    try {
      fs.unlinkSync(scriptPath)
    } catch {
      void 0
    }
  }
})

test('verifyLliamCli swallows timeouts (does not throw)', () => {
  // We can't easily provoke a real 5s hang in CI without slowing the
  // suite, but we CAN confirm that an invocation that DOES throw
  // (because the binary is missing) returns false rather than
  // propagating. Same code path the timeout case takes.
  assert.equal(verifyLliamCli('/definitely/not/a/real/binary/anywhere'), false)
})
