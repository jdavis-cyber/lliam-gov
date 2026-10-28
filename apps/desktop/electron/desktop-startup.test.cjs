const test = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const vm = require('node:vm')
const { buildDesktopBackendPath, buildDesktopBackendEnv } = require('./backend-env.cjs')
const { canImportLliamCli, verifyLliamCli } = require('./backend-probes.cjs')
const { runBootstrap } = require('./bootstrap-runner.cjs')
const main = fs.readFileSync(path.join(__dirname, 'main.cjs'), 'utf8')

// Exercise the actual main-process functions without starting Electron windows.
function mainFunction(name, nextName, bindings) {
  const start = main.indexOf(`function ${name}(`)
  const end = main.indexOf(`function ${nextName}(`, start)
  const prefix = main.slice(start - 6, start) === 'async ' ? 'async ' : ''
  const body = prefix + main.slice(start, end).trim().replace(/async\s*$/, '')
  const context = vm.createContext(bindings)
  vm.runInContext(body, context)
  return context[name]
}

test('fresh Dock home matches the canonical CLI home and retains existing legacy homes', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lliam-home-'))
  try {
    const resolveHome = mainFunction('resolveLliamHome', 'lliamManagedNodePathEntries', {
      path, process: { env: {} }, IS_WINDOWS: false, USER_DATA_OVERRIDE: null,
      app: { getPath: () => home }, directoryExists: p => fs.existsSync(p)
    })
    assert.equal(resolveHome(), path.join(home, '.lliam'))
    fs.mkdirSync(path.join(home, '.hermes'))
    assert.equal(resolveHome(), path.join(home, '.hermes'))
  } finally {
    fs.rmSync(home, { recursive: true, force: true })
  }
})

test('Dock PATH resolves an executable in the user install directory', () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lliam dock '))
  try {
    const bin = path.join(home, '.local', 'bin')
    fs.mkdirSync(bin, { recursive: true })
    const cli = path.join(bin, 'lliam-gov')
    fs.writeFileSync(cli, '#!/bin/sh\ntest "$1" = --help\n', { mode: 0o755 })
    const findOnPath = mainFunction('findOnPath', 'isCommandScript', {
      path, buildDesktopBackendPath, HERMES_HOME: path.join(home, 'data'),
      VENV_ROOT: path.join(home, 'data', 'hermes-agent', 'venv'),
      app: { getPath: () => home }, process: { env: { PATH: '/usr/bin:/bin' } },
      IS_WINDOWS: false, IS_WSL: false, isWindowsBinaryPathInWsl: () => false,
      fileExists: p => fs.existsSync(p)
    })
    assert.equal(findOnPath('lliam-gov'), cli)
    assert.equal(verifyLliamCli(cli, { env: buildDesktopBackendEnv({ lliamHome: home }) }), true)
  } finally {
    fs.rmSync(home, { recursive: true, force: true })
  }
})

test('main bootstrap caller carries the selected home through real installer subprocesses', {
  skip: process.platform === 'win32'
}, async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lliam bootstrap '))
  const repo = path.join(home, 'source')
  try {
    fs.mkdirSync(path.join(repo, 'scripts'), { recursive: true })
    fs.writeFileSync(path.join(repo, 'scripts', 'install.sh'), `#!/bin/bash
set -eu
case "$1" in
 --manifest) echo '{"protocol_version":1,"stages":[{"name":"check","needs_user_input":false}]}' ;;
 --stage)
   test "$HERMES_HOME" = "$LLIAM_HOME"
   test -n "$LLIAM_HOME"
   printf '%s' "$LLIAM_HOME" > "$LLIAM_HOME/selected-home"
   echo '{"stage":"check","ok":true,"skipped":false}' ;;
esac
`)
    let marker
    const ensureRuntime = mainFunction('ensureRuntime', 'fetchJson', {
      path, HERMES_HOME: home, SOURCE_REPO_ROOT: repo, runBootstrap, AbortController,
      advanceBootProgress: async () => {}, rememberLog: () => {},
      handOffWindowsBootstrapRecovery: async () => false, broadcastBootstrapEvent: () => {},
      writeBootstrapMarker: payload => (marker = payload),
      resolveLliamBackend: () => ({ bootstrap: false, label: 'installed' }),
      applyWindowsNoConsoleSpawnHints: backend => backend
    })
    const backend = await ensureRuntime({
      bootstrap: true, kind: 'bootstrap-needed', activeRoot: path.join(home, 'hermes-agent'),
      installStamp: { commit: 'a'.repeat(40), branch: 'main' }, args: []
    })
    assert.equal(backend.label, 'installed')
    assert.equal(fs.readFileSync(path.join(home, 'selected-home'), 'utf8'), home)
    assert.equal(marker.pinnedCommit, 'a'.repeat(40))
  } finally {
    fs.rmSync(home, { recursive: true, force: true })
  }
})

const repoRoot = path.resolve(__dirname, '../../..')
const python = process.env.LLIAM_TEST_PYTHON || path.join(repoRoot, 'venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python')
test('runtime probe imports the installed renamed CLI with an isolated home', {
  skip: !fs.existsSync(python)
}, () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lliam-import-'))
  try {
    assert.equal(canImportLliamCli(python, {
      env: { HERMES_HOME: home, LLIAM_HOME: home, PYTHONPATH: repoRoot }
    }), true)
  } finally {
    fs.rmSync(home, { recursive: true, force: true })
  }
})
