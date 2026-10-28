/**
 * Cross-checks every Python entry point the desktop shell invokes against the
 * agent source tree in this repo.
 *
 * Run with: node --test electron/lliam-cli-entrypoints.test.cjs
 * (Wired into npm test:desktop:platforms in package.json.)
 *
 * The Python package was renamed hermes_cli -> lliam_cli. The desktop calls it
 * by module name in three places that only fail at runtime on a user's
 * machine, never at build time:
 *   - backend-probes.cjs: the system-Python fallback import probe
 *     (`python -c "import yaml; import lliam_cli.config"`)
 *   - desktop-uninstall.cjs: the uninstall cleanup script
 *     (`python -m lliam_cli.uninstall --mode <gui|lite|full>`)
 *   - main.cjs: the uninstall summary probe and its source-root fallback
 *     (`python -m lliam_cli.main uninstall --gui-summary`)
 * A stale module name there turns into a silent "ModuleNotFoundError" and a
 * fallback UI, so these tests resolve each name to a real file and check the
 * CLI contract the desktop relies on.
 */

const test = require('node:test')
const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')

const { lliamRuntimeImportProbe } = require('./backend-probes.cjs')
const { UNINSTALL_MODES, uninstallArgsForMode } = require('./desktop-uninstall.cjs')

const ELECTRON_DIR = __dirname
const DESKTOP_DIR = path.resolve(ELECTRON_DIR, '..')
const REPO_ROOT = path.resolve(DESKTOP_DIR, '..', '..')

function readText(file) {
  return fs.readFileSync(file, 'utf8').replace(/\r\n/g, '\n')
}

// Resolve a dotted Python module name to its source file in this repo.
function moduleSourceFile(dotted) {
  const base = path.join(REPO_ROOT, ...dotted.split('.'))
  const candidates = [`${base}.py`, path.join(base, '__init__.py')]
  const found = candidates.find(candidate => fs.existsSync(candidate))
  assert.ok(found, `module ${dotted} does not resolve to a source file under ${REPO_ROOT}`)
  return found
}

test('system-Python fallback probe imports modules that exist in the agent tree', () => {
  const probe = lliamRuntimeImportProbe()
  const imported = [...probe.matchAll(/\bimport\s+([\w.]+)/g)].map(match => match[1])

  assert.ok(imported.includes('lliam_cli.config'), `probe should import lliam_cli.config: ${probe}`)
  assert.ok(!imported.some(name => name.startsWith('hermes_cli')), `probe still imports hermes_cli: ${probe}`)

  for (const name of imported.filter(name => name.startsWith('lliam_cli'))) {
    moduleSourceFile(name)
  }
})

test('uninstall cleanup runs a module entrypoint that accepts every desktop mode', () => {
  for (const mode of UNINSTALL_MODES) {
    const args = uninstallArgsForMode(mode)
    assert.equal(args[0], '-m')
    assert.match(args[1], /^lliam_cli\./, `uninstall module for ${mode} is ${args[1]}`)

    const source = readText(moduleSourceFile(args[1]))
    assert.match(source, /^if __name__ == "__main__":/m, `${args[1]} must be runnable with python -m`)
    assert.deepEqual(args.slice(2), ['--mode', mode])
    const modeArg = /"--mode",\s*\n\s*choices=\[([^\]]*)\]/.exec(source)
    assert.ok(modeArg, `${args[1]} no longer declares --mode with explicit choices`)
    assert.match(modeArg[1], new RegExp(`"${mode}"`), `${args[1]} --mode does not accept ${mode}`)
  }
})

test('uninstall summary probe and its fallback point at the lliam_cli CLI', () => {
  const main = readText(path.join(ELECTRON_DIR, 'main.cjs'))

  const probe = /spawn\(\s*py,\s*\['-m', '([\w.]+)', 'uninstall', '--gui-summary'\]/.exec(main)
  assert.ok(probe, 'getUninstallSummary no longer spawns `-m <module> uninstall --gui-summary`')
  assert.equal(probe[1], 'lliam_cli.main')
  const cliSource = readText(moduleSourceFile(probe[1]))
  assert.match(cliSource, /def cmd_uninstall\(args\):[\s\S]*?getattr\(args, "gui_summary", False\)/)
  assert.match(readText(moduleSourceFile('lliam_cli.subcommands.uninstall')), /"--gui-summary"/)

  // The JS-side fallback reports agent_installed from isLliamSourceRoot();
  // with a stale package directory it would always report "not installed".
  const sourceRoot =
    /function isLliamSourceRoot\(root\) \{\n\s*return [^\n]*path\.join\(root, '(\w+)', '(\w+\.py)'\)/.exec(main)
  assert.ok(sourceRoot, 'isLliamSourceRoot no longer checks <root>/<package>/<file>.py')
  assert.equal(sourceRoot[1], 'lliam_cli')
  assert.ok(fs.existsSync(path.join(REPO_ROOT, sourceRoot[1], sourceRoot[2])))
})

test('desktop shell source has no hermes_cli module references left', () => {
  const stale = []
  const walk = dir => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      if (entry.name === 'node_modules' || entry.name === 'dist' || entry.name === 'release') continue
      const full = path.join(dir, entry.name)
      if (entry.isDirectory()) {
        walk(full)
      } else if (/\.(c?js|mjs|ts|tsx)$/.test(entry.name) && full !== __filename) {
        if (readText(full).includes('hermes_cli')) stale.push(path.relative(DESKTOP_DIR, full))
      }
    }
  }
  for (const dir of ['electron', 'scripts', 'src']) walk(path.join(DESKTOP_DIR, dir))

  assert.deepEqual(stale, [])
})
