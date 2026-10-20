'use strict'

const assert = require('node:assert/strict')
const test = require('node:test')

const { execFileSync } = require('node:child_process')
const fs = require('node:fs/promises')
const os = require('node:os')
const path = require('node:path')

const { repoStatus, resolveRenamePath } = require('./git-review-ops.cjs')

test('resolveRenamePath: plain path is unchanged', () => {
  assert.equal(resolveRenamePath('src/a.ts'), 'src/a.ts')
})

test('resolveRenamePath: simple rename resolves to the new path', () => {
  assert.equal(resolveRenamePath('old.ts => new.ts'), 'new.ts')
})

test('resolveRenamePath: brace rename resolves to the new path', () => {
  assert.equal(resolveRenamePath('src/{old => new}/file.ts'), 'src/new/file.ts')
})

test('resolveRenamePath: brace rename collapsing a segment', () => {
  assert.equal(resolveRenamePath('src/{lib => }/file.ts'), 'src/file.ts')
})


test('repoStatus reads a real repository through the patched Git client', async t => {
  const cwd = await fs.mkdtemp(path.join(os.tmpdir(), 'lliam-git-security-'))
  t.after(() => fs.rm(cwd, { recursive: true, force: true }))
  execFileSync('git', ['-c', 'init.templateDir=', 'init', '--quiet'], {
    cwd,
    env: { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1' }
  })
  await fs.writeFile(path.join(cwd, 'example.txt'), 'local regression fixture\n', 'utf8')
  const status = await repoStatus(cwd)
  assert.ok(status, 'Git status should remain available after the security update')
  assert.equal(status.untracked, 1)
  assert.ok(status.files.some(file => file.path === 'example.txt'))
})
