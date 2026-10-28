'use strict'

const assert = require('node:assert/strict')
const test = require('node:test')

const { execFileSync } = require('node:child_process')
const fs = require('node:fs/promises')
const os = require('node:os')
const path = require('node:path')

const { fileDiffVsHead, parseStatusV2, repoStatus, sumNumstat } = require('./git-status-ops.cjs')

const GIT_ENV = { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1' }

function git(cwd, ...args) {
  return execFileSync(
    'git',
    ['-c', 'init.templateDir=', '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', ...args],
    { cwd, env: GIT_ENV, encoding: 'utf8' }
  )
}

async function tempRepo(t, { branch = 'main' } = {}) {
  const cwd = await fs.mkdtemp(path.join(os.tmpdir(), 'lliam-git-status-'))
  t.after(() => fs.rm(cwd, { recursive: true, force: true }))
  git(cwd, 'init', '--quiet', '-b', branch)

  return cwd
}

async function commitFile(cwd, name, content, message = `add ${name}`) {
  await fs.writeFile(path.join(cwd, name), content, 'utf8')
  git(cwd, 'add', '--', name)
  git(cwd, 'commit', '--quiet', '-m', message)
}

test('parseStatusV2 reads branch headers, ordinary, rename, unmerged and untracked records', () => {
  const out = [
    '# branch.oid 0123456789abcdef0123456789abcdef01234567',
    '# branch.head feature/x',
    '# branch.upstream origin/feature/x',
    '# branch.ab +2 -3',
    '1 .M N... 100644 100644 100644 aaaa bbbb src/a file.ts',
    '2 R. N... 100644 100644 100644 aaaa bbbb R100 new name.ts',
    'old name.ts',
    'u UU N... 100644 100644 100644 100644 aaaa bbbb cccc conflict.ts',
    '? untracked dir/new.ts',
    ''
  ].join('\0')

  assert.deepEqual(parseStatusV2(out), {
    head: 'feature/x',
    upstream: 'origin/feature/x',
    ahead: 2,
    behind: 3,
    files: [
      { path: 'src/a file.ts', index: ' ', workingDir: 'M', unmerged: false },
      { path: 'new name.ts', index: 'R', workingDir: ' ', unmerged: false },
      { path: 'conflict.ts', index: 'U', workingDir: 'U', unmerged: true },
      { path: 'untracked dir/new.ts', index: '?', workingDir: '?', unmerged: false }
    ]
  })
})

test('sumNumstat totals text changes and counts binary files as zero', () => {
  assert.deepEqual(sumNumstat('3\t1\ta.ts\n-\t-\timage.png\n10\t0\tsrc/{old => new}.ts\n'), { added: 13, removed: 1 })
  assert.deepEqual(sumNumstat(''), { added: 0, removed: 0 })
})

test('repoStatus reads a fresh repository with only untracked files', async t => {
  const cwd = await tempRepo(t)
  await fs.writeFile(path.join(cwd, 'example.txt'), 'local regression fixture\n', 'utf8')

  const status = await repoStatus(cwd)

  assert.ok(status, 'git status should be available for a fresh repository')
  assert.equal(status.branch, 'main')
  assert.equal(status.detached, false)
  assert.equal(status.untracked, 1)
  assert.equal(status.changed, 1)
  assert.equal(status.added, 1)
  assert.deepEqual(status.files, [
    { path: 'example.txt', staged: false, unstaged: false, untracked: true, conflicted: false }
  ])
})

test('repoStatus counts staged, unstaged and untracked changes against HEAD', async t => {
  const cwd = await tempRepo(t)
  await commitFile(cwd, 'tracked.txt', 'one\ntwo\nthree\n')
  await commitFile(cwd, 'staged.txt', 'a\n')

  await fs.writeFile(path.join(cwd, 'tracked.txt'), 'one\nTWO\nthree\nfour\n', 'utf8')
  await fs.writeFile(path.join(cwd, 'staged.txt'), 'a\nb\n', 'utf8')
  git(cwd, 'add', '--', 'staged.txt')
  await fs.mkdir(path.join(cwd, 'nested'))
  await fs.writeFile(path.join(cwd, 'nested', 'new.txt'), 'x\ny', 'utf8')

  const status = await repoStatus(cwd)

  assert.equal(status.branch, 'main')
  assert.equal(status.defaultBranch, 'main')
  assert.equal(status.staged, 1)
  assert.equal(status.unstaged, 1)
  assert.equal(status.untracked, 1)
  assert.equal(status.conflicted, 0)
  assert.equal(status.changed, 3)
  // tracked.txt: +2 -1, staged.txt: +1, nested/new.txt: 2 untracked lines.
  assert.equal(status.added, 5)
  assert.equal(status.removed, 1)
  assert.deepEqual(status.files.map(file => file.path).sort(), ['nested/new.txt', 'staged.txt', 'tracked.txt'])
})

test('repoStatus reports a detached HEAD without a branch name', async t => {
  const cwd = await tempRepo(t, { branch: 'trunk' })
  await commitFile(cwd, 'a.txt', 'a\n')
  await commitFile(cwd, 'b.txt', 'b\n')
  git(cwd, 'checkout', '--quiet', '--detach', 'HEAD~1')

  const status = await repoStatus(cwd)

  assert.equal(status.detached, true)
  assert.equal(status.branch, null)
  // No main/master/origin HEAD in this repo.
  assert.equal(status.defaultBranch, null)
  assert.equal(status.changed, 0)
})

test('repoStatus reports ahead/behind against the upstream and marks conflicts', async t => {
  const remote = await tempRepo(t)
  await commitFile(remote, 'shared.txt', 'base\n')

  const cwd = await fs.mkdtemp(path.join(os.tmpdir(), 'lliam-git-status-clone-'))
  t.after(() => fs.rm(cwd, { recursive: true, force: true }))
  git(path.dirname(cwd), 'clone', '--quiet', remote, cwd)

  await commitFile(remote, 'shared.txt', 'remote edit\n', 'remote edit')
  await commitFile(cwd, 'shared.txt', 'local edit\n', 'local edit')
  git(cwd, 'fetch', '--quiet')

  const diverged = await repoStatus(cwd)

  assert.equal(diverged.ahead, 1)
  assert.equal(diverged.behind, 1)
  assert.equal(diverged.defaultBranch, 'main')

  try {
    git(cwd, 'merge', '--quiet', 'origin/main')
  } catch {
    // Expected: the edits conflict.
  }

  const conflicted = await repoStatus(cwd)

  assert.equal(conflicted.conflicted, 1)
  assert.deepEqual(
    conflicted.files.find(file => file.path === 'shared.txt'),
    { path: 'shared.txt', staged: true, unstaged: true, untracked: false, conflicted: true }
  )
})

test('repoStatus returns null for a missing directory or a non-repository', async t => {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'lliam-git-status-plain-'))
  t.after(() => fs.rm(dir, { recursive: true, force: true }))

  // Stop git's upward repository discovery at the temp dir's parent so the
  // result doesn't depend on where the OS keeps temp files.
  const ceiling = process.env.GIT_CEILING_DIRECTORIES
  process.env.GIT_CEILING_DIRECTORIES = path.dirname(dir)
  t.after(() => {
    if (ceiling === undefined) {
      delete process.env.GIT_CEILING_DIRECTORIES
    } else {
      process.env.GIT_CEILING_DIRECTORIES = ceiling
    }
  })

  assert.equal(await repoStatus(path.join(dir, 'gone')), null)
  assert.equal(await repoStatus(dir), null)
  assert.equal(await repoStatus(''), null)
})

test('fileDiffVsHead diffs tracked edits, ignores clean files and all-adds untracked files', async t => {
  const cwd = await tempRepo(t)
  await commitFile(cwd, 'clean.txt', 'same\n')
  await commitFile(cwd, 'edited.txt', 'before\n')
  await fs.writeFile(path.join(cwd, 'edited.txt'), 'after\n', 'utf8')
  await fs.writeFile(path.join(cwd, 'new.txt'), 'brand new\n', 'utf8')

  const edited = await fileDiffVsHead(cwd, 'edited.txt')
  assert.match(edited, /^-before$/m)
  assert.match(edited, /^\+after$/m)

  assert.equal(await fileDiffVsHead(cwd, 'clean.txt'), '')

  const added = await fileDiffVsHead(cwd, 'new.txt')
  assert.match(added, /^--- \/dev\/null$/m)
  assert.match(added, /^\+brand new$/m)
})

test('fileDiffVsHead returns empty for an invalid repo path', async () => {
  assert.equal(await fileDiffVsHead('', 'a.txt'), '')
})
