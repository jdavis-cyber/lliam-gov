'use strict'

// Read-only git probes for the composer coding rail (branch, ahead/behind,
// change counts) and the file preview's "what changed since the last commit"
// diff. Shells to the system git binary with execFile -- the same way
// git-worktree-ops.cjs does -- and parses porcelain output directly, so there
// is no JS git wrapper to ship or patch. Every probe degrades to null/empty on
// a non-repo, a missing directory, or a git failure; nothing here mutates the
// repository.

const { execFile } = require('node:child_process')
const fs = require('node:fs/promises')
const path = require('node:path')

const { resolveRequestedPathForIpc } = require('./hardening.cjs')

const UNTRACKED_LINE_COUNT_CONCURRENCY = 16
const UNTRACKED_LINE_COUNT_MAX_BYTES = 1024 * 1024
const UNTRACKED_COUNT_MAX_FILES = 500
const STATUS_FILES_MAX = 200
const DIFF_MAX_BUFFER = 32 * 1024 * 1024

// Resolve stdout on success. `okCodes` lists non-zero exits that still carry a
// usable result (`git diff --no-index` exits 1 when the files differ).
function runGit(gitBin, args, cwd, { okCodes = [], maxBuffer = 8 * 1024 * 1024 } = {}) {
  return new Promise((resolve, reject) => {
    execFile(gitBin || 'git', args, { cwd, windowsHide: true, timeout: 30_000, maxBuffer }, (err, stdout, stderr) => {
      if (err && !okCodes.includes(err.code)) {
        err.stderr = String(stderr || '')
        reject(err)

        return
      }

      resolve(String(stdout || ''))
    })
  })
}

// Parse `git status --porcelain=v2 --branch -z`. Records are NUL-separated; a
// rename/copy ("2 ...") record is followed by one extra record holding the
// original path. XY codes use "." for "unchanged"; normalise to " " so the
// index/worktree checks below read like classic porcelain.
function parseStatusV2(out) {
  const result = { head: null, upstream: null, ahead: 0, behind: 0, files: [] }
  const records = out.split('\0')

  for (let i = 0; i < records.length; i++) {
    const record = records[i]

    if (!record) {
      continue
    }

    if (record.startsWith('# ')) {
      const [key, ...rest] = record.slice(2).split(' ')
      const value = rest.join(' ')

      if (key === 'branch.head') {
        result.head = value
      } else if (key === 'branch.upstream') {
        result.upstream = value
      } else if (key === 'branch.ab') {
        const match = /^\+(\d+) -(\d+)$/.exec(value)

        if (match) {
          result.ahead = Number(match[1])
          result.behind = Number(match[2])
        }
      }

      continue
    }

    const kind = record[0]

    if (kind === '?') {
      result.files.push({ path: record.slice(2), index: '?', workingDir: '?', unmerged: false })

      continue
    }

    // Field counts before the path: ordinary 8, rename/copy 9, unmerged 10.
    const fieldsBeforePath = kind === '1' ? 8 : kind === '2' ? 9 : kind === 'u' ? 10 : -1

    if (fieldsBeforePath < 0) {
      continue
    }

    const parts = record.split(' ')
    const xy = parts[1] || '..'
    const filePath = parts.slice(fieldsBeforePath).join(' ')
    const norm = code => (code === '.' ? ' ' : code)

    result.files.push({ path: filePath, index: norm(xy[0]), workingDir: norm(xy[1]), unmerged: kind === 'u' })

    if (kind === '2') {
      // Skip the original-path record that follows a rename/copy.
      i++
    }
  }

  return result
}

// Sum `git diff --numstat` output. Binary files report "-" and count as 0.
function sumNumstat(out) {
  let added = 0
  let removed = 0

  for (const line of out.split('\n')) {
    const [a, r] = line.split('\t')
    const addedLines = Number.parseInt(a, 10)
    const removedLines = Number.parseInt(r, 10)

    if (Number.isFinite(addedLines)) {
      added += addedLines
    }

    if (Number.isFinite(removedLines)) {
      removed += removedLines
    }
  }

  return { added, removed }
}

// Untracked files carry no diff vs HEAD; count their lines from disk so the
// rail can show +N for new files. Insertions = newline bytes, plus one for a
// final unterminated line. Binary (NUL byte) or oversized → 0, mirroring git
// numstat's "-".
async function untrackedInsertions(cwd, relPath) {
  try {
    const fullPath = path.join(cwd, relPath)
    const stat = await fs.stat(fullPath)

    if (!stat.isFile() || stat.size > UNTRACKED_LINE_COUNT_MAX_BYTES) {
      return 0
    }

    const buf = await fs.readFile(fullPath)

    if (buf.includes(0)) {
      return 0
    }

    let lines = 0

    for (const byte of buf) {
      if (byte === 10) {
        lines++
      }
    }

    return buf.length > 0 && buf[buf.length - 1] !== 10 ? lines + 1 : lines
  } catch {
    return 0
  }
}

// Resolve the repo's default branch NAME ("main" / "master" / …), preferring
// the remote's HEAD, then common local trunk names, then remote-only ones.
// Null when none is found (e.g. a fresh repo with only a feature branch). Used
// to offer "branch off the trunk" regardless of the current branch.
async function defaultBranchName(cwd, gitBin) {
  try {
    const head = (await runGit(gitBin, ['rev-parse', '--abbrev-ref', 'origin/HEAD'], cwd)).trim()

    // "origin/main" → "main"; skip the bare "origin/HEAD" placeholder.
    if (head && head !== 'origin/HEAD') {
      return head.replace(/^origin\//, '')
    }
  } catch {
    // No origin/HEAD configured.
  }

  for (const ref of [
    'refs/heads/main',
    'refs/heads/master',
    'refs/remotes/origin/main',
    'refs/remotes/origin/master'
  ]) {
    try {
      await runGit(gitBin, ['rev-parse', '--verify', '--quiet', ref], cwd)

      return ref.replace(/^refs\/(?:heads|remotes\/origin)\//, '')
    } catch {
      // Ref doesn't exist; try the next candidate.
    }
  }

  return null
}

// Compact working-tree status for the composer coding rail: branch, ahead/behind,
// per-state change counts, +/- vs HEAD, and a capped changed-file list.
async function repoStatus(repoPath, gitBin) {
  let cwd

  try {
    cwd = resolveRequestedPathForIpc(repoPath, { purpose: 'Repo status' })
  } catch {
    return null
  }

  // Session cwds can point at a deleted worktree for a moment (or forever in a
  // stale row); hide the coding rail instead of erroring.
  try {
    const stat = await fs.stat(cwd)

    if (!stat.isDirectory()) {
      return null
    }
  } catch {
    return null
  }

  let status

  try {
    status = parseStatusV2(
      await runGit(gitBin, ['status', '--porcelain=v2', '--branch', '-z', '--untracked-files=all'], cwd)
    )
  } catch {
    // Not a repo / git unavailable.
    return null
  }

  const detached = !status.head || status.head === '(detached)'
  const files = status.files.map(file => ({
    path: file.path,
    staged: file.index !== ' ' && file.index !== '?',
    unstaged: file.workingDir !== ' ' && file.workingDir !== '?',
    untracked: file.index === '?',
    conflicted: file.unmerged
  }))
  const untrackedPaths = files.filter(f => f.untracked).map(f => f.path)

  const result = {
    branch: detached ? null : status.head,
    defaultBranch: await defaultBranchName(cwd, gitBin),
    detached,
    ahead: status.ahead,
    behind: status.behind,
    staged: files.filter(f => f.staged).length,
    unstaged: files.filter(f => f.unstaged).length,
    untracked: untrackedPaths.length,
    conflicted: files.filter(f => f.conflicted).length,
    changed: files.length,
    added: 0,
    removed: 0,
    files: files.slice(0, STATUS_FILES_MAX)
  }

  // +/- vs HEAD (staged + unstaged tracked changes). No HEAD yet → leave 0.
  try {
    const delta = sumNumstat(await runGit(gitBin, ['diff', '--numstat', '--no-ext-diff', 'HEAD'], cwd))

    result.added = delta.added
    result.removed = delta.removed
  } catch {
    // No commits yet.
  }

  // `git diff HEAD` ignores untracked files, so a turn that only creates new
  // files would show +0. Fold untracked line counts into `added`, bounded by a
  // per-file size cap, a file-count cap and limited concurrency.
  const counted = untrackedPaths.slice(0, UNTRACKED_COUNT_MAX_FILES)

  for (let i = 0; i < counted.length; i += UNTRACKED_LINE_COUNT_CONCURRENCY) {
    const batch = await Promise.all(
      counted.slice(i, i + UNTRACKED_LINE_COUNT_CONCURRENCY).map(rel => untrackedInsertions(cwd, rel))
    )

    result.added += batch.reduce((sum, n) => sum + n, 0)
  }

  return result
}

// Working-tree-vs-HEAD diff for ONE file — the file preview's "what changed
// since the last commit" view. A clean tracked file returns empty; only a
// genuinely untracked file gets a synthesized all-add diff.
async function fileDiffVsHead(repoPath, filePath, gitBin) {
  let cwd

  try {
    cwd = resolveRequestedPathForIpc(repoPath, { purpose: 'File diff' })
  } catch {
    return ''
  }

  const head = await runGit(gitBin, ['diff', '--no-color', '--no-ext-diff', 'HEAD', '--', filePath], cwd, {
    maxBuffer: DIFF_MAX_BUFFER
  }).catch(() => '')

  if (head.trim()) {
    return head
  }

  const status = await runGit(gitBin, ['status', '--porcelain', '--', filePath], cwd).catch(() => '')

  if (!status.trim().startsWith('??')) {
    return ''
  }

  return runGit(gitBin, ['diff', '--no-color', '--no-ext-diff', '--no-index', '--', '/dev/null', filePath], cwd, {
    okCodes: [1],
    maxBuffer: DIFF_MAX_BUFFER
  }).catch(() => '')
}

module.exports = {
  fileDiffVsHead,
  parseStatusV2,
  repoStatus,
  sumNumstat
}
