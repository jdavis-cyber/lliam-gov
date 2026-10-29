const assert = require('node:assert/strict')
const test = require('node:test')
const shellQuote = require('shell-quote')
const tar = require('tar')
const { DOMImplementation, XMLSerializer } = require('@xmldom/xmldom')
const { expand } = require('brace-expansion')
const uri = require('fast-uri')
const path = require('node:path')

test('every locked KaTeX copy rejects inherited trust and preserves normal math', () => {
  const root = path.resolve(__dirname, '../../..')
  const lock = require(path.join(root, 'package-lock.json'))
  const copies = Object.keys(lock.packages).filter(key => key.endsWith('/node_modules/katex') || key === 'node_modules/katex')
  assert.ok(copies.length > 0)
  for (const copy of copies) {
    const katex = require(path.join(root, copy))
    const expression = String.raw`\href{https://example.test}{safe}`
    const inherited = katex.renderToString(expression, Object.create({ trust: true }))
    assert.doesNotMatch(inherited, /href="https:\/\/example\.test"/, copy)
    assert.match(katex.renderToString(expression, { trust: true }), /href="https:\/\/example\.test"/, copy)
    assert.match(katex.renderToString('x+y'), /class="katex"/, copy)
  }
})

// Preserve normal developer command quoting while rejecting the advisory's
// comment-token/line-terminator injection pattern. Nothing is executed.
test('shell quoting preserves literal arguments and rejects post-comment line terminators', () => {
  const args = ['command', 'space here', "it's quoted", '$(literal)', 'semi;colon']
  assert.deepEqual(shellQuote.parse(shellQuote.quote(args)), args)
  for (const terminator of ['\n', '\r', '\u2028', '\u2029']) {
    assert.throws(() => shellQuote.quote(['command', { comment: 'comment' }, `literal${terminator}text`]), TypeError)
  }
})

function archiveWithPath(entryPath) {
  const header = new tar.Header({ path: 'item', mode: 0o644, uid: 0, gid: 0, size: 0, type: 'File' })
  const block = Buffer.alloc(512)
  header.encode(block)
  return Buffer.concat([new tar.Pax({ path: entryPath }).encode(), block, Buffer.alloc(1024)])
}

async function selectedPaths(archive, selected) {
  const paths = []
  const parser = tar.t({ onReadEntry: entry => paths.push(entry.path) }, selected)
  await new Promise((resolve, reject) => {
    parser.once('end', resolve)
    parser.once('error', reject)
    parser.end(archive)
  })
  return paths
}

test('archive member selection handles adversarial depth and still selects valid descendants', async () => {
  // The vulnerable selector recursed once per path segment, overflowing the
  // process stack. This archive exists only in memory; no files are extracted.
  assert.deepEqual(await selectedPaths(archiveWithPath('x/'.repeat(20_000) + 'item'), ['selected']), [])
  assert.deepEqual(await selectedPaths(archiveWithPath('selected/item.txt'), ['selected']), ['selected/item.txt'])
})

test('well-formed XML serialization rejects a mutated processing-instruction target', () => {
  const document = new DOMImplementation().createDocument(null, 'root', null)
  const instruction = document.createProcessingInstruction('safe', 'value')
  const serialize = () => new XMLSerializer().serializeToString(instruction, false, null, { requireWellFormed: true })
  assert.equal(serialize(), '<?safe value?>')
  // DOM fields are writable; serializer validation must also cover mutations.
  instruction.target = 'bad?><injected/>'
  assert.throws(serialize, error => error.code === 11)
})

test('brace expansion bounds output while preserving normal alternatives', () => {
  assert.deepEqual(expand('file.{js,ts}'), ['file.js', 'file.ts'])
  // A small explicit cap proves the bounded-expansion contract without an
  // expensive or memory-exhausting payload, even against the old dependency.
  assert.deepEqual(expand('{1..100}', { max: 8 }), ['1', '2', '3', '4', '5', '6', '7', '8'])
})

test('URI serialization rejects authority injection through a malformed port', () => {
  assert.equal(uri.serialize({ scheme: 'https', host: 'example.test', port: 443 }), 'https://example.test/')
  assert.throws(() => uri.serialize({ scheme: 'https', host: 'example.test', port: '443@evil.test' }))
})
