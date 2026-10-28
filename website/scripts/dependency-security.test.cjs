const assert = require('node:assert/strict')
const test = require('node:test')
const fs = require('node:fs')
const path = require('node:path')
const { createRequire } = require('node:module')

test('every website KaTeX copy rejects inherited trust and renders ordinary math', () => {
  const root = path.resolve(__dirname, '..')
  const lock = require('../package-lock.json')
  const copies = Object.keys(lock.packages).filter(key => key.endsWith('/node_modules/katex') || key === 'node_modules/katex')
  assert.ok(copies.length > 0)
  for (const copy of copies) {
    const katex = require(path.join(root, copy))
    const expression = String.raw`\href{https://example.test}{safe}`
    assert.doesNotMatch(katex.renderToString(expression, Object.create({ trust: true })), /href="https:\/\/example\.test"/)
    assert.match(katex.renderToString(expression, { trust: true }), /href="https:\/\/example\.test"/)
    assert.match(katex.renderToString('x+y'), /class="katex"/)
  }
})

test('SVGR optimizes and transforms SVG with default and custom plugin configuration', () => {
  const { transform } = require('@svgr/core')
  const svgo = require('@svgr/plugin-svgo')
  const jsx = require('@svgr/plugin-jsx')
  const svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><title>Example</title><path d="M0 0h24v24H0z"/></svg>'
  const options = { plugins: [svgo, jsx], runtimeConfig: false, icon: true }
  const normal = transform.sync(svg, options, { componentName: 'ExampleIcon' })
  assert.match(normal, /ExampleIcon/)
  assert.match(normal, /viewBox="0 0 24 24"/)
  assert.match(normal, /<path/)
  const custom = transform.sync(svg, { ...options, svgoConfig: { plugins: ['removeTitle'] } }, { componentName: 'CustomIcon' })
  assert.match(custom, /CustomIcon/)
  assert.doesNotMatch(custom, /<title/)
})

test('the scoped unused dependency replacement does not poison object prototypes', () => {
  const pluginEntry = require.resolve('@svgr/plugin-svgo')
  // This alias is safe only while this exact published plugin does not call
  // deepmerge's callable API. Fail if a future implementation starts using it.
  assert.doesNotMatch(fs.readFileSync(pluginEntry, 'utf8'), /require\(["']deepmerge["']\)/)
  const pluginRequire = createRequire(pluginEntry)
  const { deepmerge } = pluginRequire('deepmerge')
  const payload = JSON.parse('{"__proto__":{"svgrPolluted":true},"constructor":{"prototype":{"svgrPolluted":true}}}')
  const result = deepmerge({ plugins: ['preset-default'] }, payload)
  assert.deepEqual(result.plugins, ['preset-default'])
  assert.equal(Object.prototype.svgrPolluted, undefined)
  assert.equal({}.svgrPolluted, undefined)
})
