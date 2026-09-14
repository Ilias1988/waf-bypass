import test from 'node:test'
import assert from 'node:assert/strict'

import { TARGETS, EVASION_LAYERS } from '../src/data/techniques.js'
import { generateSqliVariants } from '../src/engines/sqli.js'
import { generateXssVariants } from '../src/engines/xss.js'
import { generateCmdiVariants } from '../src/engines/cmdi.js'
import { generateLfiVariants } from '../src/engines/lfi.js'
import { generateSsrfVariants } from '../src/engines/ssrf.js'
import { generateSstiVariants } from '../src/engines/ssti.js'
import { generateXxeVariants } from '../src/engines/xxe.js'

const ENGINES = {
  sqli: generateSqliVariants,
  xss: generateXssVariants,
  cmdi: generateCmdiVariants,
  lfi: generateLfiVariants,
  ssrf: generateSsrfVariants,
  ssti: generateSstiVariants,
  xxe: generateXxeVariants,
}

const XML_SAMPLE = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY matrix SYSTEM "file:///tmp/matrix-marker">]><r>&matrix;</r>'

function sampleFor(category, target) {
  if (category === 'sqli') return "SELECT * FROM users WHERE name = 'O''Reilly'"
  if (category === 'xss') {
    if (target === 'html') return '<script>confirm(4242)</script>'
    if (target === 'attr') return 'onfocus="confirm(4242)"'
    return 'confirm(4242)'
  }
  if (category === 'cmdi') {
    if (target === 'windows') return 'echo matrix-marker'
    if (target === 'powershell') return "Write-Output 'matrix-marker'"
    return '; echo matrix-marker'
  }
  if (category === 'lfi') return target === 'dotnet' ? '..\\..\\Windows\\win.ini' : '../../../etc/passwd'
  if (category === 'ssrf') return 'http://127.0.0.1:8080/admin?q=matrix-marker'
  if (category === 'ssti') return target === 'freemarker' ? '${7*7}' : "{{ ''.__class__.__mro__ }}"
  return XML_SAMPLE
}

function keyFor(variant) {
  return variant.bytesBase64
    ? `bytes:${variant.encoding ?? ''}:${variant.bytesBase64}`
    : `text:${variant.payload}`
}

function assertWellFormed(variants, input, context) {
  assert.ok(Array.isArray(variants), `${context}: result is not an array`)
  assert.ok(variants.length >= 2, `${context}: no bypass variant was generated`)
  assert.ok(variants.length <= 13, `${context}: exceeded Original + 12 bypasses`)
  assert.equal(variants[0].label, 'Original', `${context}: first result is not Original`)
  assert.equal(variants[0].payload, input, `${context}: original input was altered`)

  const keys = new Set()
  for (const variant of variants) {
    assert.equal(typeof variant.payload, 'string', `${context}: payload is not text metadata`)
    assert.ok(Array.isArray(variant.layers), `${context}: layers metadata is malformed`)
    assert.doesNotMatch(variant.payload, /\b(?:undefined|NaN)\b/, `${context}: malformed value leaked into payload`)
    const key = keyFor(variant)
    assert.ok(!keys.has(key), `${context}: duplicate output ${key}`)
    keys.add(key)
    if (variant.bytesBase64) {
      const bytes = Buffer.from(variant.bytesBase64, 'base64')
      assert.ok(bytes.length > 2, `${context}: binary payload is empty`)
      assert.equal(bytes.toString('base64'), variant.bytesBase64, `${context}: invalid Base64 byte payload`)
    }
  }
}

test('every configured category, target, and layer generates stable well-formed output', () => {
  let combinations = 0
  let individualLayers = 0

  for (const [category, targets] of Object.entries(TARGETS)) {
    const engine = ENGINES[category]
    assert.equal(typeof engine, 'function', `${category}: missing engine`)

    for (const { id: target } of targets) {
      const input = sampleFor(category, target)
      const supportedLayers = EVASION_LAYERS[category]
        .filter((layer) => !layer.targets || layer.targets.includes(target))
        .map((layer) => layer.id)

      for (const layer of supportedLayers) {
        const context = `${category}/${target}/${layer}`
        const first = engine(input, [layer], target)
        const second = engine(input, [layer], target)
        assertWellFormed(first, input, context)
        assert.deepEqual(first, second, `${context}: output is nondeterministic`)
        assert.ok(first.some((variant) => variant.layers.includes(layer)), `${context}: layer is not represented`)
        individualLayers += 1
      }

      const context = `${category}/${target}/all-layers`
      const combined = engine(input, supportedLayers, target)
      assertWellFormed(combined, input, context)
      const represented = new Set(combined.flatMap((variant) => variant.layers))
      supportedLayers.forEach((layer) => {
        assert.ok(represented.has(layer), `${context}: ${layer} is not represented`)
      })
      combinations += 1
    }
  }

  assert.equal(combinations, 23)
  assert.ok(individualLayers >= 80)
})

test('SQL target matrix emits dialect-specific string expressions', () => {
  const expected = {
    mysql: /CONVERT\(0x[0-9a-f]+ USING utf8mb4\)/i,
    postgres: /convert_from\(decode\('[0-9a-f]+','hex'\),'UTF8'\)/i,
    mssql: /CONVERT\(nvarchar\(max\), 0x[0-9a-f]+\)/i,
    oracle: /UTL_I18N\.RAW_TO_CHAR\(HEXTORAW\('[0-9a-f]+'\),'AL32UTF8'\)/i,
    sqlite: /CAST\(X'[0-9a-f]+' AS TEXT\)/i,
  }

  for (const [target, pattern] of Object.entries(expected)) {
    const variants = generateSqliVariants("SELECT 'matrix-marker'", ['hex-encoding'], target).slice(1)
    assert.ok(variants.some((variant) => pattern.test(variant.payload)), `${target}: wrong hex expression`)
  }
})

test('SQL case and comment layers keep quoted literals opaque', () => {
  const input = "SELECT * FROM users WHERE name = convert_from(decode('4f275265696c6c79','hex'),'UTF8')"
  for (const layer of ['case-toggle', 'inline-comments']) {
    const variants = generateSqliVariants(input, [layer], 'postgres').slice(1)
    assert.ok(variants.length > 0)
    for (const variant of variants) {
      assert.match(variant.payload, /'hex'/)
      assert.match(variant.payload, /'UTF8'/)
      assert.doesNotMatch(variant.payload, /\/\*!/)
    }
  }
})

test('SSRF authority transformations retain explicit ports, paths, and queries', () => {
  const input = 'http://127.0.0.1:8080/admin?q=matrix-marker'
  for (const layer of ['ip-decimal', 'ip-hex', 'ip-octal', 'ip-short', 'url-tricks']) {
    const variants = generateSsrfVariants(input, [layer], 'http').slice(1)
    for (const variant of variants) {
      assert.match(variant.payload, /:8080/)
      assert.match(variant.payload, /\/admin\?q=matrix-marker/)
    }
  }
})
