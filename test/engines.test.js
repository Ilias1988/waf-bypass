import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'

import { generateSqliVariants } from '../src/engines/sqli.js'
import { generateXssVariants } from '../src/engines/xss.js'
import { generateCmdiVariants } from '../src/engines/cmdi.js'
import { generateLfiVariants } from '../src/engines/lfi.js'
import { generateSsrfVariants } from '../src/engines/ssrf.js'
import { generateSstiVariants } from '../src/engines/ssti.js'
import { generateXxeVariants } from '../src/engines/xxe.js'

const bypasses = (variants) => variants.slice(1)
const representedLayers = (variants) => new Set(variants.flatMap((variant) => variant.layers))

test('SQL transformations are dialect-aware and preserve escaped strings', () => {
  const sqlite = bypasses(generateSqliVariants('SELECT 1', ['inline-comments'], 'sqlite'))[0].payload
  assert.match(sqlite, /SELECT/)
  const parsed = spawnSync(
    'python',
    ['-c', 'import sqlite3,sys; sqlite3.connect(":memory:").execute(sys.stdin.read())'],
    { input: sqlite, encoding: 'utf8' },
  )
  assert.equal(parsed.status, 0, parsed.stderr)

  const escaped = bypasses(generateSqliVariants("SELECT 'O''Reilly'", ['hex-encoding'], 'mysql'))[0].payload
  assert.equal((escaped.match(/0x/g) || []).length, 1)
  assert.match(escaped, /4f275265696c6c79/i)

  const backslashEscaped = bypasses(generateSqliVariants("SELECT 'O\\'Reilly'", ['hex-encoding'], 'mysql'))[0].payload
  assert.equal((backslashEscaped.match(/0x/g) || []).length, 1)

  const postgres = bypasses(generateSqliVariants("SELECT 'Ω'", ['hex-encoding'], 'postgres'))[0].payload
  assert.match(postgres, /convert_from\(decode\('[0-9a-f]+'/i)

  const nested = "SELECT * FROM users WHERE name = convert_from(decode('4f275265696c6c79','hex'),'UTF8')"
  const cased = bypasses(generateSqliVariants(nested, ['case-toggle'], 'postgres'))
  assert.ok(cased.every((variant) => variant.payload.includes("'hex'") && variant.payload.includes("'UTF8'")))
  const postgresComments = bypasses(generateSqliVariants(nested, ['inline-comments'], 'postgres'))
  assert.ok(postgresComments.every((variant) => !variant.payload.includes('/*!')))
  assert.ok(postgresComments.every((variant) => variant.payload.includes("'hex'") && variant.payload.includes("'UTF8'")))
})

test('SQL whitespace variants preserve literals, plus operators, and line-comment boundaries', () => {
  const input = "SELECT 'matrix marker' + SYSTEM_USER + 'x+y'"
  const variants = bypasses(generateSqliVariants(input, ['whitespace'], 'mssql'))

  for (const variant of variants) {
    assert.match(variant.payload, /'matrix(?: marker|%20marker)'/)
    assert.match(variant.payload, /'x(?:\+|%2B)y'/i)
  }

  const formVariant = variants.find((variant) => variant.payload.includes('+') && variant.payload.includes('%2B'))
  assert.ok(formVariant)
  const formDecoded = decodeURIComponent(formVariant.payload.replace(/\+/g, ' '))
  assert.equal(formDecoded, input)

  const commented = bypasses(generateSqliVariants('SELECT 1 -- keep words\nUNION SELECT 2', ['inline-comments'], 'postgres'))[0].payload
  assert.match(commented, /-- keep words\n/)
  assert.match(commented, /UNION\/\*\*\/SELECT/)
})

test('every SQL whitespace variant keeps query semantics after its required decode pass', () => {
  const input = "SELECT CASE WHEN 'O''Reilly 100% + marker' = 'O''Reilly 100% + marker' THEN 1 ELSE 0 END"
  const variants = bypasses(generateSqliVariants(input, ['whitespace'], 'sqlite'))

  for (const variant of variants) {
    const decoded = variant.validity === 'conditional'
      ? decodeURIComponent(variant.payload.replace(/\+/g, ' '))
      : variant.payload
    const executed = spawnSync(
      'python',
      ['-c', 'import sqlite3,sys; print(sqlite3.connect(":memory:").execute(sys.stdin.read()).fetchone()[0])'],
      { input: decoded, encoding: 'utf8' },
    )
    assert.equal(executed.status, 0, `${variant.payload}\n${executed.stderr}`)
    assert.equal(executed.stdout.trim(), '1', variant.payload)
  }
})

test('XSS transformations preserve supplied JavaScript and respect context', () => {
  const html = generateXssVariants('<script>confirm(42)</script>', ['tag-variation'], 'html')
  assert.ok(bypasses(html).every((variant) => variant.payload.includes('confirm(42)')))
  const attr = generateXssVariants('confirm(42)', ['tag-variation'], 'attr')
  assert.notDeepEqual(html, attr)
  const js = generateXssVariants("alert(call('Ω'))", ['js-obfuscation'], 'js')
  for (const variant of bypasses(js)) assert.doesNotThrow(() => new Function(variant.payload))

  const firstRun = generateXssVariants('<img src=x onerror=confirm(42)>', ['html-entities'], 'html')
  const secondRun = generateXssVariants('<img src=x onerror=confirm(42)>', ['html-entities'], 'html')
  assert.deepEqual(firstRun, secondRun)
})

test('XSS JavaScript obfuscation cannot terminate a double-quoted event attribute', () => {
  const variants = bypasses(generateXssVariants('onfocus="confirm(4242)"', ['js-obfuscation'], 'attr'))
  assert.ok(variants.length > 0)
  for (const variant of variants) {
    const attribute = variant.payload.match(/^onfocus="([^"]*)"$/)
    assert.ok(attribute, variant.payload)
    assert.doesNotThrow(() => new Function(attribute[1]))
  }
})

test('CMDi transformations preserve Unicode and emit valid PowerShell Base64', () => {
  assert.doesNotThrow(() => generateCmdiVariants('; echo Ω', ['variable-expansion'], 'linux'))
  const variants = bypasses(generateCmdiVariants('; whoami', ['variable-expansion'], 'powershell'))
  const encoded = variants.find((variant) => variant.payload.includes('-EncodedCommand')).payload.split('-EncodedCommand ')[1]
  assert.equal(Buffer.from(encoded, 'base64').toString('utf16le'), 'whoami')

  const harmless = bypasses(generateCmdiVariants('Write-Output codex-functional-marker', ['variable-expansion'], 'powershell'))
  const harmlessEncoded = harmless.find((variant) => variant.payload.includes('-EncodedCommand')).payload.split('-EncodedCommand ')[1]
  const executed = spawnSync('powershell.exe', ['-NoProfile', '-EncodedCommand', harmlessEncoded], { encoding: 'utf8' })
  assert.equal(executed.status, 0, executed.stderr)
  assert.match(executed.stdout, /codex-functional-marker/)
})

test('Linux command variants execute a quoted marker without changing its arguments', (t) => {
  const bash = 'C:\\Program Files\\Git\\bin\\bash.exe'
  const input = "printf '%s\\n' 'matrix Ω 4242'"
  const layerSets = [
    ['space-bypass'],
    ['keyword-bypass'],
    ['variable-expansion'],
    ['hex-cmd'],
    ['space-bypass', 'keyword-bypass'],
  ]

  for (const layers of layerSets) {
    const variants = bypasses(generateCmdiVariants(input, layers, 'linux'))
    assert.ok(variants.length > 0, layers.join(','))
    for (const variant of variants) {
      const decoded = variant.payload
        .replace(/%09/gi, '\t')
        .replace(/%20/gi, ' ')
      const result = spawnSync(bash, ['-lc', decoded], { encoding: 'utf8' })
      assert.equal(result.status, 0, `${variant.payload}\n${result.stderr}`)
      assert.equal(result.stdout.trim(), 'matrix Ω 4242', variant.payload)
    }
  }
})

test('Windows command variants execute a harmless marker after their documented decode stage', () => {
  const spaceVariants = bypasses(generateCmdiVariants('echo matrix-marker', ['space-bypass'], 'windows'))
  for (const variant of spaceVariants) {
    const decoded = decodeURIComponent(variant.payload)
    const result = spawnSync('cmd.exe', ['/D', '/S', '/C', decoded], { encoding: 'utf8' })
    assert.equal(result.status, 0, `${variant.payload}\n${result.stderr}`)
    assert.match(result.stdout, /matrix-marker/)
  }

  const hexVariants = bypasses(generateCmdiVariants("Write-Output 'matrix-marker'", ['hex-cmd'], 'powershell'))
  for (const variant of hexVariants) {
    const result = spawnSync('powershell.exe', ['-NoProfile', '-Command', variant.payload], { encoding: 'utf8' })
    assert.equal(result.status, 0, `${variant.payload}\n${result.stderr}`)
    assert.match(result.stdout, /matrix-marker/)
  }

  const keywordVariants = bypasses(generateCmdiVariants("Write-Output 'matrix-marker'", ['keyword-bypass'], 'powershell'))
  for (const variant of keywordVariants) {
    const result = spawnSync('powershell.exe', ['-NoProfile', '-Command', variant.payload], { encoding: 'utf8' })
    assert.equal(result.status, 0, `${variant.payload}\n${result.stderr}`)
    assert.match(result.stdout, /matrix-marker/)
  }

  assert.equal(generateCmdiVariants('dir /b', ['hex-cmd', 'variable-expansion'], 'windows').length, 1)
})

test('PowerShell statement payloads are never rewritten as command invocations', () => {
  const script = [
    '$encoded = "Write-Output%20\'matrix-marker\'"',
    '$decoded = [Uri]::UnescapeDataString($encoded)',
    '& ([scriptblock]::Create($decoded))',
  ].join('\n')

  const keyword = generateCmdiVariants(script, ['keyword-bypass'], 'powershell')
  assert.equal(keyword.length, 1)

  const safeVariants = bypasses(generateCmdiVariants(script, ['variable-expansion', 'hex-cmd'], 'powershell'))
  assert.ok(safeVariants.length > 0)
  for (const variant of safeVariants) {
    const result = spawnSync('powershell.exe', ['-NoProfile', '-Command', variant.payload], { encoding: 'utf8' })
    assert.equal(result.status, 0, `${variant.payload}\n${result.stderr}`)
    assert.match(result.stdout, /matrix-marker/)
  }
})

test('LFI transformations support Windows traversal and Unicode PHP paths', () => {
  const windows = generateLfiVariants('..\\..\\Windows\\win.ini', ['path-normalization'], 'dotnet')
  assert.ok(bypasses(windows).some((variant) => variant.payload.includes('Windows\\win.ini')))
  const windowsCombo = bypasses(generateLfiVariants('..\\..\\Windows\\win.ini', ['path-normalization', 'unicode-encoding'], 'dotnet'))
  assert.ok(windowsCombo.some((variant) => variant.layers.length === 2 && variant.payload.includes('%u005c')))
  assert.ok(windowsCombo.every((variant) => !variant.payload.includes('%c0%af')))
  assert.doesNotThrow(() => generateLfiVariants('../../../tmp/Ω', ['wrapper-bypass'], 'php'))

  const source = '../../../etc/passwd'
  const wrappers = bypasses(generateLfiVariants(source, ['wrapper-bypass'], 'php'))
  assert.ok(wrappers.some((variant) => variant.payload.includes(`resource=${source}`)))
  const dataWrapper = wrappers.find((variant) => variant.payload.startsWith('data://'))
  const phpSource = Buffer.from(dataWrapper.payload.split(',')[1], 'base64').toString('utf8')
  assert.match(phpSource, /\.\.\/\.\.\/\.\.\/etc\/passwd/)

  const noTraversalCombo = bypasses(generateLfiVariants('/etc/passwd', ['double-url', 'null-byte'], 'php'))
  assert.ok(noTraversalCombo.every((variant) => variant.layers.length !== 2))

  for (const candidate of ['../../../etc/passwd', '..\\..\\Windows\\win.ini']) {
    const encoded = bypasses(generateLfiVariants(candidate, ['double-url'], 'generic'))
    assert.ok(encoded.length > 0)
    for (const variant of encoded) {
      const decodedOnce = decodeURIComponent(variant.payload)
      assert.notEqual(decodedOnce, candidate, variant.payload)
      assert.equal(decodeURIComponent(decodedOnce), candidate, variant.payload)
    }
  }
})

test('SSRF variants preserve authority fields and use the selected target', () => {
  const urlVariants = bypasses(generateSsrfVariants('http://127.0.0.1:8080/admin', ['url-tricks'], 'http'))
  assert.ok(urlVariants.every((variant) => variant.payload.includes(':8080')))

  const redirect = bypasses(generateSsrfVariants('https://example.com/redirect?next=http://127.0.0.1', ['url-tricks'], 'http'))
  for (const variant of redirect) {
    const hostname = new URL(variant.payload).hostname.replace(/\.$/, '')
    assert.equal(hostname, 'example.com')
  }

  const http = generateSsrfVariants('http://127.0.0.1/', ['dns-redirect'], 'http')
  const cloud = generateSsrfVariants('http://127.0.0.1/', ['dns-redirect'], 'cloud')
  assert.notDeepEqual(http, cloud)
  assert.ok(bypasses(cloud).some((variant) => variant.payload.includes('169.254.169.254')))

  const raw = 'http://user:pass@127.0.0.1:8080/api/../admin?q=a%2Fb#marker'
  for (const layer of ['ip-decimal', 'ip-hex', 'ip-octal', 'ip-short']) {
    const transformed = bypasses(generateSsrfVariants(raw, [layer], 'http'))
    assert.ok(transformed.length > 0, layer)
    assert.ok(transformed.every((variant) => variant.payload.includes('user:pass@')))
    assert.ok(transformed.every((variant) => variant.payload.endsWith('/api/../admin?q=a%2Fb#marker')))
  }
})

test('SSTI transformations preserve intent and transform complete dunder chains', () => {
  const input = "{{ lipsum.__globals__['os'].popen('whoami').read() }}"
  const filtered = bypasses(generateSstiVariants(input, ['filter-bypass'], 'jinja2'))
  assert.ok(filtered.every((variant) => variant.payload.includes('whoami')))

  const chain = bypasses(generateSstiVariants("{{ ''.__class__.__mro__ }}", ['string-concat'], 'jinja2'))
  assert.ok(chain.some((variant) => !variant.payload.includes('__class__') && !variant.payload.includes('__mro__')))

  const freemarker = bypasses(generateSstiVariants('${7*7}', ['filter-bypass'], 'freemarker'))
  assert.ok(freemarker.every((variant) => variant.payload.includes('7*7')))
})

test('XXE byte encodings are real and entity parsing preserves quoted paths', () => {
  const source = `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY loot SYSTEM 'file:///tmp/secret'>]><r>&loot;</r>`
  const utf16 = bypasses(generateXxeVariants('<?xml version="1.0"?><root>Ω</root>', ['utf16'], 'generic'))[0]
  const bytes = Buffer.from(utf16.bytesBase64, 'base64')
  assert.deepEqual([...bytes.subarray(0, 2)], [0xff, 0xfe])
  const parsed = spawnSync(
    'python',
    ['-c', 'import sys,xml.etree.ElementTree as E; E.fromstring(sys.stdin.buffer.read())'],
    { input: bytes },
  )
  assert.equal(parsed.status, 0, parsed.stderr?.toString())

  const nested = bypasses(generateXxeVariants(source, ['entity-nesting'], 'generic'))[0].payload
  assert.match(nested, /file:\/\/\/tmp\/secret/)
  assert.match(nested, /loot_source/)
  const nestedParsed = spawnSync(
    'python',
    ['-c', 'import io,sys,xml.sax; from xml.sax import handler; p=xml.sax.make_parser(); p.setFeature(handler.feature_external_ges,False); p.parse(io.BytesIO(sys.stdin.buffer.read()))'],
    { input: nested, encoding: 'utf8' },
  )
  assert.equal(nestedParsed.status, 0, nestedParsed.stderr)

  const utf7 = bypasses(generateXxeVariants(source, ['utf7'], 'generic'))[0].payload
  assert.match(utf7, /\+AEUATgBUAEkAVABZ-/)
  assert.match(utf7, /\+AFMAWQBTAFQARQBN-/)
})

test('every engine caps results at original plus 12 bypasses', () => {
  const cases = [
    generateSqliVariants("' OR 1=1 UNION SELECT 'admin' FROM users", ['whitespace', 'case-toggle', 'inline-comments', 'hex-encoding', 'url-encoding', 'double-url'], 'mysql'),
    generateXssVariants('<script>alert(1)</script>', ['html-entities', 'url-encoding', 'js-obfuscation', 'tag-variation', 'case-toggle', 'encoding-mix'], 'html'),
    generateCmdiVariants("Write-Output 'matrix-marker'", ['space-bypass', 'keyword-bypass', 'newline-bypass', 'variable-expansion', 'hex-cmd'], 'powershell'),
    generateLfiVariants('../../../etc/passwd', ['double-url', 'unicode-encoding', 'null-byte', 'path-normalization', 'wrapper-bypass'], 'php'),
    generateSsrfVariants('http://127.0.0.1:8080/admin', ['ip-decimal', 'ip-hex', 'ip-octal', 'ip-short', 'url-tricks', 'dns-redirect'], 'cloud'),
    generateSstiVariants("{{ ''.__class__.__mro__ }}", ['string-concat', 'hex-encoding', 'attr-access', 'filter-bypass'], 'jinja2'),
    generateXxeVariants('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/hosts">]><r>&x;</r>', ['utf16', 'utf7', 'entity-nesting', 'cdata-wrap'], 'generic'),
  ]
  cases.forEach((variants) => assert.ok(variants.length <= 13))
})

test('selected layers are represented when they apply to the payload and target', () => {
  const layers = ['whitespace', 'case-toggle', 'inline-comments', 'hex-encoding', 'url-encoding', 'double-url']
  const variants = generateSqliVariants("SELECT 'admin' FROM users WHERE id = 1", layers, 'mysql')
  const represented = representedLayers(variants)
  layers.forEach((layer) => assert.ok(represented.has(layer), `${layer} missing`))
})
