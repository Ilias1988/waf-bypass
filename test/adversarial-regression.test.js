import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'

import {
  alternatingCase,
  doubleUrlEncode,
  hexEscape,
  htmlDecimalEncode,
  htmlHexEncode,
  ipToDecimal,
  ipToHex,
  ipToOctal,
  jsUnicodeEscape,
  randomCase,
  toSqlHex,
  toUtf16Hex,
  toUtf7,
  urlEncode,
  urlEncodeChar,
  utf16BeToBase64,
  utf16LeToBase64,
  utf7Shift,
  utf8ToBase64,
  utf8ToHex,
  utf8ToHexEscapes,
} from '../src/utils/encoding.js'
import {
  detectTraversal,
  extractHostnameIp,
  extractIp,
  extractPath,
  extractQuotedStrings,
  isIpv4,
  mapCommandSpaces,
  mapSqlSegments,
  parseCommand,
  parseUrl,
  pickOne,
  pickRandom,
  randomMysqlVersion,
  replaceSqlStringLiterals,
  shuffle,
  splitSqlKeywords,
} from '../src/utils/helpers.js'
import { conditional, finalizeVariants, validated } from '../src/utils/variants.js'
import { CATEGORIES, EVASION_LAYERS, TARGETS } from '../src/data/techniques.js'
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

const XML_PAYLOAD = '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY marker SYSTEM "file:///tmp/matrix Ω marker">]><root>&marker;</root>'

const ADVERSARIAL_INPUTS = {
  sqli: {
    mysql: "SELECT CONCAT('O''Reilly Ω','x+y') FROM users WHERE note='FROM SELECT' # UNION",
    postgres: "SELECT $$FROM WHERE 'not a literal'$$, $tag$UNION SELECT$tag$, 'O''Reilly Ω' FROM users -- DELETE\r\nWHERE id = 7",
    mssql: "SELECT N'O''Reilly 😀' + SYSTEM_USER FROM [SELECT] -- DELETE\r\nWHERE 1=1",
    oracle: "SELECT q'[FROM WHERE O'Reilly]' AS label, 'Ω' FROM dual",
    sqlite: "SELECT 'O''Reilly 😀' AS value /* FROM WHERE */",
  },
  xss: {
    html: '<script>const text="confirm(1)";/*alert(2)*/window.confirm(4242)</script><img src=x onerror="prompt(7)">',
    js: 'const text="confirm(1)"; /* alert(2) */ window.confirm(4242); obj.prompt(7)',
    attr: 'onfocus="const text=\'alert(1)\'; confirm(4242)"',
  },
  cmdi: {
    linux: "printf '%s\\n' 'matrix Ω \\\"quoted\\\" 4242'",
    windows: 'echo matrix-marker',
    powershell: "Write-Output 'matrix Ω 4242'",
  },
  lfi: {
    php: '../../../var/www/Ω config.php',
    java: '../../../WEB-INF/web.xml',
    dotnet: '..\\..\\Windows\\win.ini',
    generic: '../../../etc/hosts',
  },
  ssrf: {
    http: 'http://user:p%40ss@127.0.0.1:8080/a/../admin?q=%2Fmatrix#frag',
    cloud: 'http://127.0.0.1:8080/a/../metadata?q=%2Fmatrix#frag',
  },
  ssti: {
    jinja2: "{{ user.__class__.__mro__ }}",
    twig: "{{ user.__class__.__mro__ }}",
    freemarker: '${(7 * 7)?string}',
  },
  xxe: {
    generic: XML_PAYLOAD,
    php: XML_PAYLOAD,
    java: XML_PAYLOAD,
  },
}

function variantKey(variant) {
  return variant.bytesBase64
    ? `bytes:${variant.encoding}:${variant.bytesBase64}`
    : `text:${variant.payload}`
}

function decodeHtmlEntities(value) {
  return value
    .replace(/&#x([0-9a-f]+);/gi, (_match, hex) => String.fromCodePoint(Number.parseInt(hex, 16)))
    .replace(/&#([0-9]+);/g, (_match, decimal) => String.fromCodePoint(Number.parseInt(decimal, 10)))
}

function decodeUtf16Base64(base64, littleEndian, hasBom) {
  const bytes = Buffer.from(base64, 'base64')
  const start = hasBom ? 2 : 0
  let value = ''
  for (let index = start; index < bytes.length; index += 2) {
    const unit = littleEndian
      ? bytes[index] | (bytes[index + 1] << 8)
      : (bytes[index] << 8) | bytes[index + 1]
    value += String.fromCharCode(unit)
  }
  return value
}

test('adversarial full-project regression matrix', { timeout: 60_000 }, async (t) => {
  await t.test('configuration is complete, unique, and routable to every engine', () => {
    const categoryIds = CATEGORIES.map((category) => category.id)
    assert.equal(new Set(categoryIds).size, categoryIds.length)
    assert.deepEqual([...categoryIds].sort(), Object.keys(ENGINES).sort())

    for (const category of categoryIds) {
      assert.ok(TARGETS[category]?.length > 0, `${category}: no targets`)
      assert.ok(EVASION_LAYERS[category]?.length > 0, `${category}: no layers`)
      assert.equal(new Set(TARGETS[category].map(({ id }) => id)).size, TARGETS[category].length)
      assert.equal(new Set(EVASION_LAYERS[category].map(({ id }) => id)).size, EVASION_LAYERS[category].length)

      for (const layer of EVASION_LAYERS[category]) {
        for (const target of layer.targets ?? []) {
          assert.ok(TARGETS[category].some(({ id }) => id === target), `${category}/${layer.id}: unknown target ${target}`)
        }
      }
    }
  })

  await t.test('every UTF and transport encoder round-trips adversarial Unicode', () => {
    const corpus = ['', 'ASCII + % & quotes \' " \\', 'Ώ', '中文', '😀🚀', 'line1\r\nline2', '\0tail']

    for (const value of corpus) {
      assert.equal(decodeURIComponent(urlEncode(value)), value)
      assert.equal(decodeURIComponent(decodeURIComponent(doubleUrlEncode(value))), value)
      assert.equal(decodeHtmlEntities(htmlHexEncode(value)), value)
      assert.equal(decodeHtmlEntities(htmlDecimalEncode(value)), value)
      assert.equal(Buffer.from(utf8ToBase64(value), 'base64').toString('utf8'), value)
      assert.equal(Buffer.from(utf8ToHex(value), 'hex').toString('utf8'), value)
      assert.equal(Buffer.from(toSqlHex(value).slice(2), 'hex').toString('utf8'), value)

      const escapedBytes = utf8ToHexEscapes(value).match(/\\x([0-9a-f]{2})/g) ?? []
      assert.equal(Buffer.from(escapedBytes.map((item) => Number.parseInt(item.slice(2), 16))).toString('utf8'), value)
      assert.equal(decodeUtf16Base64(utf16LeToBase64(value), true, true), value)
      assert.equal(decodeUtf16Base64(utf16BeToBase64(value), false, true), value)
      assert.equal(decodeUtf16Base64(utf16LeToBase64(value, false), true, false), value)
      assert.equal(decodeUtf16Base64(utf16BeToBase64(value, false), false, false), value)
      assert.equal(Function(`"use strict"; return "${jsUnicodeEscape(value)}"`)(), value)
      assert.equal(Function(`"use strict"; return "${hexEscape(value)}"`)(), value)

      const utf16HexBytes = (toUtf16Hex(value).match(/\\x([0-9a-f]{2})/g) ?? [])
        .map((item) => Number.parseInt(item.slice(2), 16))
      assert.equal(decodeUtf16Base64(Buffer.from(utf16HexBytes).toString('base64'), false, false), value)
    }

    assert.equal(urlEncodeChar('😀'), '%F0%9F%98%80')
    assert.equal(toUtf7('A+Ω'), 'A+-+A6k-')
    assert.equal(utf7Shift('Ω'), '+A6k-')
    assert.equal(alternatingCase('a1b-c', 0), 'A1b-C')
    assert.equal(randomCase('a1b-c'), 'A1b-C')
  })

  await t.test('IPv4, random collection, and finalizer boundary contracts hold', () => {
    assert.equal(ipToDecimal('0.0.0.0'), 0)
    assert.equal(ipToDecimal('255.255.255.255'), 0xffffffff)
    assert.equal(ipToHex('127.0.0.1'), '0x7f000001')
    assert.equal(ipToOctal('127.0.0.1'), '0177.0000.0000.0001')
    for (const invalid of ['1.2.3', '1.2.3.4.5', '-1.0.0.0', '1e2.0.0.1', '256.0.0.1']) {
      assert.equal(isIpv4(invalid), false)
      assert.throws(() => ipToDecimal(invalid))
    }

    const source = Object.freeze(['a', 'b', 'c', 'd'])
    for (let run = 0; run < 50; run += 1) {
      assert.deepEqual([...shuffle(source)].sort(), [...source])
      assert.equal(pickRandom(source, 99).length, source.length)
      assert.ok(source.includes(pickOne(source)))
      assert.match(randomMysqlVersion(), /^50(?:0\d{2}|100|500)$/)
    }

    const finalized = finalizeVariants([
      { payload: 'original', label: 'Original', layers: [] },
      { payload: 'original', label: 'No-op', layers: ['a'] },
      { payload: 'changed', label: 'Changed', layers: ['a', 'not-selected'] },
      { payload: 'changed', label: 'Duplicate', layers: ['b'] },
      { payload: 'ignored', label: 'Ignored', layers: ['not-selected'] },
    ], ['a', 'b'])
    assert.equal(finalized.length, 2)
    assert.deepEqual(finalized[1].layers.sort(), ['a', 'b'])
    assert.equal(finalized[1].validity, 'conditional')
    assert.deepEqual(conditional('runtime'), { validity: 'conditional', note: 'runtime' })
    assert.deepEqual(validated(), { validity: 'validated' })
    assert.deepEqual(validated('checked'), { validity: 'validated', note: 'checked' })
  })

  await t.test('lexers preserve SQL literals/comments and quoted command regions', () => {
    const sql = "SELECT $$FROM WHERE 'inside'$$, $tag$UNION SELECT$tag$, q'[DELETE 'quoted']', 'outside' FROM dual -- UPDATE\r\nWHERE 1=1"
    const tokens = splitSqlKeywords(sql)
    const keywords = tokens.filter(({ type }) => type === 'keyword').map(({ value }) => value.toUpperCase())
    assert.deepEqual(keywords, ['SELECT', 'FROM', 'WHERE'])

    const mapped = mapSqlSegments(sql, (code) => code.replace(/\b(?:SELECT|FROM|WHERE)\b/g, 'TOKEN'))
    assert.match(mapped, /\$\$FROM WHERE 'inside'\$\$/)
    assert.match(mapped, /\$tag\$UNION SELECT\$tag\$/)
    assert.match(mapped, /q'\[DELETE 'quoted'\]'/)
    assert.match(mapped, /-- UPDATE\r\n/)

    const literals = extractQuotedStrings(sql)
    assert.deepEqual(literals.map(({ content }) => content), ['outside'])
    const replaced = replaceSqlStringLiterals(sql, (content) => `[${content}]`)
    assert.match(replaced, /\[outside\]/)
    assert.match(replaced, /q'\[DELETE 'quoted'\]'/)

    assert.deepEqual(parseCommand('%0D%0A"C:\\Program Files\\tool.exe" "a b" c'), {
      prefix: '%0D%0A',
      command: '"C:\\Program Files\\tool.exe"',
      args: '"a b" c',
      raw: '%0D%0A"C:\\Program Files\\tool.exe" "a b" c',
    })
    assert.equal(mapCommandSpaces('one "two three" \'four five\' six\\ seven', '_', '%20'), 'one_"two%20three"_\'four%20five\'_six\\ seven')
    assert.deepEqual(detectTraversal('/../../safe/../target'), {
      depth: 2,
      targetFile: 'safe/../target',
      raw: '/../../safe/../target',
      leadingSlash: true,
    })
  })

  await t.test('raw URL parsing never normalizes the authority suffix', () => {
    const raw = 'https://us%40er:p%3Ass@[::1]:8443/a/../b//c?q=%2F%2E%2E#fragment'
    const parsed = parseUrl(raw)
    assert.equal(parsed.valid, true)
    assert.equal(parsed.protocol, 'https:')
    assert.equal(parsed.credentials, 'us%40er:p%3Ass@')
    assert.equal(parsed.hostname, '::1')
    assert.equal(parsed.port, '8443')
    assert.equal(parsed.rawSuffix, '/a/../b//c?q=%2F%2E%2E#fragment')
    assert.equal(extractPath(raw), parsed.rawSuffix)
    assert.equal(extractHostnameIp(raw), null)
    assert.equal(extractIp('https://example.test/path/999.1.1.1?q=127.0.0.1'), '127.0.0.1')
    assert.equal(parseUrl('/relative/path').valid, false)
  })

  await t.test('every supported target/layer survives a new adversarial corpus deterministically', () => {
    let exercised = 0
    for (const [category, targets] of Object.entries(TARGETS)) {
      for (const { id: target } of targets) {
        const input = ADVERSARIAL_INPUTS[category][target]
        assert.equal(typeof input, 'string', `${category}/${target}: missing adversarial input`)
        const supported = EVASION_LAYERS[category].filter((layer) => !layer.targets || layer.targets.includes(target))

        for (const { id: layer } of supported) {
          const first = ENGINES[category](input, [layer], target)
          const second = ENGINES[category](input, [layer], target)
          assert.deepEqual(first, second, `${category}/${target}/${layer}: nondeterministic`)
          assert.equal(first[0]?.payload, input, `${category}/${target}/${layer}: original changed`)
          assert.ok(first.length > 1, `${category}/${target}/${layer}: layer unexpectedly inapplicable`)
          assert.ok(first.length <= 13)

          const keys = new Set()
          for (const variant of first) {
            assert.equal(typeof variant.payload, 'string')
            assert.ok(Array.isArray(variant.layers))
            assert.doesNotMatch(variant.payload, /\b(?:undefined|NaN)\b/)
            const key = variantKey(variant)
            assert.equal(keys.has(key), false, `${category}/${target}/${layer}: duplicate`)
            keys.add(key)
            if (variant.label !== 'Original') {
              assert.ok(['validated', 'conditional', 'legacy'].includes(variant.validity))
              assert.ok(variant.layers.includes(layer))
            }
            if (variant.bytesBase64) {
              assert.equal(Buffer.from(variant.bytesBase64, 'base64').toString('base64'), variant.bytesBase64)
            }
          }
          exercised += 1
        }
      }
    }
    assert.ok(exercised >= 85, `only ${exercised} target/layer branches exercised`)
  })

  await t.test('JavaScript obfuscation changes global calls but not strings, comments, or object methods', () => {
    const input = 'const text="confirm(1)"; /* alert(2) */ window.confirm(4242); obj.prompt(7)'
    const variants = generateXssVariants(input, ['js-obfuscation'], 'js').slice(1)
    assert.ok(variants.length > 0)
    for (const variant of variants) {
      assert.match(variant.payload, /"confirm\(1\)"/)
      assert.match(variant.payload, /\/\* alert\(2\) \*\//)
      assert.match(variant.payload, /obj\.prompt\(7\)/)
      assert.doesNotMatch(variant.payload, /window\.confirm\(4242\)/)
      assert.doesNotThrow(() => new Function(variant.payload))
    }
  })

  await t.test('complex PowerShell scripts retain structure and pre-existing transport literals', () => {
    const script = [
      'function Get-Matrix {',
      '  param([string]$Value)',
      '  # spacing and Unicode must survive every applicable transform',
      '  try {',
      '    $items = @(\'alpha beta\', "quoted \' value")',
      '    return [pscustomobject]@{ Value = $Value; Count = $items.Count }',
      '  } catch { throw }',
      '}',
      "$literal = 'already%20encoded + plus'",
      '$result = Get-Matrix -Value \'matrix Ω 4242\'',
      'Write-Output "$($result.Value)|$literal|$($result.Count)"',
    ].join('\n')
    const expected = 'matrix Ω 4242|already%20encoded + plus|2'

    assert.equal(generateCmdiVariants(script, ['keyword-bypass'], 'powershell').length, 1)

    for (const layer of ['space-bypass', 'newline-bypass', 'variable-expansion', 'hex-cmd']) {
      const variants = generateCmdiVariants(script, [layer], 'powershell').slice(1)
      assert.ok(variants.length > 0, layer)
      for (const variant of variants) {
        const executable = ['space-bypass', 'newline-bypass'].includes(layer)
          ? decodeURIComponent(variant.payload.replace(/\+/g, ' '))
          : variant.payload
        const result = spawnSync('powershell.exe', ['-NoProfile', '-Command', executable], { encoding: 'utf8' })
        assert.equal(result.status, 0, `${layer}: ${variant.payload}\n${result.stderr}`)
        assert.equal(result.stdout.trim(), expected, `${layer}: ${variant.payload}`)
      }
    }
  })

  await t.test('binary XML variants decode exactly and parse without resolving external entities', () => {
    const variants = generateXxeVariants(XML_PAYLOAD, ['utf16'], 'generic').slice(1)
    assert.equal(variants.length, 2)
    for (const variant of variants) {
      const littleEndian = variant.encoding === 'UTF-16LE'
      assert.equal(decodeUtf16Base64(variant.bytesBase64, littleEndian, true), variant.payload)
      const parsed = spawnSync(
        'python',
        ['-c', 'import io,sys,xml.sax; from xml.sax import handler; p=xml.sax.make_parser(); p.setFeature(handler.feature_external_ges,False); p.parse(io.BytesIO(sys.stdin.buffer.read()))'],
        { input: Buffer.from(variant.bytesBase64, 'base64') },
      )
      assert.equal(parsed.status, 0, `${variant.encoding}: ${parsed.stderr?.toString()}`)
    }
  })
})
