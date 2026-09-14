import test from 'node:test'
import assert from 'node:assert/strict'

import {
  htmlHexEncode,
  ipToDecimal,
  jsUnicodeEscape,
  urlEncode,
  utf16LeToBase64,
  utf8ToBase64,
} from '../src/utils/encoding.js'

test('Unicode encoders operate on code points and UTF-8 bytes', () => {
  assert.equal(urlEncode('Ω'), '%CE%A9')
  assert.equal(urlEncode('😀'), '%F0%9F%98%80')
  assert.equal(htmlHexEncode('😀'), '&#x1F600;')
  assert.equal(jsUnicodeEscape('😀'), '\\u{1f600}')
  assert.equal(Buffer.from(utf8ToBase64('Ω'), 'base64').toString('utf8'), 'Ω')
})

test('PowerShell-compatible UTF-16LE Base64 excludes a BOM when requested', () => {
  const encoded = utf16LeToBase64('whoami', false)
  assert.equal(Buffer.from(encoded, 'base64').toString('utf16le'), 'whoami')
})

test('IPv4 conversion validates every octet', () => {
  assert.equal(ipToDecimal('127.0.0.1'), 2130706433)
  assert.throws(() => ipToDecimal('999.0.0.1'), /Invalid IPv4/)
})
