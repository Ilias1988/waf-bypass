/**
 * Encoding Utilities for WAF Bypass Toolkit
 * Core encoding/decoding functions used across all engines.
 */

/** URL-encode a single character */
export function urlEncodeChar(c) {
  return '%' + c.charCodeAt(0).toString(16).padStart(2, '0').toUpperCase()
}

/** URL-encode an entire string */
export function urlEncode(str) {
  return Array.from(str).map(urlEncodeChar).join('')
}

/** Double URL-encode a string */
export function doubleUrlEncode(str) {
  return urlEncode(urlEncode(str))
}

/** HTML hex entity encode: &#xHH; */
export function htmlHexEncode(str) {
  return Array.from(str)
    .map((c) => '&#x' + c.charCodeAt(0).toString(16).toUpperCase() + ';')
    .join('')
}

/** HTML decimal entity encode: &#DDD; */
export function htmlDecimalEncode(str) {
  return Array.from(str)
    .map((c) => '&#' + c.charCodeAt(0) + ';')
    .join('')
}

/** Hex string encoding for SQL: 0x... */
export function toSqlHex(str) {
  return '0x' + Array.from(str)
    .map((c) => c.charCodeAt(0).toString(16).padStart(2, '0'))
    .join('')
}

/** Random case toggle per character */
export function randomCase(str) {
  return Array.from(str)
    .map((c) => (Math.random() > 0.5 ? c.toUpperCase() : c.toLowerCase()))
    .join('')
}

/** Convert IP string to decimal number */
export function ipToDecimal(ip) {
  const parts = ip.split('.').map(Number)
  return ((parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]) >>> 0
}

/** Convert IP string to hex */
export function ipToHex(ip) {
  return '0x' + ipToDecimal(ip).toString(16).padStart(8, '0')
}

/** Convert IP string to octal parts */
export function ipToOctal(ip) {
  return ip.split('.').map((p) => '0' + Number(p).toString(8).padStart(3, '0')).join('.')
}

/** UTF-7 encode a string (simplified) */
export function toUtf7(str) {
  let result = ''
  let inBase64 = false
  let buffer = ''

  for (const char of str) {
    const code = char.charCodeAt(0)
    if (code >= 0x20 && code <= 0x7e && char !== '+') {
      if (inBase64) {
        result += '+' + btoa(buffer) .replace(/=+$/, '') + '-'
        buffer = ''
        inBase64 = false
      }
      result += char
    } else {
      if (!inBase64) inBase64 = true
      // Store as UTF-16BE bytes
      buffer += String.fromCharCode((code >> 8) & 0xff, code & 0xff)
    }
  }
  if (inBase64) {
    result += '+' + btoa(buffer).replace(/=+$/, '') + '-'
  }
  return result
}

/** Simulate UTF-16 hex representation of XML content */
export function toUtf16Hex(str) {
  return Array.from(str)
    .map((c) => {
      const code = c.charCodeAt(0)
      return '\\x' + ((code >> 8) & 0xff).toString(16).padStart(2, '0') +
        '\\x' + (code & 0xff).toString(16).padStart(2, '0')
    })
    .join('')
}

/** Hex escape for template strings: \x5f */
export function hexEscape(str) {
  return Array.from(str)
    .map((c) => '\\x' + c.charCodeAt(0).toString(16).padStart(2, '0'))
    .join('')
}

/** Unicode escape for JS: \u0041 */
export function jsUnicodeEscape(str) {
  return Array.from(str)
    .map((c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'))
    .join('')
}
