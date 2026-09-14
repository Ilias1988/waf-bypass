/** Encoding utilities shared by every payload engine. */

const textEncoder = new TextEncoder()

function utf8Bytes(value) {
  return textEncoder.encode(String(value))
}
function bytesToBase64(bytes) {
  let binary = ''
  const chunkSize = 0x8000
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize))
  }
  return btoa(binary)
}

/** URL-encode one Unicode character as UTF-8 bytes. */
export function urlEncodeChar(char) {
  return Array.from(utf8Bytes(char))
    .map((byte) => `%${byte.toString(16).padStart(2, '0').toUpperCase()}`)
    .join('')
}

/** URL-encode an entire string, including normally unreserved characters. */
export function urlEncode(value) {
  return Array.from(String(value)).map(urlEncodeChar).join('')
}

export function doubleUrlEncode(value) {
  return urlEncode(urlEncode(value))
}

export function htmlHexEncode(value) {
  return Array.from(String(value))
    .map((char) => `&#x${char.codePointAt(0).toString(16).toUpperCase()};`)
    .join('')
}

export function htmlDecimalEncode(value) {
  return Array.from(String(value))
    .map((char) => `&#${char.codePointAt(0)};`)
    .join('')
}

/** SQL hex representation of the UTF-8 bytes used by the web request. */
export function toSqlHex(value) {
  return `0x${Array.from(utf8Bytes(value))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')}`
}

/** Stable alternating case; offset creates reproducible variants. */
export function alternatingCase(value, offset = 0) {
  let letterIndex = 0
  return Array.from(String(value)).map((char) => {
    if (!/[a-z]/i.test(char)) return char
    const upper = (letterIndex++ + offset) % 2 === 0
    return upper ? char.toUpperCase() : char.toLowerCase()
  }).join('')
}

/** Backwards-compatible deterministic case transform. */
export function randomCase(value) {
  return alternatingCase(value)
}

function parseIpv4(ip) {
  const parts = String(ip).split('.')
  if (parts.length !== 4 || parts.some((part) => !/^\d{1,3}$/.test(part))) {
    throw new TypeError(`Invalid IPv4 address: ${ip}`)
  }
  const numbers = parts.map(Number)
  if (numbers.some((part) => part < 0 || part > 255)) {
    throw new TypeError(`Invalid IPv4 address: ${ip}`)
  }
  return numbers
}

export function ipToDecimal(ip) {
  const [a, b, c, d] = parseIpv4(ip)
  return (((a * 256 + b) * 256 + c) * 256 + d) >>> 0
}

export function ipToHex(ip) {
  return `0x${ipToDecimal(ip).toString(16).padStart(8, '0')}`
}

export function ipToOctal(ip) {
  return parseIpv4(ip)
    .map((part) => `0${part.toString(8).padStart(3, '0')}`)
    .join('.')
}

export function utf8ToBase64(value) {
  return bytesToBase64(utf8Bytes(value))
}

export function utf8ToHex(value) {
  return Array.from(utf8Bytes(value))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
}

export function utf8ToHexEscapes(value) {
  return Array.from(utf8Bytes(value))
    .map((byte) => `\\x${byte.toString(16).padStart(2, '0')}`)
    .join('')
}

function utf16Bytes(value, littleEndian, includeBom = true) {
  const input = String(value)
  const bytes = []
  if (includeBom) bytes.push(...(littleEndian ? [0xff, 0xfe] : [0xfe, 0xff]))
  for (let index = 0; index < input.length; index += 1) {
    const codeUnit = input.charCodeAt(index)
    const high = (codeUnit >> 8) & 0xff
    const low = codeUnit & 0xff
    bytes.push(...(littleEndian ? [low, high] : [high, low]))
  }
  return Uint8Array.from(bytes)
}

export function utf16LeToBase64(value, includeBom = true) {
  return bytesToBase64(utf16Bytes(value, true, includeBom))
}

export function utf16BeToBase64(value, includeBom = true) {
  return bytesToBase64(utf16Bytes(value, false, includeBom))
}

/** Encode a string as one UTF-7 shifted sequence. */
export function utf7Shift(value) {
  const encoded = bytesToBase64(utf16Bytes(value, false, false)).replace(/=+$/, '')
  return `+${encoded}-`
}

/** RFC 2152-style UTF-7 encoding for non-direct characters. */
export function toUtf7(value) {
  let result = ''
  let buffered = ''

  const flush = () => {
    if (!buffered) return
    result += utf7Shift(buffered)
    buffered = ''
  }

  for (const char of String(value)) {
    const codePoint = char.codePointAt(0)
    const direct = codePoint >= 0x20 && codePoint <= 0x7e && char !== '+'
    if (direct) {
      flush()
      result += char
    } else if (char === '+') {
      flush()
      result += '+-'
    } else {
      buffered += char
    }
  }
  flush()
  return result
}

export function toUtf16Hex(value) {
  let result = ''
  const input = String(value)
  for (let index = 0; index < input.length; index += 1) {
    const codeUnit = input.charCodeAt(index)
    result += `\\x${((codeUnit >> 8) & 0xff).toString(16).padStart(2, '0')}`
    result += `\\x${(codeUnit & 0xff).toString(16).padStart(2, '0')}`
  }
  return result
}

export function hexEscape(value) {
  return Array.from(String(value)).map((char) => {
    const codePoint = char.codePointAt(0)
    return codePoint <= 0xff
      ? `\\x${codePoint.toString(16).padStart(2, '0')}`
      : `\\u{${codePoint.toString(16)}}`
  }).join('')
}

export function jsUnicodeEscape(value) {
  return Array.from(String(value)).map((char) => {
    const codePoint = char.codePointAt(0)
    return codePoint <= 0xffff
      ? `\\u${codePoint.toString(16).padStart(4, '0')}`
      : `\\u{${codePoint.toString(16)}}`
  }).join('')
}
