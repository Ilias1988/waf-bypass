/**
 * Helper Utilities for WAF Bypass Toolkit
 * Random generators, shufflers, and string manipulation.
 */

/** Shuffle an array (Fisher-Yates) */
export function shuffle(arr) {
  const a = [...arr]
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]]
  }
  return a
}

/** Pick N random items from array */
export function pickRandom(arr, n) {
  const shuffled = shuffle(arr)
  return shuffled.slice(0, Math.min(n, arr.length))
}

/** Pick one random item from array */
export function pickOne(arr) {
  return arr[Math.floor(Math.random() * arr.length)]
}

/** Generate a random version number for MySQL comments */
export function randomMysqlVersion() {
  const versions = ['50000', '50001', '50002', '50003', '50004', '50005', '50006', '50007', '50008', '50009', '50010', '50100', '50500']
  return pickOne(versions)
}

/** Split a string into SQL keywords and non-keywords */
export function splitSqlKeywords(payload) {
  const sqlKeywords = /\b(SELECT|UNION|INSERT|UPDATE|DELETE|FROM|WHERE|AND|OR|ORDER|BY|GROUP|HAVING|LIMIT|JOIN|LEFT|RIGHT|INNER|OUTER|ON|INTO|VALUES|SET|DROP|CREATE|ALTER|TABLE|DATABASE|NULL|NOT|IN|LIKE|BETWEEN|EXISTS|CASE|WHEN|THEN|ELSE|END|AS|IS|DISTINCT|ALL|ANY|SOME|TRUE|FALSE|SLEEP|BENCHMARK|EXTRACTVALUE|UPDATEXML|LOAD_FILE|OUTFILE|DUMPFILE|CONCAT|CHAR|HEX|UNHEX|ASCII|ORD|MID|SUBSTRING|IF|IFNULL|NULLIF|COALESCE|CAST|CONVERT|VERSION|USER|SCHEMA|INFORMATION_SCHEMA|GROUP_CONCAT|CONCAT_WS)\b/gi
  
  const tokens = []
  let lastIndex = 0
  let match
  
  while ((match = sqlKeywords.exec(payload)) !== null) {
    if (match.index > lastIndex) {
      tokens.push({ type: 'other', value: payload.slice(lastIndex, match.index) })
    }
    tokens.push({ type: 'keyword', value: match[0] })
    lastIndex = match.index + match[0].length
  }
  
  if (lastIndex < payload.length) {
    tokens.push({ type: 'other', value: payload.slice(lastIndex) })
  }
  
  return tokens
}

/** Extract quoted strings from SQL payload */
export function extractQuotedStrings(payload) {
  const matches = []
  const regex = /'([^']*?)'/g
  let match
  while ((match = regex.exec(payload)) !== null) {
    matches.push({ full: match[0], content: match[1], index: match.index })
  }
  return matches
}

/** Parse URL into components */
export function parseUrl(url) {
  try {
    const u = new URL(url)
    return {
      protocol: u.protocol,
      hostname: u.hostname,
      port: u.port,
      pathname: u.pathname,
      search: u.search,
      hash: u.hash,
      valid: true,
    }
  } catch {
    return { valid: false, raw: url }
  }
}

/** Extract IP address from URL */
export function extractIp(url) {
  const match = url.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/)
  return match ? match[1] : null
}

/** Extract path from URL */
export function extractPath(url) {
  try {
    const u = new URL(url)
    return u.pathname + u.search + u.hash
  } catch {
    const pathMatch = url.match(/\/(.*)$/)
    return pathMatch ? '/' + pathMatch[1] : '/'
  }
}

/** Split command injection payload into prefix + command + args */
export function parseCommand(payload) {
  const trimmed = payload.trim()
  
  // Find the separator prefix (; | && || ` $( %0a \n)
  const prefixMatch = trimmed.match(/^([;|&`\n%]+\s*|\$\(\s*)/)
  const prefix = prefixMatch ? prefixMatch[0] : ''
  const rest = trimmed.slice(prefix.length).trim()
  
  // Split into command and arguments
  const parts = rest.split(/\s+/)
  const command = parts[0] || ''
  const args = parts.slice(1).join(' ')
  
  return { prefix, command, args, raw: trimmed }
}

/** Detect path traversal sequences */
export function detectTraversal(payload) {
  const sequences = payload.match(/(\.\.\/?)+/g) || []
  const depth = sequences.reduce((max, seq) => {
    const d = (seq.match(/\.\./g) || []).length
    return Math.max(max, d)
  }, 0)
  
  // Extract the target file
  const afterTraversal = payload.replace(/^(\.\.\/?)+/, '')
  
  return { depth, targetFile: afterTraversal, raw: payload }
}
