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

function findSqlProtectedRanges(payload) {
  const ranges = []
  let index = 0

  while (index < payload.length) {
    const start = index
    const delimiter = payload[index]

    if (delimiter === '$') {
      const opening = payload.slice(index).match(/^\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$/)?.[0]
      if (opening) {
        const closing = payload.indexOf(opening, index + opening.length)
        if (closing !== -1) {
          index = closing + opening.length
          ranges.push({ start, end: index })
          continue
        }
      }
    }

    if ((delimiter === 'q' || delimiter === 'Q') && payload[index + 1] === "'" && index + 3 < payload.length) {
      const opening = payload[index + 2]
      const paired = { '[': ']', '{': '}', '(': ')', '<': '>' }
      const closingDelimiter = paired[opening] ?? opening
      const closing = payload.indexOf(`${closingDelimiter}'`, index + 3)
      if (closing !== -1) {
        index = closing + 2
        ranges.push({ start, end: index })
        continue
      }
    }

    if (delimiter === "'" || delimiter === '"' || delimiter === '`' || delimiter === '[') {
      const closing = delimiter === '[' ? ']' : delimiter
      index += 1
      while (index < payload.length) {
        if (delimiter !== '[' && payload[index] === '\\' && index + 1 < payload.length) {
          index += 2
          continue
        }
        if (payload[index] === closing) {
          if (payload[index + 1] === closing) {
            index += 2
            continue
          }
          index += 1
          break
        }
        index += 1
      }
      ranges.push({ start, end: index })
      continue
    }

    if (payload.startsWith('/*', index)) {
      const closing = payload.indexOf('*/', index + 2)
      index = closing === -1 ? payload.length : closing + 2
      ranges.push({ start, end: index })
      continue
    }

    if (payload.startsWith('--', index) || delimiter === '#') {
      const newline = payload.indexOf('\n', index + 1)
      // Keep the newline protected as well: replacing/removing it can extend a
      // line comment over the SQL statement that follows.
      index = newline === -1 ? payload.length : newline + 1
      ranges.push({ start, end: index })
      continue
    }

    index += 1
  }

  return ranges
}

/** Apply transformations only to SQL code, never inside literals/identifiers/comments. */
export function mapSqlSegments(payload, codeMapper, protectedMapper = (value) => value) {
  const ranges = findSqlProtectedRanges(payload)
  let cursor = 0
  let result = ''

  for (const range of ranges) {
    result += codeMapper(payload.slice(cursor, range.start))
    result += protectedMapper(payload.slice(range.start, range.end))
    cursor = range.end
  }

  return result + codeMapper(payload.slice(cursor))
}

/** Split SQL keywords while keeping literals, identifiers, and comments opaque. */
export function splitSqlKeywords(payload) {
  const sqlKeywords = /\b(SELECT|UNION|INSERT|UPDATE|DELETE|FROM|WHERE|AND|OR|ORDER|BY|GROUP|HAVING|LIMIT|JOIN|LEFT|RIGHT|INNER|OUTER|ON|INTO|VALUES|SET|DROP|CREATE|ALTER|TABLE|DATABASE|NULL|NOT|IN|LIKE|BETWEEN|EXISTS|CASE|WHEN|THEN|ELSE|END|AS|IS|DISTINCT|ALL|ANY|SOME|TRUE|FALSE|SLEEP|BENCHMARK|EXTRACTVALUE|UPDATEXML|LOAD_FILE|OUTFILE|DUMPFILE|CONCAT|CHAR|HEX|UNHEX|ASCII|ORD|MID|SUBSTRING|IF|IFNULL|NULLIF|COALESCE|CAST|CONVERT|VERSION|USER|SCHEMA|INFORMATION_SCHEMA|GROUP_CONCAT|CONCAT_WS)\b/gi
  const protectedRanges = findSqlProtectedRanges(payload)

  const tokens = []
  let lastIndex = 0
  let match

  while ((match = sqlKeywords.exec(payload)) !== null) {
    if (protectedRanges.some((range) => match.index >= range.start && match.index < range.end)) {
      continue
    }
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
export function extractQuotedStrings(payload, { backslashEscapes = false } = {}) {
  const matches = []
  const protectedRanges = findSqlProtectedRanges(payload)
  let index = 0

  while (index < payload.length) {
    const enclosingRange = protectedRanges.find((range) => range.start < index && index < range.end)
    if (enclosingRange) {
      index = enclosingRange.end
      continue
    }
    if (payload[index] !== "'") {
      index += 1
      continue
    }

    const start = index
    let content = ''
    index += 1

    while (index < payload.length) {
      if (backslashEscapes && payload[index] === '\\' && index + 1 < payload.length) {
        content += payload[index + 1]
        index += 2
        continue
      }
      if (payload[index] === "'" && payload[index + 1] === "'") {
        content += "'"
        index += 2
        continue
      }
      if (payload[index] === "'") {
        index += 1
        matches.push({
          full: payload.slice(start, index),
          content,
          index: start,
          end: index,
        })
        break
      }
      content += payload[index]
      index += 1
    }
  }
  return matches
}

/** Replace SQL single-quoted literals without losing doubled-quote escapes. */
export function replaceSqlStringLiterals(payload, replacer, options) {
  const strings = extractQuotedStrings(payload, options)
  if (strings.length === 0) return payload

  let result = ''
  let cursor = 0
  strings.forEach((string, index) => {
    result += payload.slice(cursor, string.index)
    result += replacer(string.content, string, index)
    cursor = string.end
  })
  return result + payload.slice(cursor)
}

function splitRawAuthority(authority) {
  const at = authority.lastIndexOf('@')
  const credentials = at === -1 ? '' : authority.slice(0, at + 1)
  const hostPort = at === -1 ? authority : authority.slice(at + 1)
  let hostname = hostPort
  let port = ''

  if (hostPort.startsWith('[')) {
    const closing = hostPort.indexOf(']')
    if (closing !== -1) {
      hostname = hostPort.slice(0, closing + 1)
      if (hostPort[closing + 1] === ':') port = hostPort.slice(closing + 2)
    }
  } else {
    const colon = hostPort.lastIndexOf(':')
    if (colon !== -1 && /^\d*$/.test(hostPort.slice(colon + 1))) {
      hostname = hostPort.slice(0, colon)
      port = hostPort.slice(colon + 1)
    }
  }

  return { credentials, hostname, port }
}

function splitRawSuffix(suffix) {
  const hashIndex = suffix.indexOf('#')
  const beforeHash = hashIndex === -1 ? suffix : suffix.slice(0, hashIndex)
  const hash = hashIndex === -1 ? '' : suffix.slice(hashIndex)
  const searchIndex = beforeHash.indexOf('?')
  const pathname = searchIndex === -1 ? beforeHash : beforeHash.slice(0, searchIndex)
  const search = searchIndex === -1 ? '' : beforeHash.slice(searchIndex)
  return { pathname, search, hash }
}

/** Parse an absolute URL while retaining its exact raw authority suffix. */
export function parseUrl(url) {
  try {
    const raw = String(url)
    const absolute = raw.match(/^([A-Za-z][A-Za-z\d+.-]*:)\/\/([^/?#]*)([\s\S]*)$/)
    if (!absolute) return { valid: false, raw }
    const u = new URL(raw)
    const authority = splitRawAuthority(absolute[2])
    const suffix = splitRawSuffix(absolute[3])
    return {
      protocol: absolute[1],
      username: u.username,
      password: u.password,
      host: u.host,
      hostname: authority.hostname.replace(/^\[|\]$/g, ''),
      port: authority.port,
      credentials: authority.credentials,
      pathname: suffix.pathname,
      search: suffix.search,
      hash: suffix.hash,
      rawAuthority: absolute[2],
      rawSuffix: absolute[3],
      normalizedHref: u.href,
      valid: true,
    }
  } catch {
    return { valid: false, raw: url }
  }
}

/** Extract IP address from URL */
export function extractIp(url) {
  const matches = String(url).match(/(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])/g) || []
  return matches.find(isIpv4) ?? null
}

export function isIpv4(value) {
  const parts = String(value).split('.')
  return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255)
}

/** Return an IPv4 literal only when it is the URL authority, never from path/query data. */
export function extractHostnameIp(value) {
  const parsed = parseUrl(value)
  if (parsed.valid) return isIpv4(parsed.hostname) ? parsed.hostname : null
  return isIpv4(value) ? value : null
}

/** Extract path from URL */
export function extractPath(url) {
  const parsed = parseUrl(url)
  if (parsed.valid) return parsed.rawSuffix || '/'
  const pathMatch = url.match(/\/(.*)$/)
  return pathMatch ? '/' + pathMatch[1] : '/'
}

/** Split command injection payload into prefix + command + args */
export function parseCommand(payload) {
  const trimmed = payload.trim()

  // Match complete separators. A bare '%' must never consume only the first
  // character of an encoded newline such as %0a.
  const prefixMatch = trimmed.match(/^(?:(?:%0[dD]%0[aA])|(?:%0[aAdD])|&&|\|\||[;|&]|\r?\n)\s*/)
  const prefix = prefixMatch ? prefixMatch[0] : ''
  const rest = trimmed.slice(prefix.length).trim()

  const tokenMatch = rest.match(/^(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|\S+)/)
  const command = tokenMatch?.[0] ?? ''
  const args = rest.slice(command.length).trim()
  
  return { prefix, command, args, raw: trimmed }
}

/** Replace spaces without corrupting quoted command arguments. */
export function mapCommandSpaces(value, unquotedReplacement, quotedReplacement = ' ') {
  let quote = null
  let result = ''

  for (let index = 0; index < value.length; index += 1) {
    const char = value[index]
    if (char === '\\' && index + 1 < value.length) {
      result += char + value[++index]
      continue
    }
    if ((char === "'" || char === '"') && (!quote || quote === char)) {
      quote = quote ? null : char
      result += char
      continue
    }
    if (char === ' ') {
      result += quote ? quotedReplacement : unquotedReplacement
      continue
    }
    result += char
  }

  return result
}

/** Detect path traversal sequences */
export function detectTraversal(payload) {
  const raw = String(payload)
  const leadingSlash = /^[\\/]/.test(raw)
  const body = leadingSlash ? raw.slice(1) : raw
  const prefixMatch = body.match(/^(?:(?:\.\.)[\\/])+/)
  const prefix = prefixMatch?.[0] ?? ''
  const depth = (prefix.match(/\.\./g) || []).length
  const targetFile = prefix ? body.slice(prefix.length) : body

  return { depth, targetFile, raw, leadingSlash }
}
