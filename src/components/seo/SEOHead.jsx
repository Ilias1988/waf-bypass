import { Helmet } from 'react-helmet-async'

const BASE_URL = 'https://waf-bypass.dev'

const SEO_DATA = {
  sqli: {
    title: 'SQLi Payload Transformer for WAF Testing | WAF Bypass Toolkit',
    description: 'Generate dialect-aware SQL injection variants with token-safe whitespace, comments, casing and encoding for authorized WAF testing.',
    keywords: 'SQL injection bypass, SQLi WAF bypass, SQL injection obfuscator, WAF evasion SQLi, Cloudflare SQL bypass, ModSecurity bypass, union select bypass, hex encoding SQL',
  },
  xss: {
    title: 'XSS Payload Transformer for WAF Testing | WAF Bypass Toolkit',
    description: 'Generate context-aware XSS variants for HTML, JavaScript and attribute contexts with explicit parsing and decoding requirements.',
    keywords: 'XSS bypass, XSS WAF evasion, cross-site scripting bypass, XSS filter bypass, HTML entity encoding, JS obfuscation, svg onload bypass, WAF XSS bypass',
  },
  cmdi: {
    title: 'Command Injection Payload Transformer | WAF Bypass Toolkit',
    description: 'Generate shell-aware command injection variants for Linux, Windows cmd.exe and PowerShell, including transport and runtime prerequisites.',
    keywords: 'command injection bypass, OS command injection WAF, CMDi bypass, space bypass IFS, keyword bypass, Linux command injection, cmd.exe, PowerShell',
  },
  lfi: {
    title: 'LFI & Path Traversal Payload Transformer | WAF Bypass Toolkit',
    description: 'Generate target-aware LFI and path traversal variants with encoding depth, normalization, legacy and PHP-wrapper requirements clearly labeled.',
    keywords: 'LFI bypass, path traversal bypass, local file inclusion WAF, double URL encoding, null byte injection, PHP wrapper bypass, directory traversal evasion',
  },
  ssrf: {
    title: 'SSRF URL & IP Payload Transformer | WAF Bypass Toolkit',
    description: 'Generate parser-aware SSRF variants using alternate IP notation, raw URL preservation and provider-specific metadata endpoints.',
    keywords: 'SSRF bypass, SSRF WAF evasion, IP obfuscation, decimal IP, hex IP, localhost bypass, cloud metadata SSRF, DNS aliases, URL obfuscation',
  },
  ssti: {
    title: 'SSTI Payload Transformer for Template Engines | WAF Bypass Toolkit',
    description: 'Generate target-aware SSTI variants for Jinja2, Twig and Freemarker while preserving template syntax and documenting prerequisites.',
    keywords: 'SSTI bypass, template injection bypass, Jinja2 bypass, Twig bypass, Freemarker bypass, SSTI WAF evasion, template injection obfuscation',
  },
  xxe: {
    title: 'XXE Payload & XML Encoding Transformer | WAF Bypass Toolkit',
    description: 'Generate byte-correct UTF-16 XML downloads and parser-dependent UTF-7, entity, XInclude and SVG variants for authorized testing.',
    keywords: 'XXE bypass, XML external entity testing, XXE WAF evasion, UTF-16 XXE, UTF-7 XXE, entity indirection, XInclude testing',
  },
}

const FAQ_SCHEMA = {
  '@context': 'https://schema.org',
  '@type': 'FAQPage',
  mainEntity: [
    {
      '@type': 'Question',
      name: 'What is a Web Application Firewall (WAF)?',
      acceptedAnswer: {
        '@type': 'Answer',
        text: 'A Web Application Firewall (WAF) is a security solution that monitors, filters, and blocks HTTP traffic to and from a web application. WAFs protect against common web attacks like SQL injection, XSS, command injection, and more by analyzing request patterns against a set of rules. Popular WAFs include Cloudflare WAF, AWS WAF, ModSecurity, Akamai Kona, and Imperva.',
      },
    },
    {
      '@type': 'Question',
      name: 'How do WAF bypass tests work?',
      acceptedAnswer: {
        '@type': 'Answer',
        text: 'Authorized tests compare how the WAF, transport decoder, framework, and backend parser interpret alternate representations of the same input.',
      },
    },
    {
      '@type': 'Question',
      name: 'What is SQL injection WAF bypass?',
      acceptedAnswer: {
        '@type': 'Answer',
        text: 'SQL injection WAF testing compares how a filtering layer and the selected database or request decoder interpret equivalent input. This toolkit creates dialect-aware variants and labels outputs that depend on an additional decoding or parser step.',
      },
    },
    {
      '@type': 'Question',
      name: 'Is using WAF bypass tools legal?',
      acceptedAnswer: {
        '@type': 'Answer',
        text: 'WAF bypass tools are legal when used for authorized penetration testing, bug bounty programs with explicit scope authorization, and security research on systems you own. Unauthorized testing against systems without permission is illegal under computer fraud laws in most jurisdictions. Always ensure you have written authorization before testing.',
      },
    },
    {
      '@type': 'Question',
      name: 'Does this tool guarantee a WAF bypass?',
      acceptedAnswer: {
        '@type': 'Answer',
        text: 'No. It generates deterministic candidate variants for authorized testing. Results depend on the target grammar, decoding chain, application context, WAF rules and backend behavior. Conditional and legacy labels identify important prerequisites.',
      },
    },
  ],
}

const WEBSITE_SCHEMA = {
  '@context': 'https://schema.org',
  '@type': 'WebSite',
  name: 'WAF Bypass Toolkit',
  alternateName: 'WAF Payload Transformer',
  url: `${BASE_URL}/`,
}

export default function SEOHead({ category = 'sqli' }) {
  const seo = SEO_DATA[category] || SEO_DATA.sqli

  const webAppSchema = {
    '@context': 'https://schema.org',
    '@type': 'WebApplication',
    name: 'WAF Bypass Toolkit',
    url: `${BASE_URL}/`,
    description: 'Target-aware payload transformation toolkit for authorized web security testing.',
    applicationCategory: 'SecurityApplication',
    operatingSystem: 'Web Browser',
    inLanguage: 'en',
    browserRequirements: 'Requires JavaScript',
    datePublished: '2026-04-03',
    dateModified: '2026-09-14',
    softwareVersion: '1.1.0',
    isAccessibleForFree: true,
    featureList: [
      'SQLi, XSS, CMDi, LFI, SSRF, SSTI and XXE transformation engines',
      'Target-aware and context-aware output',
      'Validated, conditional and legacy output labels',
      'Exact UTF-16 XML byte downloads',
    ],
    author: {
      '@type': 'Person',
      name: 'Ilias Georgopoulos',
      url: 'https://ilias1988.me/',
      sameAs: [
        'https://github.com/Ilias1988',
        'https://www.linkedin.com/in/ilias-georgopoulos-b491a3371/',
        'https://x.com/EliotGeo',
      ],
    },
    offers: { '@type': 'Offer', price: '0', priceCurrency: 'USD' },
    keywords: seo.keywords,
  }

  return (
    <Helmet>
      <title>{seo.title}</title>
      <meta name="description" content={seo.description} />
      <meta name="keywords" content={seo.keywords} />
      <link rel="canonical" href={`${BASE_URL}/`} />

      {/* Open Graph */}
      <meta property="og:type" content="website" />
      <meta property="og:url" content={`${BASE_URL}/`} />
      <meta property="og:title" content={seo.title} />
      <meta property="og:description" content={seo.description} />
      <meta property="og:site_name" content="WAF Bypass Toolkit" />

      {/* Twitter Card */}
      <meta name="twitter:card" content="summary_large_image" />
      <meta name="twitter:creator" content="@EliotGeo" />
      <meta name="twitter:title" content={seo.title} />
      <meta name="twitter:description" content={seo.description} />

      <script type="application/ld+json">{JSON.stringify(webAppSchema)}</script>
      <script type="application/ld+json">{JSON.stringify(FAQ_SCHEMA)}</script>
      <script type="application/ld+json">{JSON.stringify(WEBSITE_SCHEMA)}</script>
    </Helmet>
  )
}
