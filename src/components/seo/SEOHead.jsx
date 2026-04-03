import { Helmet } from 'react-helmet-async'

const BASE_URL = 'https://waf-bypass.dev'

const SEO_DATA = {
  sqli: {
    title: 'SQL Injection WAF Bypass Tool — SQLi Payload Obfuscator | WAF Bypass Toolkit',
    description: 'Generate obfuscated SQL injection payloads to bypass WAFs like Cloudflare, AWS WAF & ModSecurity. Whitespace bypass, case toggling, inline comments, hex encoding & more.',
    keywords: 'SQL injection bypass, SQLi WAF bypass, SQL injection obfuscator, WAF evasion SQLi, Cloudflare SQL bypass, ModSecurity bypass, union select bypass, hex encoding SQL',
  },
  xss: {
    title: 'XSS WAF Bypass Tool — Cross-Site Scripting Payload Obfuscator | WAF Bypass Toolkit',
    description: 'Evade XSS WAF filters with HTML entity encoding, JS obfuscation, tag variation, case toggling and mixed encoding techniques. Generate bypass payloads for Burp Suite.',
    keywords: 'XSS bypass, XSS WAF evasion, cross-site scripting bypass, XSS filter bypass, HTML entity encoding, JS obfuscation, svg onload bypass, WAF XSS bypass',
  },
  cmdi: {
    title: 'Command Injection WAF Bypass — OS CMDi Payload Obfuscator | WAF Bypass Toolkit',
    description: 'Bypass command injection WAF rules with space bypass, keyword obfuscation, newline injection, variable expansion and hex-encoded commands for Linux & Windows.',
    keywords: 'command injection bypass, OS command injection WAF, CMDi bypass, space bypass IFS, keyword bypass, command obfuscation, Linux command injection, Windows CMDi',
  },
  lfi: {
    title: 'LFI & Path Traversal WAF Bypass — File Inclusion Obfuscator | WAF Bypass Toolkit',
    description: 'Evade LFI and path traversal WAF detection with double URL encoding, Unicode overlong bytes, null byte injection, path normalization tricks and PHP wrappers.',
    keywords: 'LFI bypass, path traversal bypass, local file inclusion WAF, double URL encoding, null byte injection, PHP wrapper bypass, directory traversal evasion',
  },
  ssrf: {
    title: 'SSRF WAF Bypass Tool — IP Obfuscation & URL Tricks | WAF Bypass Toolkit',
    description: 'Obfuscate SSRF payloads with IP decimal/hex/octal notation, short forms, URL tricks, DNS rebinding and cloud metadata endpoint variations.',
    keywords: 'SSRF bypass, SSRF WAF evasion, IP obfuscation, decimal IP, hex IP, localhost bypass, cloud metadata SSRF, DNS rebinding, URL obfuscation',
  },
  ssti: {
    title: 'SSTI WAF Bypass — Server-Side Template Injection Obfuscator | WAF Bypass Toolkit',
    description: 'Bypass SSTI WAF rules for Jinja2, Twig & Freemarker with string concatenation, hex encoding, attr() filter bypass and indirect template access techniques.',
    keywords: 'SSTI bypass, template injection bypass, Jinja2 bypass, Twig bypass, Freemarker bypass, SSTI WAF evasion, template injection obfuscation',
  },
  xxe: {
    title: 'XXE WAF Bypass — XML External Entity Encoding Evasion | WAF Bypass Toolkit',
    description: 'Evade XXE WAF detection by re-encoding XML payloads to UTF-16/UTF-7, using parameter entity nesting, CDATA wrapping, XInclude and SVG-based XXE techniques.',
    keywords: 'XXE bypass, XML external entity bypass, XXE WAF evasion, UTF-16 XXE, UTF-7 XXE, parameter entity, CDATA XXE, XInclude attack',
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
      name: 'How do WAF bypass techniques work?',
      acceptedAnswer: {
        '@type': 'Answer',
        text: 'WAF bypass techniques exploit gaps in how WAFs parse and analyze HTTP requests compared to how the backend application processes them. Common approaches include encoding payloads (URL encoding, hex, Unicode), altering whitespace and case, using alternative syntax (different HTML tags, SQL comment styles), and leveraging parser differentials between the WAF and the target application.',
      },
    },
    {
      '@type': 'Question',
      name: 'What is SQL injection WAF bypass?',
      acceptedAnswer: {
        '@type': 'Answer',
        text: 'SQL injection WAF bypass involves modifying SQLi payloads so they are not detected by WAF rules but are still executed by the database. Techniques include replacing spaces with comments (/**/), using alternative whitespace characters (%09, %0a), toggling case (uNiOn SeLeCt), MySQL versioned comments (/*!50000SELECT*/), hex-encoding strings (0x61646d696e), and double URL encoding.',
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
      name: 'Can this tool bypass Cloudflare WAF?',
      acceptedAnswer: {
        '@type': 'Answer',
        text: 'This tool generates multiple payload variants using real-world WAF evasion techniques that are commonly effective against various WAFs including Cloudflare. However, WAF bypass success depends on the specific ruleset configuration, and Cloudflare continuously updates its rules. The tool is designed to help security professionals test WAF configurations during authorized assessments.',
      },
    },
  ],
}

const BREADCRUMB_SCHEMA = {
  '@context': 'https://schema.org',
  '@type': 'BreadcrumbList',
  itemListElement: [
    { '@type': 'ListItem', position: 1, name: 'Home', item: `${BASE_URL}/` },
    { '@type': 'ListItem', position: 2, name: 'WAF Bypass Toolkit', item: `${BASE_URL}/` },
  ],
}

export default function SEOHead({ category = 'sqli' }) {
  const seo = SEO_DATA[category] || SEO_DATA.sqli

  const webAppSchema = {
    '@context': 'https://schema.org',
    '@type': 'WebApplication',
    name: 'WAF Bypass Toolkit',
    url: `${BASE_URL}/`,
    description: 'Swiss Army Knife for WAF bypass — generate obfuscated web payloads for pentesting and bug bounty hunting.',
    applicationCategory: 'SecurityApplication',
    operatingSystem: 'Web Browser',
    inLanguage: 'en',
    browserRequirements: 'Requires JavaScript',
    datePublished: '2026-04-03',
    dateModified: '2026-04-03',
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
      <script type="application/ld+json">{JSON.stringify(BREADCRUMB_SCHEMA)}</script>
    </Helmet>
  )
}
