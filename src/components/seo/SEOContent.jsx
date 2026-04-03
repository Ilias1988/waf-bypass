import { BookOpen, Shield, Zap, Eye, Globe, Scale, ChevronRight } from 'lucide-react'

export default function SEOContent() {
  return (
    <section
      id="education"
      className="relative px-5 py-16 bg-dark-900/50 border-t border-dark-700/30"
      aria-label="Educational content about WAF bypass and evasion techniques"
    >
      <div className="max-w-4xl mx-auto space-y-10">

        {/* Section Title */}
        <div className="text-center space-y-3">
          <div className="inline-flex items-center gap-2 px-3 py-1.5 bg-waf-red/10 border border-waf-red/20 rounded-full text-waf-red text-xs font-medium tracking-wide uppercase">
            <BookOpen size={14} />
            Educational Resource
          </div>
          <h2 className="text-3xl sm:text-4xl font-bold text-gray-100 tracking-tight">
            WAF Bypass Techniques &amp; Evasion Theory
          </h2>
          <p className="text-dark-400 text-base max-w-2xl mx-auto">
            A comprehensive guide to understanding Web Application Firewall evasion, payload obfuscation,
            and the role of these techniques in modern penetration testing.
          </p>
        </div>

        {/* What is a WAF */}
        <article className="space-y-3">
          <div className="flex items-center gap-2">
            <Shield size={20} className="text-waf-red shrink-0" />
            <h3 className="text-xl font-semibold text-gray-200">
              What is a Web Application Firewall (WAF)?
            </h3>
          </div>
          <p className="text-dark-300 leading-relaxed pl-7">
            A <strong className="text-gray-200">Web Application Firewall (WAF)</strong> is a security layer that sits
            between users and web applications, inspecting HTTP/HTTPS traffic in real-time. WAFs like{' '}
            <strong className="text-gray-200">Cloudflare</strong>, <strong className="text-gray-200">AWS WAF</strong>,{' '}
            <strong className="text-gray-200">ModSecurity</strong>, <strong className="text-gray-200">Akamai Kona</strong>,
            and <strong className="text-gray-200">Imperva</strong> analyze incoming requests against a set of rules
            designed to detect common web attacks such as <strong className="text-gray-200">SQL injection</strong>,{' '}
            <strong className="text-gray-200">Cross-Site Scripting (XSS)</strong>,{' '}
            <strong className="text-gray-200">command injection</strong>, and{' '}
            <strong className="text-gray-200">path traversal</strong>. When a request matches a malicious pattern,
            the WAF blocks it — returning a 403 Forbidden response or a challenge page.
          </p>
          <p className="text-dark-300 leading-relaxed pl-7">
            While WAFs provide a critical layer of defense, they are not infallible. WAF rules rely on
            <strong className="text-gray-200"> pattern matching</strong> and <strong className="text-gray-200">regular expressions</strong>,
            which means they can be bypassed when payloads are obfuscated in ways the rules don't anticipate.
            This is why <strong className="text-gray-200">penetration testers</strong> and <strong className="text-gray-200">bug bounty hunters</strong> need
            to understand WAF evasion techniques — not to exploit applications maliciously, but to test
            whether WAF configurations are robust enough to withstand sophisticated attacks.
          </p>
        </article>

        {/* SQL Injection Bypass Theory */}
        <article className="space-y-3">
          <div className="flex items-center gap-2">
            <Zap size={20} className="text-waf-amber shrink-0" />
            <h3 className="text-xl font-semibold text-gray-200">
              SQL Injection WAF Bypass Techniques
            </h3>
          </div>
          <p className="text-dark-300 leading-relaxed pl-7">
            <strong className="text-gray-200">SQL injection (SQLi)</strong> remains one of the most critical web vulnerabilities.
            WAFs typically detect SQLi by looking for SQL keywords like{' '}
            <code className="text-waf-green font-mono text-sm bg-dark-800/80 px-1.5 py-0.5 rounded">UNION SELECT</code>,{' '}
            <code className="text-waf-green font-mono text-sm bg-dark-800/80 px-1.5 py-0.5 rounded">OR 1=1</code>, and{' '}
            <code className="text-waf-green font-mono text-sm bg-dark-800/80 px-1.5 py-0.5 rounded">DROP TABLE</code>.
            Bypass techniques exploit the gap between how the WAF parses SQL and how the database engine interprets it.
            <strong className="text-gray-200"> Whitespace substitution</strong> replaces spaces with{' '}
            <code className="text-waf-green font-mono text-sm bg-dark-800/80 px-1.5 py-0.5 rounded">/**/</code> comments
            or URL-encoded characters. <strong className="text-gray-200">Case toggling</strong> like{' '}
            <code className="text-waf-green font-mono text-sm bg-dark-800/80 px-1.5 py-0.5 rounded">uNiOn SeLeCt</code>{' '}
            defeats case-sensitive regex rules. <strong className="text-gray-200">MySQL versioned comments</strong> such as{' '}
            <code className="text-waf-green font-mono text-sm bg-dark-800/80 px-1.5 py-0.5 rounded">/*!50000SELECT*/</code>{' '}
            are ignored by WAFs but executed by MySQL. These techniques, combined with{' '}
            <strong className="text-gray-200">hex encoding</strong> and{' '}
            <strong className="text-gray-200">double URL encoding</strong>, make SQL payloads nearly invisible to pattern matching.
          </p>
        </article>

        {/* XSS & Command Injection */}
        <article className="space-y-3">
          <div className="flex items-center gap-2">
            <Eye size={20} className="text-waf-orange shrink-0" />
            <h3 className="text-xl font-semibold text-gray-200">
              XSS Filter Evasion &amp; Command Injection Bypasses
            </h3>
          </div>
          <p className="text-dark-300 leading-relaxed pl-7">
            <strong className="text-gray-200">Cross-Site Scripting (XSS)</strong> WAF rules typically block{' '}
            <code className="text-waf-green font-mono text-sm bg-dark-800/80 px-1.5 py-0.5 rounded">&lt;script&gt;</code>{' '}
            tags and <code className="text-waf-green font-mono text-sm bg-dark-800/80 px-1.5 py-0.5 rounded">alert()</code>{' '}
            calls. Evasion relies on <strong className="text-gray-200">alternative HTML tags</strong> ({' '}
            <code className="text-waf-green font-mono text-sm bg-dark-800/80 px-1.5 py-0.5 rounded">&lt;svg/onload=...&gt;</code>,{' '}
            <code className="text-waf-green font-mono text-sm bg-dark-800/80 px-1.5 py-0.5 rounded">&lt;img onerror=...&gt;</code>),{' '}
            <strong className="text-gray-200">JavaScript function splitting</strong> ({' '}
            <code className="text-waf-green font-mono text-sm bg-dark-800/80 px-1.5 py-0.5 rounded">window['al'+'ert'](1)</code>),
            and <strong className="text-gray-200">encoding mixing</strong> that combines HTML entities with JS Unicode escapes.
          </p>
          <p className="text-dark-300 leading-relaxed pl-7">
            <strong className="text-gray-200">OS Command Injection</strong> bypasses target filters that block common commands.
            On Linux, replacing spaces with{' '}
            <code className="text-waf-green font-mono text-sm bg-dark-800/80 px-1.5 py-0.5 rounded">$&#123;IFS&#125;</code>{' '}
            or using brace expansion{' '}
            <code className="text-waf-green font-mono text-sm bg-dark-800/80 px-1.5 py-0.5 rounded">&#123;cat,/etc/passwd&#125;</code>{' '}
            avoids space-based detection. Keyword bypass techniques like{' '}
            <code className="text-waf-green font-mono text-sm bg-dark-800/80 px-1.5 py-0.5 rounded">c''a''t</code> or{' '}
            <code className="text-waf-green font-mono text-sm bg-dark-800/80 px-1.5 py-0.5 rounded">c$@at</code>{' '}
            break the string signature while remaining valid shell syntax.
          </p>
        </article>

        {/* Advanced: SSRF, SSTI, XXE */}
        <article className="space-y-3">
          <div className="flex items-center gap-2">
            <Globe size={20} className="text-waf-cyan shrink-0" />
            <h3 className="text-xl font-semibold text-gray-200">
              SSRF, SSTI &amp; XXE: Advanced WAF Evasion
            </h3>
          </div>
          <p className="text-dark-300 leading-relaxed pl-7">
            <strong className="text-gray-200">Server-Side Request Forgery (SSRF)</strong> bypasses focus on IP address
            obfuscation — converting <code className="text-waf-green font-mono text-sm bg-dark-800/80 px-1.5 py-0.5 rounded">127.0.0.1</code> to
            decimal (<code className="text-waf-green font-mono text-sm bg-dark-800/80 px-1.5 py-0.5 rounded">2130706433</code>),
            hexadecimal, octal, or IPv6-mapped formats.{' '}
            <strong className="text-gray-200">Server-Side Template Injection (SSTI)</strong> evades
            keyword-based WAF rules by splitting Python dunder attributes with string concatenation or hex escapes.{' '}
            <strong className="text-gray-200">XML External Entity (XXE)</strong> bypass techniques re-encode entire XML
            payloads from UTF-8 to UTF-16 or UTF-7, preventing the WAF from reading keywords like{' '}
            <code className="text-waf-green font-mono text-sm bg-dark-800/80 px-1.5 py-0.5 rounded">ENTITY</code> and{' '}
            <code className="text-waf-green font-mono text-sm bg-dark-800/80 px-1.5 py-0.5 rounded">SYSTEM</code>{' '}
            while the XML parser on the server processes them normally.
          </p>
        </article>

        {/* Multi-Layer Strategy */}
        <article className="space-y-3">
          <div className="flex items-center gap-2">
            <ChevronRight size={20} className="text-waf-purple shrink-0" />
            <h3 className="text-xl font-semibold text-gray-200">
              Multi-Layer Bypass Strategy for Modern WAFs
            </h3>
          </div>
          <p className="text-dark-300 leading-relaxed pl-7">
            Modern WAFs employ multiple detection engines simultaneously — regex matching, machine learning classifiers,
            behavioral analysis, and reputation scoring. A single evasion technique is rarely sufficient.
            The most effective approach is <strong className="text-gray-200">combining multiple layers</strong>: for example,
            applying whitespace bypass + case toggling + hex encoding to a SQLi payload generates variants that
            look fundamentally different from the original while maintaining the same exploit logic. This
            WAF Bypass Toolkit generates <strong className="text-gray-200">5-12 unique variants</strong> per payload,
            each using different layer combinations, giving penetration testers a diverse set of payloads
            to test against specific WAF configurations during <strong className="text-gray-200">authorized security assessments</strong>.
          </p>
        </article>

        {/* Ethics Box */}
        <div className="ml-7 p-5 bg-dark-800/60 border border-dark-700/40 border-l-4 border-l-waf-green rounded-lg space-y-2">
          <div className="flex items-center gap-2 text-waf-green font-semibold text-sm uppercase tracking-wide">
            <Scale size={16} />
            Ethics &amp; Responsible Use
          </div>
          <p className="text-dark-300 text-sm leading-relaxed">
            WAF bypass tools exist exclusively for <strong className="text-gray-200">authorized penetration testing</strong>,{' '}
            <strong className="text-gray-200">bug bounty programs</strong>, and{' '}
            <strong className="text-gray-200">security research</strong>. Always ensure you have explicit written
            permission before testing any system. Responsible disclosure through platforms like{' '}
            <strong className="text-gray-200">HackerOne</strong>, <strong className="text-gray-200">Bugcrowd</strong>,
            or <strong className="text-gray-200">Intigriti</strong> ensures vulnerabilities are fixed before they can be
            exploited maliciously. The goal of security testing is to make the internet safer —
            never to cause harm.
          </p>
        </div>

      </div>
    </section>
  )
}
