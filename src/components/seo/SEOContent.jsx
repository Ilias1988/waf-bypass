import { BookOpen, Shield, Zap, Eye, Globe, Scale, ChevronRight, HelpCircle } from 'lucide-react'

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
            While WAFs provide a critical layer of defense, their decisions depend on rules, normalization,
            signatures, and—depending on the product—behavioral or machine-learning signals. Differences between
            how a WAF, web framework, and backend parser decode the same request are important test cases.
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
            <strong className="text-gray-200"> Whitespace substitution</strong> can replace spaces with{' '}
            <code className="text-waf-green font-mono text-sm bg-dark-800/80 px-1.5 py-0.5 rounded">/**/</code> comments
            or URL-encoded characters. <strong className="text-gray-200">Case toggling</strong> like{' '}
            <code className="text-waf-green font-mono text-sm bg-dark-800/80 px-1.5 py-0.5 rounded">uNiOn SeLeCt</code>{' '}
            probes case-sensitive rules. <strong className="text-gray-200">MySQL versioned comments</strong> such as{' '}
            <code className="text-waf-green font-mono text-sm bg-dark-800/80 px-1.5 py-0.5 rounded">/*!50000SELECT*/</code>{' '}
            have MySQL-specific behavior. Techniques such as{' '}
            <strong className="text-gray-200">hex encoding</strong> and{' '}
            <strong className="text-gray-200">double URL encoding</strong> are useful only when the selected database and
            request decoding chain interpret them as expected. The toolkit preserves quoted literals and applies SQL
            transformations outside protected strings, identifiers, and comments whenever the technique requires it.
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
            creates an alternate separator for compatible shells. Keyword variants use syntax appropriate to the
            selected runtime: quotes or backslashes for compatible POSIX shells, carets for{' '}
            <code className="text-waf-green font-mono text-sm bg-dark-800/80 px-1.5 py-0.5 rounded">cmd.exe</code>,
            and command reconstruction for PowerShell. Transport-encoded spaces and newlines are marked conditional
            because they require a decoding pass before the shell sees them.
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
            <strong className="text-gray-200">Server-Side Request Forgery (SSRF)</strong> testing often includes IP address
            obfuscation — converting <code className="text-waf-green font-mono text-sm bg-dark-800/80 px-1.5 py-0.5 rounded">127.0.0.1</code> to
            decimal (<code className="text-waf-green font-mono text-sm bg-dark-800/80 px-1.5 py-0.5 rounded">2130706433</code>),
            hexadecimal, octal, or IPv6-mapped formats.{' '}
            <strong className="text-gray-200">Server-Side Template Injection (SSTI)</strong> evades
            keyword-based WAF rules by splitting Python dunder attributes with string concatenation or hex escapes.{' '}
            <strong className="text-gray-200"> XML External Entity (XXE)</strong> testing may require exact byte-level
            encodings such as UTF-16 or legacy UTF-7, plus parser-specific alternatives such as XInclude. Encoding
            declarations alone are insufficient, so UTF-16 variants are downloaded as their real bytes. Entity,
            XInclude, SVG, and UTF-7 variants remain parser-dependent and are labeled with their prerequisites.
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
            Modern WAFs can combine normalization, signatures, anomaly scores, behavioral signals, and reputation data.
            Combining compatible layers helps test different decoding and parsing paths, but an arbitrary combination
            can also change meaning or break syntax. This
            WAF Bypass Toolkit generates <strong className="text-gray-200">up to 12 unique variants</strong> per payload,
            reserves coverage for selected layers, removes duplicates, and labels environment-dependent outputs.
            Test each result only against an explicitly authorized target and verify it in the exact database, shell,
            template, URL, HTML, or XML context for which it was generated.
          </p>
        </article>

        {/* Visible FAQ mirrors the structured data in SEOHead. */}
        <article className="space-y-4" aria-labelledby="faq-title">
          <div className="flex items-center gap-2">
            <HelpCircle size={20} className="text-waf-green shrink-0" />
            <h3 id="faq-title" className="text-xl font-semibold text-gray-200">Frequently Asked Questions</h3>
          </div>
          <div className="grid gap-3 pl-0 sm:pl-7">
            {[
              ['What is a Web Application Firewall (WAF)?', 'A WAF inspects HTTP traffic and applies rules or scoring to block suspicious requests before they reach an application.'],
              ['How do WAF bypass tests work?', 'Authorized tests compare how the WAF, transport decoder, framework, and backend parser interpret alternate representations of the same input.'],
              ['What is SQL injection WAF testing?', 'It creates database-dialect-aware SQLi variants and verifies which normalization, quoting, comment, or encoding rules apply to the selected stack.'],
              ['Is using this toolkit legal?', 'Use it only on systems you own or where you have explicit written permission and a clearly defined testing scope.'],
              ['Does this tool guarantee a WAF bypass?', 'No. Success depends on the WAF policy, decoding chain, application context, backend grammar, and runtime. Conditional and legacy labels identify prerequisites.'],
            ].map(([question, answer]) => (
              <div key={question} className="rounded-lg border border-dark-700/40 bg-dark-850/50 p-4">
                <h4 className="font-semibold text-gray-200">{question}</h4>
                <p className="mt-1 text-sm leading-relaxed text-dark-300">{answer}</p>
              </div>
            ))}
          </div>
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
