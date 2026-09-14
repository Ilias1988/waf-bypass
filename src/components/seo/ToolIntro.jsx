import { Binary, CheckCircle2, Laptop } from 'lucide-react'

const highlights = [
  {
    icon: Binary,
    title: 'Target-aware transformations',
    text: 'Choose the database, shell, parser, framework, or injection context before generating variants.',
  },
  {
    icon: CheckCircle2,
    title: 'Honest validity labels',
    text: 'Validated, conditional, and legacy labels show when decoding, parser behavior, or older runtimes are required.',
  },
  {
    icon: Laptop,
    title: 'Local payload processing',
    text: 'Payload generation runs in your browser. The toolkit does not send payloads to a target or execute them.',
  },
]

export default function ToolIntro() {
  return (
    <section className="mb-5 space-y-4" aria-labelledby="tool-intro-title">
      <div className="max-w-4xl">
        <p className="text-xs font-semibold uppercase tracking-[0.18em] text-waf-red">
          Authorized security testing
        </p>
        <h2 id="tool-intro-title" className="mt-1 text-2xl sm:text-3xl font-bold tracking-tight text-gray-100">
          Transform complex web payloads without losing their intended syntax
        </h2>
        <p className="mt-2 text-sm sm:text-base leading-relaxed text-dark-300">
          Generate deterministic candidate variants for SQLi, XSS, command injection, LFI, SSRF, SSTI, and XXE.
          Outputs are context-sensitive test material—not a guarantee that a particular WAF or backend will accept them.
        </p>
      </div>

      <div className="grid gap-3 md:grid-cols-3">
        {highlights.map(({ icon: Icon, title, text }) => (
          <article key={title} className="rounded-lg border border-dark-700/40 bg-dark-850/70 p-3">
            <div className="flex items-center gap-2 text-sm font-semibold text-gray-200">
              <Icon size={15} className="text-waf-green" />
              {title}
            </div>
            <p className="mt-1.5 text-xs leading-relaxed text-dark-400">{text}</p>
          </article>
        ))}
      </div>
    </section>
  )
}
