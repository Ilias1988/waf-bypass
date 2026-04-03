import { Shield, Github, Bug } from 'lucide-react'

export default function Header() {
  return (
    <header className="border-b border-dark-700/50 bg-dark-900/80 backdrop-blur-sm sticky top-0 z-40">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 py-3 flex items-center justify-between">
        {/* Logo & Title */}
        <div className="flex items-center gap-3">
          <div className="relative">
            <Shield size={28} className="text-waf-red" />
            <div className="absolute -top-0.5 -right-0.5 w-2.5 h-2.5 bg-waf-red rounded-full animate-pulse" />
          </div>
          <div>
            <h1 className="text-base sm:text-lg font-bold text-gray-100 tracking-tight">
              WAF Bypass Toolkit
            </h1>
            <p className="text-[10px] text-dark-400 font-medium tracking-wider uppercase hidden sm:block">
              Web Payload Obfuscator — Pentesting & Bug Bounty
            </p>
          </div>
        </div>

        {/* Right side */}
        <div className="flex items-center gap-2">
          <span className="hidden sm:inline-flex items-center gap-1 px-2 py-1 bg-waf-red/10 border border-waf-red/20 rounded text-[10px] text-waf-red font-semibold uppercase tracking-wider badge-pulse">
            <Bug size={10} />
            v1.0
          </span>
          <a
            href="https://github.com/Ilias1988/waf-bypass"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-dark-300 hover:text-gray-100 bg-dark-800 hover:bg-dark-700 border border-dark-600/30 rounded-lg transition-all"
          >
            <Github size={14} />
            <span className="hidden sm:inline">GitHub</span>
          </a>
        </div>
      </div>
    </header>
  )
}
