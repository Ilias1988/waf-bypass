import { Shield, Heart, Github, Linkedin, Globe } from 'lucide-react'

export default function Footer() {
  return (
    <footer className="border-t border-dark-700/30 bg-dark-900/50 mt-auto">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 py-6">
        <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
          {/* Left */}
          <div className="flex items-center gap-2 text-xs text-dark-500">
            <Shield size={14} className="text-waf-red/50" />
            <span>WAF Bypass Toolkit — For authorized security testing only</span>
          </div>

          {/* Social Links */}
          <div className="flex items-center gap-3">
            <a href="https://github.com/Ilias1988" target="_blank" rel="noopener noreferrer"
              className="flex items-center gap-1.5 px-2.5 py-1.5 text-dark-400 hover:text-gray-100 bg-dark-800/50 hover:bg-dark-800 border border-dark-700/30 rounded-lg transition-all text-xs"
              aria-label="GitHub Profile">
              <Github size={13} />
              <span className="hidden sm:inline">GitHub</span>
            </a>
            <a href="https://www.linkedin.com/in/ilias-georgopoulos-b491a3371/" target="_blank" rel="noopener noreferrer"
              className="flex items-center gap-1.5 px-2.5 py-1.5 text-dark-400 hover:text-[#0A66C2] bg-dark-800/50 hover:bg-dark-800 border border-dark-700/30 rounded-lg transition-all text-xs"
              aria-label="LinkedIn Profile">
              <Linkedin size={13} />
              <span className="hidden sm:inline">LinkedIn</span>
            </a>
            <a href="https://x.com/EliotGeo" target="_blank" rel="noopener noreferrer"
              className="flex items-center gap-1.5 px-2.5 py-1.5 text-dark-400 hover:text-gray-100 bg-dark-800/50 hover:bg-dark-800 border border-dark-700/30 rounded-lg transition-all text-xs"
              aria-label="X (Twitter) Profile">
              <svg viewBox="0 0 24 24" width="13" height="13" fill="currentColor"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>
              <span className="hidden sm:inline">X</span>
            </a>
            <a href="https://ilias1988.me/" target="_blank" rel="noopener noreferrer"
              className="flex items-center gap-1.5 px-2.5 py-1.5 text-dark-400 hover:text-waf-amber bg-dark-800/50 hover:bg-dark-800 border border-dark-700/30 rounded-lg transition-all text-xs"
              aria-label="Portfolio">
              <Globe size={13} />
              <span className="hidden sm:inline">Portfolio</span>
            </a>
          </div>

          {/* Right */}
          <div className="flex items-center gap-4 text-xs text-dark-500">
            <span className="flex items-center gap-1">
              Made with <Heart size={11} className="text-waf-red" /> for the InfoSec community
            </span>
          </div>
        </div>

        {/* Bottom info */}
        <div className="mt-4 pt-4 border-t border-dark-700/20 flex flex-col sm:flex-row items-center justify-between gap-2">
          <p className="text-[10px] text-dark-600">
            100% Client-Side — No data leaves your browser
          </p>
          <p className="text-[10px] text-dark-600 max-w-xl text-center sm:text-right leading-relaxed">
            ⚠️ Intended for authorized penetration testing, bug bounty programs, and security research only.
            Unauthorized use is illegal. The authors assume no liability for misuse.
          </p>
        </div>
      </div>
    </footer>
  )
}
