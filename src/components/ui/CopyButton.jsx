import { useState } from 'react'
import { Copy, Check } from 'lucide-react'

export default function CopyButton({ text, size = 'sm', className = '' }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = async () => {
    if (!text) return
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      // Fallback for older browsers
      const ta = document.createElement('textarea')
      ta.value = text
      document.body.appendChild(ta)
      ta.select()
      document.execCommand('copy')
      document.body.removeChild(ta)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }

  const sizeClasses = {
    sm: 'px-2 py-1 text-[11px]',
    md: 'px-3 py-1.5 text-xs',
  }

  return (
    <button
      onClick={handleCopy}
      className={`inline-flex items-center gap-1 ${sizeClasses[size]} rounded transition-all duration-200 ${
        copied
          ? 'bg-waf-green/20 text-waf-green border border-waf-green/30'
          : 'text-dark-400 hover:text-gray-200 bg-dark-700/30 hover:bg-dark-700/60 border border-dark-600/30'
      } ${className}`}
      title={copied ? 'Copied!' : 'Copy to clipboard'}
    >
      {copied ? <Check size={11} /> : <Copy size={11} />}
      <span>{copied ? 'Copied' : 'Copy'}</span>
    </button>
  )
}
