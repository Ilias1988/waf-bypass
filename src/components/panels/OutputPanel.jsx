import { Code, Shield, AlertTriangle, Hash } from 'lucide-react'
import CopyButton from '../ui/CopyButton'
import DownloadButton from '../ui/DownloadButton'

export default function OutputPanel({ variants, error }) {
  const hasVariants = variants.length > 1 // >1 because first is always "Original"
  const textVariants = variants.filter((variant) => variant.label !== 'Original' && !variant.bytesBase64)

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="terminal-header flex items-center justify-between px-3 py-2 border-b border-dark-700/50 rounded-t-lg">
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-1.5">
            <span className="terminal-dot bg-waf-red/80" />
            <span className="terminal-dot bg-waf-amber/80" />
            <span className="terminal-dot bg-waf-green/80" />
          </div>
          <div className="flex items-center gap-1.5 ml-2">
            <Shield size={13} className="text-waf-green" />
            <span className="text-xs text-dark-400 font-medium">
              WAF Bypass Variants
            </span>
          </div>
          {hasVariants && (
            <span className="text-[10px] px-1.5 py-0.5 bg-waf-green/10 border border-waf-green/30 text-waf-green rounded-full font-medium">
              {variants.length - 1} variants
            </span>
          )}
        </div>

        {/* Copy All Button */}
        {textVariants.length > 0 && (
          <CopyButton
            text={textVariants
              .map((v, i) => `# Variant ${i + 1} [${v.label}]\n${v.payload}`)
              .join('\n\n')}
            size="sm"
          />
        )}
      </div>

      {/* Output Content */}
      <div className="flex-1 overflow-y-auto bg-dark-900 rounded-b-lg">
        {error ? (
          <div className="flex items-center gap-2 p-4 text-waf-amber">
            <AlertTriangle size={16} />
            <span className="text-sm">{error}</span>
          </div>
        ) : hasVariants ? (
          <div className="p-3 space-y-3">
            {variants
              .filter((v) => v.label !== 'Original')
              .map((variant, index) => (
                <div key={index} className="variant-card animate-slide-up" style={{ animationDelay: `${index * 50}ms` }}>
                  {/* Variant Header */}
                  <div className="flex items-center justify-between px-3 py-2 bg-dark-850 border-b border-dark-700/30">
                    <div className="flex items-center gap-2">
                      <div className="flex items-center gap-1">
                        <Hash size={11} className="text-dark-500" />
                        <span className="text-[11px] font-semibold text-dark-300">
                          {index + 1}
                        </span>
                      </div>
                      <span className="text-[10px] font-medium text-waf-amber">
                        {variant.label}
                      </span>
                      {variant.validity && (
                        <span className={`text-[9px] px-1.5 py-0.5 rounded uppercase tracking-wide ${
                          variant.validity === 'validated'
                            ? 'bg-waf-green/10 text-waf-green'
                            : variant.validity === 'legacy'
                              ? 'bg-waf-orange/10 text-waf-orange'
                              : 'bg-waf-cyan/10 text-waf-cyan'
                        }`}>
                          {variant.validity}
                        </span>
                      )}
                      {/* Layer badges */}
                      <div className="flex gap-1">
                        {variant.layers.map((layer) => (
                          <span
                            key={layer}
                            className="text-[9px] px-1.5 py-0.5 bg-dark-700/50 text-dark-400 rounded"
                          >
                            {layer}
                          </span>
                        ))}
                      </div>
                    </div>
                    {variant.bytesBase64 ? (
                      <DownloadButton
                        bytesBase64={variant.bytesBase64}
                        filename={variant.filename}
                        mimeType="application/xml"
                      />
                    ) : (
                      <CopyButton text={variant.payload} size="sm" />
                    )}
                  </div>

                  {/* Variant Code */}
                  <pre className="code-block max-h-[200px]">
                    {variant.payload}
                  </pre>
                  {variant.note && (
                    <p className="px-3 py-2 text-[10px] leading-relaxed text-dark-400 border-t border-dark-700/30">
                      {variant.note}
                    </p>
                  )}
                </div>
              ))}
          </div>
        ) : (
          <div className="flex items-center justify-center h-full min-h-[200px] lg:min-h-[400px]">
            <div className="text-center space-y-2">
              <Code size={32} className="mx-auto text-dark-700" />
              <p className="text-dark-600 text-sm">WAF bypass variants will appear here</p>
              <p className="text-dark-700 text-xs">Select evasion layers and click Generate</p>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
