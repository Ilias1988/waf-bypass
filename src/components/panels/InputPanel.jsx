import { Terminal, Trash2, Target } from 'lucide-react'
import { CATEGORIES, TARGETS } from '../../data/techniques'

export default function InputPanel({ category, target, onTargetChange, inputPayload, onPayloadChange, onClear }) {
  const catData = CATEGORIES.find((c) => c.id === category)
  const targets = TARGETS[category] || []

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
            <Terminal size={13} className="text-waf-amber" />
            <span className="text-xs text-dark-400 font-medium">
              Raw Payload
            </span>
            <span className="text-sm ml-1">{catData?.icon}</span>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {/* Target Selector */}
          {targets.length > 0 && (
            <div className="flex items-center gap-1.5">
              <Target size={11} className="text-dark-400" />
              <select
                value={target}
                onChange={(e) => onTargetChange(e.target.value)}
                className="bg-dark-800 border border-dark-600/40 text-xs text-dark-300 rounded px-2 py-1 focus:outline-none focus:border-waf-red/40 cursor-pointer"
              >
                {targets.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.name}
                  </option>
                ))}
              </select>
            </div>
          )}

          {/* Clear Button */}
          <button
            onClick={onClear}
            className="inline-flex items-center gap-1 px-2 py-1 text-[11px] text-dark-400 hover:text-waf-red bg-dark-700/30 hover:bg-dark-700/60 border border-dark-600/30 rounded transition-colors"
            title="Clear"
          >
            <Trash2 size={11} />
          </button>
        </div>
      </div>

      {/* Textarea */}
      <div className="flex-1 relative overflow-hidden rounded-b-lg">
        <textarea
          value={inputPayload}
          onChange={(e) => onPayloadChange(e.target.value)}
          placeholder={catData?.placeholder || 'Paste your payload here...'}
          className="w-full h-full min-h-[200px] lg:min-h-[400px] p-4 bg-dark-900 text-gray-200 font-mono text-sm leading-relaxed resize-none focus:outline-none placeholder:text-dark-600"
          spellCheck={false}
        />
        {/* Char count */}
        {inputPayload && (
          <div className="absolute bottom-2 right-3 text-[10px] text-dark-600 font-mono">
            {inputPayload.length} chars
          </div>
        )}
      </div>
    </div>
  )
}
