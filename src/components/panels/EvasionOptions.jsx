import { Layers, Zap } from 'lucide-react'
import { EVASION_LAYERS } from '../../data/techniques'

export default function EvasionOptions({ category, activeLayers, onToggleLayer, onGenerate, hasInput }) {
  const layers = EVASION_LAYERS[category] || []

  return (
    <div className="space-y-3">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Layers size={15} className="text-waf-amber" />
          <span className="text-xs font-semibold text-gray-200 uppercase tracking-wider">
            Evasion Layers
          </span>
          {activeLayers.length > 0 && (
            <span className="text-[10px] px-1.5 py-0.5 bg-waf-red/15 text-waf-red rounded-full font-medium">
              {activeLayers.length} active
            </span>
          )}
        </div>
      </div>

      {/* Layers */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-1 gap-1.5">
        {layers.map((layer) => {
          const isActive = activeLayers.includes(layer.id)

          return (
            <button
              key={layer.id}
              onClick={() => onToggleLayer(layer.id)}
              className={`group flex items-start gap-2.5 p-2.5 rounded-lg border text-left transition-all duration-200 ${
                isActive
                  ? 'border-waf-red/30 bg-waf-red/5 hover:bg-waf-red/10'
                  : 'border-dark-700/30 bg-dark-800/30 hover:border-dark-600/50 hover:bg-dark-800/50'
              }`}
            >
              {/* Toggle */}
              <div
                className={`mt-0.5 layer-switch shrink-0 ${
                  isActive ? 'bg-waf-red' : 'bg-dark-600'
                }`}
              >
                <span
                  className={`layer-switch-knob ${
                    isActive ? 'translate-x-4' : 'translate-x-0.5'
                  }`}
                />
              </div>

              {/* Info */}
              <div className="min-w-0">
                <div className="flex items-center gap-1.5">
                  <span className="text-sm">{layer.icon}</span>
                  <span className={`text-xs font-medium ${isActive ? 'text-gray-100' : 'text-dark-300'}`}>
                    {layer.name}
                  </span>
                </div>
                <p className="text-[10px] text-dark-500 leading-tight mt-0.5 line-clamp-2">
                  {layer.description}
                </p>
              </div>
            </button>
          )
        })}
      </div>

      {/* Generate Button */}
      <button
        onClick={onGenerate}
        disabled={!hasInput || activeLayers.length === 0}
        className={`w-full flex items-center justify-center gap-2 px-4 py-3 rounded-lg font-semibold text-sm transition-all duration-200 ${
          hasInput && activeLayers.length > 0
            ? 'bg-waf-red hover:bg-red-600 text-white shadow-lg shadow-waf-red/20 animate-pulse-glow'
            : 'bg-dark-700 text-dark-500 cursor-not-allowed'
        }`}
      >
        <Zap size={16} />
        Generate Bypasses
      </button>

      {!hasInput && (
        <p className="text-[10px] text-dark-600 text-center">
          Paste a payload and select at least one layer
        </p>
      )}
    </div>
  )
}
