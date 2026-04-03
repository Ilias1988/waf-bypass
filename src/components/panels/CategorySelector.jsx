import { CATEGORIES } from '../../data/techniques'

export default function CategorySelector({ category, onSelect }) {
  return (
    <div className="space-y-1.5">
      <div className="px-2 mb-2">
        <span className="text-[10px] font-semibold text-dark-400 uppercase tracking-wider">
          Vulnerability Type
        </span>
      </div>

      {CATEGORIES.map((cat) => {
        const isActive = category === cat.id
        return (
          <button
            key={cat.id}
            onClick={() => onSelect(cat.id)}
            className={`w-full flex items-center gap-2.5 px-3 py-2.5 rounded-lg text-left transition-all duration-200 ${
              isActive
                ? 'sidebar-item-active bg-dark-800/60'
                : 'hover:bg-dark-800/40 border-l-2 border-transparent'
            }`}
          >
            <span className="text-lg flex-shrink-0">{cat.icon}</span>
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <span
                  className={`text-xs font-semibold ${
                    isActive ? 'text-gray-100' : 'text-dark-300'
                  }`}
                >
                  {cat.shortName}
                </span>
                {isActive && (
                  <span
                    className="w-1.5 h-1.5 rounded-full animate-pulse"
                    style={{ backgroundColor: cat.color }}
                  />
                )}
              </div>
              <p className={`text-[10px] leading-tight mt-0.5 truncate ${
                isActive ? 'text-dark-400' : 'text-dark-500'
              }`}>
                {cat.name}
              </p>
            </div>
          </button>
        )
      })}
    </div>
  )
}
