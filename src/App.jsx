import { useState } from 'react'
import Header from './components/layout/Header'
import Footer from './components/layout/Footer'
import CategorySelector from './components/panels/CategorySelector'
import InputPanel from './components/panels/InputPanel'
import OutputPanel from './components/panels/OutputPanel'
import EvasionOptions from './components/panels/EvasionOptions'
import SEOHead from './components/seo/SEOHead'
import SEOContent from './components/seo/SEOContent'
import useWafBypass from './hooks/useWafBypass'
import { Zap, Menu, X } from 'lucide-react'

export default function App() {
  const {
    category,
    setCategory,
    target,
    setTarget,
    inputPayload,
    setInputPayload,
    activeLayers,
    toggleLayer,
    variants,
    generate,
    clearAll,
    error,
  } = useWafBypass()

  const [sidebarOpen, setSidebarOpen] = useState(false)

  return (
    <div className="min-h-screen flex flex-col bg-dark-950">
      {/* Dynamic SEO Head */}
      <SEOHead category={category} />

      {/* Header */}
      <Header />

      {/* Main Content */}
      <main className="flex-1 max-w-7xl mx-auto w-full px-4 sm:px-6 py-5">
        <div className="flex gap-4 relative">

          {/* Mobile Sidebar Toggle */}
          <button
            onClick={() => setSidebarOpen(!sidebarOpen)}
            className="lg:hidden fixed bottom-4 left-4 z-50 flex items-center gap-2 px-4 py-3 bg-waf-red text-white rounded-full shadow-lg shadow-waf-red/20"
          >
            {sidebarOpen ? <X size={18} /> : <Menu size={18} />}
            <span className="text-xs font-semibold">{sidebarOpen ? 'Close' : 'Menu'}</span>
          </button>

          {/* Left Sidebar */}
          <aside
            className={`
              fixed lg:static inset-0 z-40 lg:z-auto
              w-72 lg:w-56 xl:w-64 flex-shrink-0
              bg-dark-950 lg:bg-transparent
              transform transition-transform duration-300 lg:transform-none
              ${sidebarOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'}
              overflow-y-auto
            `}
          >
            {sidebarOpen && (
              <div
                className="fixed inset-0 bg-black/50 lg:hidden -z-10"
                onClick={() => setSidebarOpen(false)}
              />
            )}

            <div className="p-3 lg:p-0 space-y-4">
              <div className="bg-dark-850 border border-dark-700/30 rounded-lg p-3">
                <CategorySelector
                  category={category}
                  onSelect={(cat) => { setCategory(cat); setSidebarOpen(false) }}
                />
              </div>

              <div className="bg-dark-850 border border-dark-700/30 rounded-lg p-3">
                <EvasionOptions
                  category={category}
                  activeLayers={activeLayers}
                  onToggleLayer={toggleLayer}
                  onGenerate={() => { generate(); setSidebarOpen(false) }}
                  hasInput={inputPayload.trim().length > 0}
                />
              </div>
            </div>
          </aside>

          {/* Main Panels */}
          <div className="flex-1 min-w-0">
            <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
              <div className="bg-dark-850 border border-dark-700/30 rounded-lg overflow-hidden terminal-glow">
                <InputPanel
                  category={category}
                  target={target}
                  onTargetChange={setTarget}
                  inputPayload={inputPayload}
                  onPayloadChange={setInputPayload}
                  onClear={clearAll}
                />
              </div>

              <div className="bg-dark-850 border border-dark-700/30 rounded-lg overflow-hidden terminal-glow">
                <OutputPanel variants={variants} error={error} />
              </div>
            </div>

            {/* Mobile Generate Button */}
            <div className="xl:hidden mt-4">
              <button
                onClick={generate}
                disabled={!inputPayload.trim() || activeLayers.length === 0}
                className={`w-full flex items-center justify-center gap-2 px-4 py-3 rounded-lg font-semibold text-sm transition-all ${
                  inputPayload.trim() && activeLayers.length > 0
                    ? 'bg-waf-red hover:bg-red-600 text-white shadow-lg shadow-waf-red/20'
                    : 'bg-dark-700 text-dark-500 cursor-not-allowed'
                }`}
              >
                <Zap size={16} />
                Generate Bypasses
              </button>
            </div>
          </div>
        </div>
      </main>

      {/* SEO Educational Content */}
      <SEOContent />

      {/* Footer */}
      <Footer />
    </div>
  )
}
