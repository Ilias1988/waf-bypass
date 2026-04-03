import { useEffect, useState } from 'react'
import { AlertCircle, CheckCircle, X } from 'lucide-react'

export default function Toast({ message, type = 'info', onClose, duration = 3000 }) {
  const [visible, setVisible] = useState(true)

  useEffect(() => {
    const timer = setTimeout(() => {
      setVisible(false)
      setTimeout(onClose, 300)
    }, duration)
    return () => clearTimeout(timer)
  }, [duration, onClose])

  const colors = {
    error: 'bg-waf-red/10 border-waf-red/30 text-waf-red',
    success: 'bg-waf-green/10 border-waf-green/30 text-waf-green',
    info: 'bg-waf-blue/10 border-waf-blue/30 text-waf-blue',
  }

  return (
    <div
      className={`fixed bottom-4 right-4 z-50 flex items-center gap-2 px-4 py-3 border rounded-lg shadow-lg ${
        colors[type]
      } ${visible ? 'toast-enter' : 'toast-exit'}`}
    >
      {type === 'error' ? <AlertCircle size={16} /> : <CheckCircle size={16} />}
      <span className="text-sm font-medium">{message}</span>
      <button onClick={() => { setVisible(false); setTimeout(onClose, 300) }} className="ml-2 opacity-60 hover:opacity-100">
        <X size={14} />
      </button>
    </div>
  )
}
