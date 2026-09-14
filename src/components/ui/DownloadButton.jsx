import { Download } from 'lucide-react'

export default function DownloadButton({ bytesBase64, filename = 'payload.bin', mimeType = 'application/octet-stream' }) {
  const handleDownload = () => {
    const binary = atob(bytesBase64)
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0))
    const url = URL.createObjectURL(new Blob([bytes], { type: mimeType }))
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = filename
    anchor.click()
    setTimeout(() => URL.revokeObjectURL(url), 0)
  }

  return (
    <button
      type="button"
      onClick={handleDownload}
      className="inline-flex items-center gap-1 px-2 py-1 text-[11px] rounded transition-all duration-200 text-waf-cyan bg-waf-cyan/10 hover:bg-waf-cyan/20 border border-waf-cyan/30"
      title="Download the exact encoded bytes"
    >
      <Download size={11} />
      <span>Download bytes</span>
    </button>
  )
}
