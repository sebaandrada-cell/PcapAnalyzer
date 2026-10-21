import { useCallback, useEffect, useRef, useState } from 'react'
import { useSettings } from '../settings'

interface HealthTshark {
  available: boolean
  install_hint: string | null
}

interface HealthResponse {
  tshark?: HealthTshark
  max_upload_mb?: number
  auth?: { enabled: boolean }
}

interface Props {
  analyzing: boolean
  error: string | null
  onFile: (file: File) => void
}

export default function UploadScreen({ analyzing, error, onFile }: Props) {
  const { t } = useSettings()
  const inputRef = useRef<HTMLInputElement>(null)
  const [drag, setDrag] = useState(false)
  const [tsharkHint, setTsharkHint] = useState<string | null>(null)
  const [authHint, setAuthHint] = useState(false)
  const [maxUploadMB, setMaxUploadMB] = useState(200)

  useEffect(() => {
    fetch('/health')
      .then((r) => r.json())
      .then((h: HealthResponse) => {
        if (h.tshark && !h.tshark.available) setTsharkHint(h.tshark.install_hint)
        if (h.max_upload_mb) setMaxUploadMB(h.max_upload_mb)
        setAuthHint(h.auth?.enabled === false)
      })
      .catch(() => {
        setTsharkHint(t('upload.backendError'))
      })
  }, [t])

  const handleDrop = useCallback(
    (event: React.DragEvent) => {
      event.preventDefault()
      setDrag(false)
      const file = event.dataTransfer.files[0]
      if (file && !analyzing) onFile(file)
    },
    [analyzing, onFile],
  )

  const loadSample = useCallback(async () => {
    const response = await fetch('/sample.pcap')
    const blob = await response.blob()
    onFile(new File([blob], 'sample.pcap', { type: 'application/octet-stream' }))
  }, [onFile])

  return (
    <div className="upload-wrap">
      <h1>PcapAnalyzer</h1>
      <p className="sub">{t('upload.subtitle')}</p>

      <div
        className={`dropzone${drag ? ' drag' : ''}`}
        onClick={() => inputRef.current?.click()}
        onDragOver={(event) => {
          event.preventDefault()
          setDrag(true)
        }}
        onDragLeave={() => setDrag(false)}
        onDrop={handleDrop}
        aria-disabled={analyzing}
      >
        <div className="big">{analyzing ? t('upload.analyzing') : t('upload.drop')}</div>
        <div className="hint">        {t('upload.hint', { max: maxUploadMB })}</div>
        <input
          ref={inputRef}
          type="file"
          accept=".pcap,.pcapng,.cap,.gz"
          disabled={analyzing}
          hidden
          onChange={(event) => {
            const file = event.target.files?.[0]
            if (file) onFile(file)
            event.target.value = ''
          }}
        />
      </div>

      <div className="upload-actions">
        <button onClick={loadSample} disabled={analyzing}>
          {t('upload.sample')}
        </button>
      </div>

      {error && <div className="upload-error">{error}</div>}
      {tsharkHint && <div className="tshark-warn">{tsharkHint}</div>}
      {authHint && <div className="upload-error">{t('upload.authNotConfigured')}</div>}
    </div>
  )
}
