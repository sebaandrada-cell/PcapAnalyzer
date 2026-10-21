import { useState } from 'react'
import type { AnalysisResult } from '../api'
import { exportReport } from '../api'
import { formatBytes, formatDuration } from '../format'
import { useSettings } from '../settings'

interface Props {
  result: AnalysisResult
  diagnosis: string | null
  onReset: () => void
}

export default function Header({ result, diagnosis, onReset }: Props) {
  const { t } = useSettings()
  const { file, summary, meta } = result
  const [exporting, setExporting] = useState(false)
  const [exportError, setExportError] = useState<string | null>(null)

  const handleExport = () => {
    setExporting(true)
    setExportError(null)
    exportReport(result, diagnosis)
      .catch((err: Error) => setExportError(err.message))
      .finally(() => setExporting(false))
  }

  return (
    <div className="header">
      <div>
        <h1>{file.name}</h1>
        <div className="meta">
          {t('header.meta', {
            bytes: formatBytes(file.size_bytes),
            dur: formatDuration(summary.duration_seconds),
            ms: meta.analysis_duration_ms,
            tshark: meta.tshark_version.split('(')[0].trim(),
          })}
          {exportError && <span className="export-error"> · {exportError}</span>}
        </div>
      </div>
      <div className="actions">
        <button onClick={onReset}>{t('header.analyzeAnother')}</button>
        <button onClick={handleExport} disabled={exporting} title={t('header.exportTitle')}>
          {exporting ? t('header.exporting') : t('header.export')}
        </button>
      </div>
    </div>
  )
}
