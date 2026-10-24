import { useState } from 'react'
import type { AnalysisResult } from '../api'
import { exportReport } from '../api'
import { formatBytes, formatDuration } from '../format'
import { useSettings } from '../settings'

interface Props {
  result: AnalysisResult
  diagnosis: string | null
  onReset: () => void
  /** Public demo: there is no backend to export from or capture to replace. */
  demo?: boolean
}

export default function Header({ result, diagnosis, onReset, demo = false }: Props) {
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
        {/* In the public demo the banner above already carries the purchase link. */}
        {!demo && (
          <>
            <button onClick={onReset}>{t('header.analyzeAnother')}</button>
            <button onClick={handleExport} disabled={exporting} title={t('header.exportTitle')}>
              {exporting ? t('header.exporting') : t('header.export')}
            </button>
          </>
        )}
      </div>
    </div>
  )
}
