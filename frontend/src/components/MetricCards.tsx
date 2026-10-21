import type { AnalysisResult } from '../api'
import { formatDuration, formatNumber } from '../format'
import { useSettings } from '../settings'

export default function MetricCards({ result }: { result: AnalysisResult }) {
  const { t } = useSettings()
  const { summary, issues } = result
  const problemCount = issues.length
  return (
    <div className="metrics">
      <div className="metric">
        <div className="label">{t('metrics.packets')}</div>
        <div className="value">{formatNumber(summary.packets)}</div>
      </div>
      <div className="metric">
        <div className="label">{t('metrics.duration')}</div>
        <div className="value">{formatDuration(summary.duration_seconds)}</div>
      </div>
      <div className="metric">
        <div className="label">{t('metrics.conversations')}</div>
        <div className="value">{formatNumber(summary.conversations)}</div>
      </div>
      <div className={`metric${problemCount > 0 ? ' alert' : ''}`}>
        <div className="label">{t('metrics.problems')}</div>
        <div className="value">{formatNumber(problemCount)}</div>
      </div>
    </div>
  )
}
