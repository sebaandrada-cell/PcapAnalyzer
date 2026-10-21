import type { Issue, Severity } from '../api'
import { useSettings } from '../settings'

interface Props {
  issues: Issue[]
  highlightedIds?: Set<string> | null
  onSelect: (issue: Issue) => void
}

/** Issues carrying a TCP stream_id support drill-down to the conversation. */
export function issueStreamId(issue: Issue): number | null {
  const value = issue.evidence['stream_id'] ?? issue.evidence['tcp_stream']
  return typeof value === 'number' ? value : null
}

export default function IssuesList({ issues, highlightedIds, onSelect }: Props) {
  const { t, lang } = useSettings()
  const severityLabel = (severity: Severity) => t(`issues.${severity}`)
  return (
    <div className="card">
      <h2 className="card-title">{t('issues.title')}</h2>
      {issues.length === 0 && (
        <p style={{ color: 'var(--ink-secondary)' }}>{t('issues.none')}</p>
      )}
      {issues.map((issue) => {
        const clickable = issueStreamId(issue) !== null
        const highlighted = highlightedIds?.has(issue.id) ?? false
        return (
          <div
            key={issue.id}
            className={`issue${clickable ? ' clickable' : ''}${highlighted ? ' highlighted' : ''}`}
            title={clickable ? t('issues.viewConv') : undefined}
            onClick={clickable ? () => onSelect(issue) : undefined}
          >
            <span className={`badge ${issue.severity}`}>{severityLabel(issue.severity)}</span>
            <div>
              <div className="title">
                {(lang === 'en' && issue.title_en) || issue.title}
              </div>
              <div className="detail">
                {(lang === 'en' && issue.detail_en) || issue.detail}
              </div>
            </div>
          </div>
        )
      })}
    </div>
  )
}
