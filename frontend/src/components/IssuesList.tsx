import { useState } from 'react'
import type { Issue, Severity } from '../api'
import { issueFilter } from '../issueFilter'
import { useSettings } from '../settings'

interface Props {
  issues: Issue[]
  highlightedIds?: Set<string> | null
  onSelect: (issue: Issue) => void
  /** Show the packets of an issue in the packet list using this display filter. */
  onShowPackets?: (filter: string) => void
}

/** Issues carrying a TCP stream_id support drill-down to the conversation. */
export function issueStreamId(issue: Issue): number | null {
  const value = issue.evidence['stream_id'] ?? issue.evidence['tcp_stream']
  return typeof value === 'number' ? value : null
}

export default function IssuesList({ issues, highlightedIds, onSelect, onShowPackets }: Props) {
  const { t, lang } = useSettings()
  const [copiedId, setCopiedId] = useState<string | null>(null)
  const copyFilter = async (id: string, filter: string) => {
    try {
      await navigator.clipboard.writeText(filter)
      setCopiedId(id)
      window.setTimeout(() => setCopiedId((current) => (current === id ? null : current)), 1500)
    } catch {
      /* clipboard blocked: nothing to do */
    }
  }
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
        const filter = issueFilter(issue)
        return (
          <div
            key={issue.id}
            className={`issue${clickable ? ' clickable' : ''}${highlighted ? ' highlighted' : ''}`}
            title={clickable ? t('issues.viewConv') : undefined}
            onClick={clickable ? () => onSelect(issue) : undefined}
          >
            <span className={`badge ${issue.severity}`}>{severityLabel(issue.severity)}</span>
            <div className="issue-body">
              <div className="title">
                {(lang === 'en' && issue.title_en) || issue.title}
              </div>
              <div className="detail">
                {(lang === 'en' && issue.detail_en) || issue.detail}
              </div>
              {filter && (
                <div className="issue-actions" onClick={(event) => event.stopPropagation()}>
                  {onShowPackets && (
                    <button className="chip small" onClick={() => onShowPackets(filter)} title={filter}>
                      {t('issues.showPackets')}
                    </button>
                  )}
                  <button className="chip small" onClick={() => copyFilter(issue.id, filter)} title={filter}>
                    {copiedId === issue.id ? t('issues.copied') : t('issues.copyFilter')}
                  </button>
                </div>
              )}
            </div>
          </div>
        )
      })}
    </div>
  )
}
