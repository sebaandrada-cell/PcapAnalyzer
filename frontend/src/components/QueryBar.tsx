import { useState } from 'react'
import type { QueryResponse } from '../api'
import { useSettings } from '../settings'

interface Props {
  loading: boolean
  result: QueryResponse | null
  error: string | null
  onSubmit: (question: string) => void
  onClear: () => void
}

// Natural-language query -> Wireshark display filter (Fase 3, AI layer).
export default function QueryBar({ loading, result, error, onSubmit, onClear }: Props) {
  const { t } = useSettings()
  const [question, setQuestion] = useState('')

  const submit = () => {
    const trimmed = question.trim()
    if (trimmed.length >= 3 && !loading) onSubmit(trimmed)
  }

  return (
    <>
      <div className="query-bar">
        <input
          placeholder={t('query.placeholder')}
          value={question}
          disabled={loading}
          onChange={(event) => setQuestion(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === 'Enter') submit()
          }}
        />
        <button className="primary" disabled={loading || question.trim().length < 3} onClick={submit}>
          {loading ? t('query.asking') : t('query.ask')}
        </button>
      </div>
      {error && (
        <div className="query-hint query-error">
          {error}{' '}
          <button className="link" onClick={onClear}>
            {t('common.close')}
          </button>
        </div>
      )}
      {result && !error && (
        <div className="query-hint">
          {t('query.generated')} <code className="mono">{result.filter}</code>
          <span className="query-explanation"> · {result.explanation}</span>
          {result.matched_tcp_streams.length > 0 && (
            <span className="query-explanation"> · {t('query.applied')}</span>
          )}
          {result.matched_tcp_streams.length === 0 && result.matched_issue_ids.length === 0 && (
            <span className="query-explanation"> · {t('query.noMatches')}</span>
          )}
          {result.matched_issue_ids.length > 0 && (
            <span className="query-explanation">
              {' '}
              · {t('query.related', { n: result.matched_issue_ids.length })}
            </span>
          )}
          <button className="link" onClick={onClear}>
            {t('common.clear')}
          </button>
        </div>
      )}
    </>
  )
}
