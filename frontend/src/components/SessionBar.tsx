import { useEffect, useState } from 'react'
import { formatNumber } from '../format'
import { useSettings } from '../settings'

interface Props {
  expiresAt: number | null // epoch seconds
  expired: boolean
  contentAllowed: boolean
  onToggleContent: (next: boolean) => void
  costUsd: number | null
  totalTokens: number
  onDelete: () => void
  onExpired: () => void
  demo: boolean
}

function mmss(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds))
  return `${String(Math.floor(s / 60)).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}`
}

// Countdown to deletion, the content switch (with its warning) and the cost.
export default function SessionBar({
  expiresAt, expired, contentAllowed, onToggleContent, costUsd, totalTokens, onDelete, onExpired, demo,
}: Props) {
  const { t } = useSettings()
  const [now, setNow] = useState(() => Date.now() / 1000)

  useEffect(() => {
    if (demo || expiresAt == null) return
    const timer = window.setInterval(() => setNow(Date.now() / 1000), 1000)
    return () => window.clearInterval(timer)
  }, [demo, expiresAt])

  const remaining = expiresAt == null ? null : expiresAt - now
  useEffect(() => {
    if (!expired && remaining != null && remaining <= 0) onExpired()
  }, [expired, remaining, onExpired])

  if (demo) return null

  const toggle = (next: boolean) => {
    if (next && !window.confirm(t('session.contentWarning'))) return
    onToggleContent(next)
  }

  return (
    <div className="session-bar" role="status">
      {expired || (remaining != null && remaining <= 0) ? (
        <span className="expired">{t('session.expired')}</span>
      ) : (
        remaining != null && <span>{t('session.expiresIn', { mmss: mmss(remaining) })}</span>
      )}
      <label title={t('session.contentWarning')}>
        <input type="checkbox" checked={contentAllowed} disabled={expired} onChange={(e) => toggle(e.target.checked)} />{' '}
        {t('session.content')}
      </label>
      <span className="spacer" />
      <span title={t('session.costTitle')}>
        {costUsd == null
          ? t('session.costUnknown', { tokens: formatNumber(totalTokens) })
          : t('session.cost', { usd: costUsd.toFixed(costUsd < 0.1 ? 3 : 2), tokens: formatNumber(totalTokens) })}
      </span>
      <button className="chip small" disabled={expired} onClick={() => window.confirm(t('session.deleteConfirm')) && onDelete()}>
        {t('session.delete')}
      </button>
    </div>
  )
}
