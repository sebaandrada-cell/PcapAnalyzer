import { useState } from 'react'
import { useSettings } from '../settings'

const KEY = 'pcap.noticeSeen'

function alreadySeen(): boolean {
  try {
    return localStorage.getItem(KEY) === '1'
  } catch {
    return false
  }
}

// One-time, dismissible informational notice (not a consent banner: only
// technical storage is used). Storage access is wrapped in try/catch.
export default function CookieNotice() {
  const { t } = useSettings()
  const [visible, setVisible] = useState(() => !alreadySeen())
  if (!visible) return null
  const dismiss = () => {
    try {
      localStorage.setItem(KEY, '1')
    } catch {
      /* storage blocked: just hide it for this page view */
    }
    setVisible(false)
  }
  return (
    <aside className="cookie-notice" role="region" aria-label={t('cookieNotice.label')}>
      <p>
        {t('cookieNotice.text')}{' '}
        <a href="#cookies">{t('cookieNotice.more')}</a>
      </p>
      <button type="button" onClick={dismiss}>
        {t('cookieNotice.ok')}
      </button>
    </aside>
  )
}
