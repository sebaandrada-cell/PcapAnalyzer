import { BUY_URL, GITHUB_URL } from '../demo'
import { useSettings } from '../settings'

// Shown above the dashboard in the public demo: says what the visitor is
// looking at and offers the free download, the source code or a way back to
// the sign-in screen.
export default function DemoBanner() {
  const { t } = useSettings()
  return (
    <div className="demo-banner" role="note">
      <span>{t('demo.banner')}</span>
      <span className="demo-actions">
        <a className="demo-buy" href={BUY_URL} target="_blank" rel="noopener noreferrer">
          {t('demo.buy')}
        </a>
        <a className="demo-link-inline" href={GITHUB_URL} target="_blank" rel="noopener noreferrer">
          {t('demo.github')}
        </a>
        {/* Empty fragment: leaves #demo and shows the normal sign-in screen. */}
        <a className="demo-signin" href="#">
          {t('demo.signIn')}
        </a>
      </span>
    </div>
  )
}
