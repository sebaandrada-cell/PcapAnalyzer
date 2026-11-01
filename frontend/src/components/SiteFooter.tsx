import { CONTACT_ENABLED } from '../contactConfig'
import { useSettings } from '../settings'

export default function SiteFooter() {
  const { t } = useSettings()
  return (
    <footer className="site-footer">
      <a href="#cookies">{t('cookies.link')}</a>
      {CONTACT_ENABLED && (
        <>
          {' · '}
          <a href="#contacto">{t('contact.link')}</a>
        </>
      )}
    </footer>
  )
}
