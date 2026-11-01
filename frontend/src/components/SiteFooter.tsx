import { useSettings } from '../settings'

export default function SiteFooter() {
  const { t } = useSettings()
  return (
    <footer className="site-footer">
      <a href="#cookies">{t('cookies.link')}</a>
      {' · '}
      <a href="#contacto">{t('contact.link')}</a>
    </footer>
  )
}
