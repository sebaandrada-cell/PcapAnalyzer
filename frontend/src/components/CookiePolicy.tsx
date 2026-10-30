import { useSettings } from '../settings'

// Short storage policy (informational; no consent needed, LSSI art. 22.2).
// Reached through the `#cookies` fragment so it works before signing in.
export default function CookiePolicy() {
  const { t } = useSettings()
  const rows: { key: string; purpose: string; duration: string }[] = [
    { key: 'pcap.lang', purpose: t('cookies.lang'), duration: t('cookies.durPersistent') },
    { key: 'pcap.theme', purpose: t('cookies.theme'), duration: t('cookies.durPersistent') },
    { key: 'pcap.rowColors', purpose: t('cookies.rowColors'), duration: t('cookies.durPersistent') },
    { key: 'pcap.apiToken (sessionStorage)', purpose: t('cookies.apiToken'), duration: t('cookies.durSession') },
    { key: 'sb-…-auth-token', purpose: t('cookies.auth'), duration: t('cookies.durAuth') },
    { key: 'pcap.noticeSeen', purpose: t('cookies.notice'), duration: t('cookies.durPersistent') },
  ]
  return (
    <main className="policy">
      <a className="policy-back" href="#">
        ← {t('cookies.back')}
      </a>
      <h1>{t('cookies.title')}</h1>
      <p>{t('cookies.intro')}</p>
      <h2>{t('cookies.tableTitle')}</h2>
      <div className="policy-table-wrap">
        <table className="policy-table">
          <thead>
            <tr>
              <th scope="col">{t('cookies.colKey')}</th>
              <th scope="col">{t('cookies.colPurpose')}</th>
              <th scope="col">{t('cookies.colDuration')}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.key}>
                <td>
                  <code>{row.key}</code>
                </td>
                <td>{row.purpose}</td>
                <td>{row.duration}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <h2>{t('cookies.legalTitle')}</h2>
      <p>{t('cookies.legal')}</p>
      <h2>{t('cookies.deleteTitle')}</h2>
      <p>{t('cookies.delete')}</p>
      <h2>{t('cookies.contactTitle')}</h2>
      <p>{t('cookies.contact')}</p>
    </main>
  )
}
