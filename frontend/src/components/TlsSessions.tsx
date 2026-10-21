import type { TlsSession } from '../api'
import { useSettings } from '../settings'

export default function TlsSessions({ sessions }: { sessions: TlsSession[] }) {
  const { t } = useSettings()
  if (sessions.length === 0) return null
  return (
    <div className="card" style={{ marginBottom: 20 }}>
      <h2 className="card-title">{t('tls.title')}</h2>
      <div className="table-scroll">
        <table className="data-table">
          <thead>
            <tr>
              <th>{t('tls.colStream')}</th>
              <th>{t('tls.colClient')}</th>
              <th>{t('tls.colServer')}</th>
              <th>{t('tls.colVersion')}</th>
              <th>{t('tls.colCipher')}</th>
              <th>{t('tls.colSni')}</th>
              <th>{t('tls.colAlert')}</th>
            </tr>
          </thead>
          <tbody>
            {sessions.map((session) => (
              <tr key={session.stream_id}>
                <td>{session.stream_id}</td>
                <td className="mono">{session.client}</td>
                <td className="mono">{session.server}</td>
                <td>{session.version ?? '—'}</td>
                <td className="mono">{session.cipher ?? '—'}</td>
                <td className="mono">{session.sni ?? '—'}</td>
                <td>
                  {session.alert ? (
                    <span className="badge critical">{session.alert}</span>
                  ) : (
                    '—'
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
