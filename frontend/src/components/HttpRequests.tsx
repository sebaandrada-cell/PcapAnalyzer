import type { HttpRequestRow } from '../api'
import { useSettings } from '../settings'

function statusClass(status: number | null): string {
  if (status === null) return 'critical'
  if (status >= 500) return 'critical'
  if (status >= 400) return 'warning'
  return 'ok'
}

export default function HttpRequests({ requests }: { requests: HttpRequestRow[] }) {
  const { t } = useSettings()
  if (requests.length === 0) return null
  return (
    <div className="card" style={{ marginBottom: 20 }}>
      <h2 className="card-title">{t('http.title')}</h2>
      <div className="table-scroll">
        <table className="data-table">
          <thead>
            <tr>
              <th>{t('http.colTime')}</th>
              <th>{t('http.colClient')}</th>
              <th>{t('http.colServer')}</th>
              <th>{t('http.colMethod')}</th>
              <th>{t('http.colUrl')}</th>
              <th>{t('http.colStatus')}</th>
            </tr>
          </thead>
          <tbody>
            {requests.map((request, index) => (
              <tr key={index}>
                <td>{request.time.toFixed(3)}</td>
                <td className="mono">{request.client}</td>
                <td className="mono">{request.server}</td>
                <td className="mono">{request.method}</td>
                <td className="mono info-cell" title={`${request.host}${request.uri}`}>
                  {request.host}
                  {request.uri}
                </td>
                <td>
                  <span className={`badge ${statusClass(request.status)}`}>
                    {request.status ?? t('http.noResponse')}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
