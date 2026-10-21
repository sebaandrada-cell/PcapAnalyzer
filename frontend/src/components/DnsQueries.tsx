import type { DnsQueryRow } from '../api'
import { useSettings } from '../settings'

const STATUS_CLASS: Record<DnsQueryRow['status'], string> = {
  ok: 'ok',
  slow: 'warning',
  unanswered: 'critical',
  servfail: 'critical',
  nxdomain: 'warning',
}

export default function DnsQueries({ queries }: { queries: DnsQueryRow[] }) {
  const { t } = useSettings()
  if (queries.length === 0) return null
  return (
    <div className="card" style={{ marginBottom: 20 }}>
      <h2 className="card-title">{t('dns.title')}</h2>
      <div className="table-scroll">
        <table className="data-table">
          <thead>
            <tr>
              <th>{t('dns.colName')}</th>
              <th>{t('dns.colClient')}</th>
              <th>{t('dns.colServer')}</th>
              <th>{t('dns.colStatus')}</th>
              <th>{t('dns.colLatency')}</th>
            </tr>
          </thead>
          <tbody>
            {queries.map((query, index) => (
              <tr key={index}>
                <td className="mono">{query.name}</td>
                <td className="mono">{query.client}</td>
                <td className="mono">{query.server}</td>
                <td>
                  <span className={`badge ${STATUS_CLASS[query.status]}`}>
                    {t(`dns.${query.status}`)}
                  </span>
                </td>
                <td>
                  {query.latency_ms != null
                    ? `${query.latency_ms.toFixed(0)} ms`
                    : '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
