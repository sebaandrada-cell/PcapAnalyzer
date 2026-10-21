import type { DhcpLeaseRow } from '../api'
import { useSettings } from '../settings'

const STATUS_CLASS: Record<DhcpLeaseRow['status'], string> = {
  bound: 'ok',
  nak: 'critical',
  no_offer: 'critical',
  offered: 'warning',
  declined: 'warning',
  released: 'ok',
}

export default function DhcpLeases({ leases }: { leases: DhcpLeaseRow[] }) {
  const { t } = useSettings()
  if (leases.length === 0) return null
  return (
    <div className="card" style={{ marginBottom: 20 }}>
      <h2 className="card-title">{t('dhcp.title')}</h2>
      <div className="table-scroll">
        <table className="data-table">
          <thead>
            <tr>
              <th>{t('dhcp.colMac')}</th>
              <th>{t('dhcp.colHost')}</th>
              <th>{t('dhcp.colIp')}</th>
              <th>{t('dhcp.colServer')}</th>
              <th>{t('dhcp.colStatus')}</th>
              <th>{t('dhcp.colLatency')}</th>
            </tr>
          </thead>
          <tbody>
            {leases.map((lease, index) => (
              <tr key={index}>
                <td className="mono">{lease.client_mac}</td>
                <td>{lease.hostname ?? '—'}</td>
                <td className="mono">{lease.ip ?? '—'}</td>
                <td className="mono">{lease.server ?? '—'}</td>
                <td>
                  <span className={`badge ${STATUS_CLASS[lease.status]}`}>
                    {t(`dhcp.${lease.status}`)}
                  </span>
                </td>
                <td>
                  {lease.latency_ms != null ? `${lease.latency_ms.toFixed(0)} ms` : '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
