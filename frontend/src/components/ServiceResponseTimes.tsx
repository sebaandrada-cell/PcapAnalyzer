import type { ServiceResponseTime } from '../api'
import { formatDecimal } from '../format'
import { useSettings } from '../settings'

// Wireshark "Service Response Time": min/avg/max latency per protocol.
export default function ServiceResponseTimes({ rows }: { rows: ServiceResponseTime[] }) {
  const { t } = useSettings()
  if (rows.length === 0) return null
  return (
    <div className="card" style={{ marginBottom: 20 }}>
      <h2 className="card-title">{t('srt.title')}</h2>
      <p className="chart-sub">{t('srt.sub')}</p>
      <div className="table-scroll">
        <table className="data-table">
          <thead>
            <tr>
              <th>{t('srt.colProto')}</th>
              <th>{t('srt.colSamples')}</th>
              <th>{t('srt.colMin')}</th>
              <th>{t('srt.colAvg')}</th>
              <th>{t('srt.colMax')}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.protocol}>
                <td>{row.protocol}</td>
                <td>{row.samples}</td>
                <td>{formatDecimal(row.min_ms, 1)} ms</td>
                <td>{formatDecimal(row.avg_ms, 1)} ms</td>
                <td>{formatDecimal(row.max_ms, 1)} ms</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
