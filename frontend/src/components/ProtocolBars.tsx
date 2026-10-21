import type { ProtocolStat } from '../api'
import { useSettings } from '../settings'

// Fixed categorical slot order (validated palette); "otros" is always muted.
const SLOT_COLORS = [
  'var(--series-1)',
  'var(--series-2)',
  'var(--series-3)',
  'var(--series-4)',
  'var(--series-5)',
  'var(--series-6)',
]
const OTHER_COLOR = 'var(--ink-muted)'
const MAX_ROWS = 6

export default function ProtocolBars({ protocols }: { protocols: ProtocolStat[] }) {
  const { t } = useSettings()
  const top = protocols.slice(0, MAX_ROWS)
  const restPct = protocols.slice(MAX_ROWS).reduce((sum, p) => sum + p.packet_pct, 0)
  const rows = top.map((p, i) => ({
    name: p.protocol.toUpperCase(),
    pct: p.packet_pct,
    color: SLOT_COLORS[i],
  }))
  if (restPct > 0) rows.push({ name: t('protocols.other'), pct: restPct, color: OTHER_COLOR })
  const maxPct = Math.max(...rows.map((r) => r.pct), 1)

  return (
    <div className="card">
      <h2 className="card-title">{t('protocols.title')}</h2>
      {rows.map((row) => (
        <div className="proto-row" key={row.name}>
          <span className="name" title={row.name}>
            {row.name}
          </span>
          <div className="track">
            <div
              className="fill"
              style={{ width: `${(row.pct / maxPct) * 100}%`, background: row.color }}
            />
          </div>
          <span className="pct">{Math.round(row.pct)}%</span>
        </div>
      ))}
    </div>
  )
}
