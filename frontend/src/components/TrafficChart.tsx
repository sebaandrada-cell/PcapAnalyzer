import { useMemo } from 'react'
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import type { TimeSeriesPoint } from '../api'
import { formatTick } from '../format'
import { useSettings } from '../settings'

// Theme-aware colours: CSS variables resolve in inline SVG, so the chart
// follows light/dark automatically.
const PACKETS_COLOR = 'var(--series-1)'
const RETRANS_COLOR = 'var(--series-6)'

interface Props {
  series: TimeSeriesPoint[]
  duration: number
}

export default function TrafficChart({ series, duration }: Props) {
  const { t } = useSettings()
  const data = useMemo(() => series, [series])

  return (
    <div className="card" style={{ marginBottom: 20 }}>
      <h2 className="card-title">{t('chart.title')}</h2>
      <p className="chart-sub">{t('chart.sub')}</p>
      <div className="legend">
        <span>
          <span className="chip" style={{ background: PACKETS_COLOR }} />
          {t('chart.packetsPerSec')}
        </span>
        <span>
          <span className="chip" style={{ background: RETRANS_COLOR }} />
          {t('chart.retransPerSec')}
        </span>
      </div>
      <ResponsiveContainer width="100%" height={220}>
        <LineChart data={data} margin={{ top: 4, right: 8, bottom: 0, left: -18 }}>
          <CartesianGrid stroke="var(--grid)" vertical={false} />
          <XAxis
            dataKey="t"
            tickFormatter={(tick: number) => formatTick(tick, duration)}
            tick={{ fill: 'var(--ink-muted)', fontSize: 12 }}
            tickLine={false}
            axisLine={{ stroke: 'var(--axis)' }}
            interval="preserveStartEnd"
          />
          <YAxis
            allowDecimals={false}
            tick={{ fill: 'var(--ink-muted)', fontSize: 12 }}
            tickLine={false}
            axisLine={false}
          />
          <Tooltip
            labelFormatter={(label) => `t = ${formatTick(Number(label), duration)}`}
            formatter={(value, name) => [
              value as number,
              name === 'packets' ? t('chart.packetsPerSec') : t('chart.retransPerSec'),
            ]}
            contentStyle={{
              borderRadius: 8,
              border: '1px solid var(--border)',
              background: 'var(--surface)',
              color: 'var(--ink)',
              fontSize: 13,
            }}
          />
          <Line
            type="monotone"
            dataKey="packets"
            stroke={PACKETS_COLOR}
            strokeWidth={2}
            dot={false}
            activeDot={{ r: 4 }}
            isAnimationActive={false}
          />
          <Line
            type="monotone"
            dataKey="retransmissions"
            stroke={RETRANS_COLOR}
            strokeWidth={2}
            dot={false}
            activeDot={{ r: 4 }}
            isAnimationActive={false}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  )
}
