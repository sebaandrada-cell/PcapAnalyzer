import type { PacketRow } from '../api'
import { useSettings } from '../settings'

const MAX_ROWS = 60
const ROW_H = 30
const TOP = 34
const LEFT_LINE = 130
const RIGHT_LINE = 470
const WIDTH = 500

// Wireshark-style flow (ladder) diagram for one conversation: two lifelines
// with a time-ordered arrow per packet. Built from the packet_list rows.
export default function FlowGraph({
  packets,
  endpoints,
}: {
  packets: PacketRow[]
  endpoints: [string, string]
}) {
  const { t } = useSettings()
  if (packets.length === 0) return null

  const [left, right] = endpoints
  const shown = packets.slice(0, MAX_ROWS)
  const overflow = packets.length - shown.length
  const height = TOP + shown.length * ROW_H + 12

  return (
    <>
      <div className="section-label">{t('flow.title')}</div>
      <div className="flow-scroll">
        <svg viewBox={`0 0 ${WIDTH} ${height}`} className="flow-svg" width="100%">
          <defs>
            <marker
              id="flow-arrow-fwd"
              markerWidth="8"
              markerHeight="8"
              refX="7"
              refY="3"
              orient="auto"
            >
              <path d="M0,0 L7,3 L0,6 Z" fill="var(--series-1)" />
            </marker>
            <marker
              id="flow-arrow-rev"
              markerWidth="8"
              markerHeight="8"
              refX="7"
              refY="3"
              orient="auto"
            >
              <path d="M0,0 L7,3 L0,6 Z" fill="var(--series-2)" />
            </marker>
          </defs>

          {/* endpoint headers */}
          <text x={LEFT_LINE} y="16" textAnchor="middle" className="flow-host">
            {left}
          </text>
          <text x={RIGHT_LINE} y="16" textAnchor="middle" className="flow-host">
            {right}
          </text>
          {/* lifelines */}
          <line x1={LEFT_LINE} y1="22" x2={LEFT_LINE} y2={height - 4} className="flow-line" />
          <line x1={RIGHT_LINE} y1="22" x2={RIGHT_LINE} y2={height - 4} className="flow-line" />

          {shown.map((pkt, index) => {
            const y = TOP + index * ROW_H
            const forward = pkt.src === left
            const x1 = forward ? LEFT_LINE : RIGHT_LINE
            const x2 = forward ? RIGHT_LINE : LEFT_LINE
            const marker = forward ? 'url(#flow-arrow-fwd)' : 'url(#flow-arrow-rev)'
            const stroke = forward ? 'var(--series-1)' : 'var(--series-2)'
            return (
              <g key={pkt.number}>
                <text x="6" y={y + 3} className="flow-time">
                  {pkt.time.toFixed(3)}
                </text>
                <text
                  x={(LEFT_LINE + RIGHT_LINE) / 2}
                  y={y - 5}
                  textAnchor="middle"
                  className="flow-label"
                >
                  {pkt.info.length > 46 ? `${pkt.info.slice(0, 46)}…` : pkt.info}
                </text>
                <line
                  x1={x1}
                  y1={y}
                  x2={x2}
                  y2={y}
                  stroke={stroke}
                  strokeWidth="1.5"
                  markerEnd={marker}
                />
              </g>
            )
          })}
        </svg>
        {overflow > 0 && <div className="flow-more">{t('flow.more', { n: overflow })}</div>}
      </div>
    </>
  )
}
