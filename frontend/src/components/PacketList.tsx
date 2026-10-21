import { useMemo, useState } from 'react'
import type { PacketListData, PacketRow } from '../api'
import { useSettings } from '../settings'

type SortKey = 'number' | 'time' | 'src' | 'dst' | 'protocol' | 'length'

const COLUMNS: { key: SortKey; labelKey: string }[] = [
  { key: 'number', labelKey: 'packets.colNo' },
  { key: 'time', labelKey: 'packets.colTime' },
  { key: 'src', labelKey: 'packets.colSrc' },
  { key: 'dst', labelKey: 'packets.colDst' },
  { key: 'protocol', labelKey: 'packets.colProto' },
  { key: 'length', labelKey: 'packets.colLen' },
]

const MAX_CHIPS = 6

// Wireshark-style packet list: free-text filter, protocol quick-filters and
// sortable columns.
export default function PacketList({
  data,
  streamIds = null,
}: {
  data: PacketListData
  streamIds?: number[] | null
}) {
  const { t } = useSettings()
  const [filter, setFilter] = useState('')
  const [protocol, setProtocol] = useState<string | null>(null)
  const [sort, setSort] = useState<{ key: SortKey; asc: boolean }>({ key: 'number', asc: true })

  const protocols = useMemo(() => {
    const counts = new Map<string, number>()
    for (const row of data.rows) counts.set(row.protocol, (counts.get(row.protocol) ?? 0) + 1)
    return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, MAX_CHIPS)
  }, [data.rows])

  const rows = useMemo(() => {
    const needle = filter.trim().toLowerCase()
    let visible = data.rows
    if (streamIds) {
      const selected = new Set(streamIds)
      visible = visible.filter((row) => row.stream != null && selected.has(row.stream))
    }
    if (protocol) visible = visible.filter((row) => row.protocol === protocol)
    if (needle) {
      visible = visible.filter((row) =>
        `${row.number} ${row.src} ${row.dst} ${row.protocol} ${row.info}`
          .toLowerCase()
          .includes(needle),
      )
    }
    const direction = sort.asc ? 1 : -1
    return [...visible].sort((a, b) => {
      const left = a[sort.key] as number | string
      const right = b[sort.key] as number | string
      if (typeof left === 'number' && typeof right === 'number') {
        return (left - right) * direction
      }
      return String(left).localeCompare(String(right)) * direction
    })
  }, [data.rows, filter, protocol, sort, streamIds])

  const toggleSort = (key: SortKey) =>
    setSort((current) =>
      current.key === key ? { key, asc: !current.asc } : { key, asc: true },
    )

  const arrow = (key: SortKey) => (sort.key === key ? (sort.asc ? ' ▲' : ' ▼') : '')

  return (
    <div className="card" style={{ marginBottom: 20 }}>
      <div className="packet-head">
        <h2 className="card-title">{t('packets.title')}</h2>
        <input
          className="packet-filter"
          placeholder={t('packets.filter')}
          value={filter}
          onChange={(event) => setFilter(event.target.value)}
        />
      </div>
      <div className="proto-chips">
        <button
          className={protocol === null ? 'chip active' : 'chip'}
          onClick={() => setProtocol(null)}
        >
          {t('packets.all')} ({data.rows.length})
        </button>
        {protocols.map(([name, count]) => (
          <button
            key={name}
            className={protocol === name ? 'chip active' : 'chip'}
            onClick={() => setProtocol(protocol === name ? null : name)}
          >
            {name} ({count})
          </button>
        ))}
      </div>
      {streamIds && (
        <p className="filter-status">
          {t('packets.queryFilter', { n: streamIds.length })}
          {data.truncated && ` ${t('packets.queryFilterSample')}`}
        </p>
      )}
      <div className="table-scroll">
        <table className="data-table mono">
          <thead>
            <tr>
              {COLUMNS.map((column) => (
                <th
                  key={column.key}
                  className="sortable"
                  onClick={() => toggleSort(column.key)}
                  title={t('packets.sort')}
                >
                  {t(column.labelKey)}
                  {arrow(column.key)}
                </th>
              ))}
              <th>{t('packets.colInfo')}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row: PacketRow) => (
              <tr key={row.number}>
                <td>{row.number}</td>
                <td>{row.time.toFixed(3)}</td>
                <td>{row.src}</td>
                <td>{row.dst}</td>
                <td>{row.protocol}</td>
                <td>{row.length}</td>
                <td className="info-cell" title={row.info}>
                  {row.info}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {rows.length === 0 && <p className="table-empty">{t('packets.empty')}</p>}
      </div>
      <div className="table-foot">
        {t('packets.foot', { shown: rows.length, total: data.rows.length })}
        {data.truncated && t('packets.footTrunc', { n: data.rows.length, captured: data.total })}
      </div>
    </div>
  )
}
