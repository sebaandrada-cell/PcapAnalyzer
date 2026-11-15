import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { PacketQueryError, queryPackets } from '../api'
import type { PacketListData, PacketRow } from '../api'
import { FILTER_FIELDS, compileFilter, filtersForRow, looksLikeFilter } from '../displayFilter'
import {
  ROW_COLORS,
  displayAddress,
  formatPacketTime,
  packetsToCsv,
  rowColor,
  type TimeFormat,
} from '../packetView'
import { remoteErrorKey, toServerFilter, type FilterMode } from '../remotePackets'
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
const EXPERT_WARNING = 6291456

// Quick filters: label key + display filter. Hidden when nothing in the capture matches.
const QUICK_FILTERS: { key: string; filter: string }[] = [
  {
    key: 'quickProblems',
    filter:
      'tcp.analysis.flags && !(tcp.analysis.window_update || tcp.analysis.keep_alive) || ' +
      `tcp.flags.reset || _ws.expert.severity >= ${EXPERT_WARNING}`,
  },
  {
    key: 'quickRetrans',
    filter:
      'tcp.analysis.retransmission || tcp.analysis.fast_retransmission || tcp.analysis.spurious_retransmission',
  },
  { key: 'quickDupAck', filter: 'tcp.analysis.duplicate_ack' },
  { key: 'quickLost', filter: 'tcp.analysis.lost_segment' },
  { key: 'quickResets', filter: 'tcp.flags.reset == 1' },
  { key: 'quickSyn', filter: 'tcp.flags.syn == 1 && tcp.flags.ack == 0' },
  { key: 'quickWindow', filter: 'tcp.analysis.zero_window || tcp.analysis.window_full' },
  { key: 'quickIcmp', filter: 'icmp || icmpv6' },
  { key: 'quickDns', filter: 'dns' },
  { key: 'quickExpert', filter: `_ws.expert.severity >= ${EXPERT_WARNING}` },
]

function loadColors(): boolean {
  try {
    return localStorage.getItem('pcap.rowColors') !== '0'
  } catch {
    return true
  }
}

function saveColors(enabled: boolean): void {
  try {
    localStorage.setItem('pcap.rowColors', enabled ? '1' : '0')
  } catch {
    /* storage blocked: the preference just does not persist */
  }
}

async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    return false
  }
}

interface Props {
  data: PacketListData
  streamIds?: number[] | null
  /** Display filter proposed by the natural-language query (used when it compiles). */
  queryFilter?: string | null
  names?: Map<string, string>
  startEpoch?: number | null
  /** Pushes a filter into the box from elsewhere (issues, conversation modal...). */
  filterRequest?: { text: string; id: number } | null
  /** Investigation session keeping the capture: enables whole-capture search. */
  sessionId?: string | null
}

interface RemoteResult {
  source: string // text in the filter box when the search ran
  filter: string // display filter sent to the server
  rows: PacketRow[]
  hasMore: boolean
  matched: number | null
}

type RemoteStatus = { kind: 'loading' } | { kind: 'error'; key: string; detail: string }

function filterMode(text: string, known: Set<string>): FilterMode {
  const compiled = compileFilter(text, known)
  if (compiled.ok) return compiled.empty ? 'none' : 'filter'
  return looksLikeFilter(text) ? 'error' : 'text'
}

// Wireshark-style packet list: display filters (a subset of the real language),
// quick filters, colouring rules, time formats, name resolution and CSV export.
export default function PacketList({
  data,
  streamIds = null,
  queryFilter = null,
  names,
  startEpoch = null,
  filterRequest = null,
  sessionId = null,
}: Props) {
  const { t } = useSettings()
  const [filter, setFilter] = useState('')
  const [protocol, setProtocol] = useState<string | null>(null)
  const [sort, setSort] = useState<{ key: SortKey; asc: boolean }>({ key: 'number', asc: true })
  const [timeFormat, setTimeFormat] = useState<TimeFormat>('relative')
  const [resolve, setResolve] = useState(false)
  const [colors, setColors] = useState(loadColors)
  const [selected, setSelected] = useState<number | null>(null)
  const [copied, setCopied] = useState<string | null>(null)
  const [validSource, setValidSource] = useState('')
  // Whole-capture search: the list holds only the first packets, the server
  // keeps the capture for the session and runs the real filter with tshark.
  const [remote, setRemote] = useState<RemoteResult | null>(null)
  const [remoteStatus, setRemoteStatus] = useState<RemoteStatus | null>(null)
  const abortRef = useRef<AbortController | null>(null)
  const canSearchAll = Boolean(sessionId) && data.truncated
  const baseRows = remote ? remote.rows : data.rows

  const knownProtocols = useMemo(
    () => new Set(baseRows.map((row) => row.protocol.toLowerCase())),
    [baseRows],
  )

  const clearRemote = useCallback(() => {
    abortRef.current?.abort()
    setRemote(null)
    setRemoteStatus(null)
  }, [])

  const searchAll = useCallback(
    async (text: string) => {
      if (!sessionId) return
      abortRef.current?.abort()
      const serverFilter = toServerFilter(text, filterMode(text, knownProtocols))
      if (!serverFilter) {
        setRemote(null)
        setRemoteStatus(null)
        return
      }
      const controller = new AbortController()
      abortRef.current = controller
      setRemoteStatus({ kind: 'loading' })
      try {
        const result = await queryPackets(sessionId, serverFilter, controller.signal)
        if (controller.signal.aborted) return
        setRemote({
          source: text.trim(),
          filter: serverFilter,
          rows: result.rows,
          hasMore: result.has_more,
          matched: result.matched,
        })
        setRemoteStatus(null)
        setProtocol(null)
        setSelected(null)
      } catch (error) {
        if (controller.signal.aborted) return
        const status = error instanceof PacketQueryError ? error.status : 0
        setRemoteStatus({
          kind: 'error',
          key: remoteErrorKey(status),
          detail: status === 422 && error instanceof Error ? error.message : '',
        })
      }
    },
    [sessionId, knownProtocols],
  )
  const searchAllRef = useRef(searchAll)
  useEffect(() => {
    searchAllRef.current = searchAll
  }, [searchAll])

  // A filter pushed from outside (evidence, issues, conversation modal) replaces
  // the current one; on a truncated list it is looked up in the whole capture.
  useEffect(() => {
    if (!filterRequest) return
    setFilter(filterRequest.text)
    setProtocol(null)
    if (canSearchAll) void searchAllRef.current(filterRequest.text)
  }, [filterRequest, canSearchAll])

  // A new analysis starts from its own sample; pending searches are dropped.
  useEffect(() => {
    setRemote(null)
    setRemoteStatus(null)
    return () => abortRef.current?.abort()
  }, [data])

  const protocols = useMemo(() => {
    const counts = new Map<string, number>()
    for (const row of baseRows) counts.set(row.protocol, (counts.get(row.protocol) ?? 0) + 1)
    return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, MAX_CHIPS)
  }, [baseRows])

  const quick = useMemo(
    () =>
      QUICK_FILTERS.map((entry) => {
        const compiled = compileFilter(entry.filter, knownProtocols)
        const count = compiled.ok ? baseRows.filter(compiled.test).length : 0
        return { ...entry, count }
      }).filter((entry) => entry.count > 0),
    [baseRows, knownProtocols],
  )

  const compiled = useMemo(() => compileFilter(filter, knownProtocols), [filter, knownProtocols])
  const queryCompiled = useMemo(
    () => (queryFilter ? compileFilter(queryFilter, knownProtocols) : null),
    [queryFilter, knownProtocols],
  )
  const queryApplies = Boolean(queryCompiled && queryCompiled.ok && !queryCompiled.empty)

  // text search | display filter | invalid display filter (keeps the last valid one)
  const mode: 'none' | 'filter' | 'text' | 'error' = compiled.ok
    ? compiled.empty
      ? 'none'
      : 'filter'
    : looksLikeFilter(filter)
      ? 'error'
      : 'text'

  // While a filter is mid-edit and invalid, keep showing the last valid one.
  useEffect(() => {
    if (mode === 'filter') setValidSource(filter)
  }, [mode, filter])
  const fallback = useMemo(() => compileFilter(validSource, knownProtocols), [validSource, knownProtocols])

  const useNames = resolve && names && names.size > 0 ? names : null
  const startEpochValue = startEpoch ?? null

  // tshark filters the raw capture, where a frame copied by the mirror port
  // looks like a retransmission; say how many of the matches are such copies.
  const remoteDuplicates = useMemo(
    () => (remote ? remote.rows.filter((row) => (row.analysis ?? []).includes('duplicate_frame')).length : 0),
    [remote],
  )

  // The server already applied the text that is still in the box.
  const remoteCoversFilter = remote != null && filter.trim() === remote.source

  const rows = useMemo(() => {
    let visible = baseRows
    if (queryApplies && queryCompiled && queryCompiled.ok) {
      visible = visible.filter(queryCompiled.test)
    } else if (streamIds) {
      const selectedStreams = new Set(streamIds)
      visible = visible.filter((row) => row.stream != null && selectedStreams.has(row.stream))
    }
    if (protocol) visible = visible.filter((row) => row.protocol === protocol)
    if (remoteCoversFilter) {
      /* nothing to narrow locally */
    } else if (mode === 'filter' && compiled.ok) visible = visible.filter(compiled.test)
    else if (mode === 'error' && fallback.ok) visible = visible.filter(fallback.test)
    else if (mode === 'text') {
      const needle = filter.trim().toLowerCase()
      visible = visible.filter((row) =>
        `${row.number} ${row.src} ${row.dst} ${displayAddress(row.src, useNames)} ${displayAddress(row.dst, useNames)} ${row.protocol} ${row.info}`
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
  }, [baseRows, remoteCoversFilter, filter, protocol, sort, streamIds, queryApplies, queryCompiled, compiled, fallback, mode, useNames])

  const selectedRow = useMemo(
    () => (selected == null ? null : (baseRows.find((row) => row.number === selected) ?? null)),
    [baseRows, selected],
  )

  const toggleSort = (key: SortKey) =>
    setSort((current) =>
      current.key === key ? { key, asc: !current.asc } : { key, asc: true },
    )
  const arrow = (key: SortKey) => (sort.key === key ? (sort.asc ? ' ▲' : ' ▼') : '')

  const flash = (id: string) => {
    setCopied(id)
    window.setTimeout(() => setCopied((current) => (current === id ? null : current)), 1500)
  }
  const copy = async (id: string, text: string) => {
    if (await copyText(text)) flash(id)
  }
  const toggleColors = () => {
    setColors((current) => {
      saveColors(!current)
      return !current
    })
  }
  const exportCsv = () => {
    const blob = new Blob([`﻿${packetsToCsv(rows, useNames)}`], { type: 'text/csv;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = 'packets.csv'
    document.body.appendChild(link)
    link.click()
    link.remove()
    URL.revokeObjectURL(url)
  }

  const filterStatus = (() => {
    if (remoteCoversFilter) return null // tshark accepted it: the local subset has no say
    if (remoteStatus?.kind === 'error') return null // the server's answer is shown instead
    if (canSearchAll && mode === 'error') {
      return { kind: 'hint' as const, text: t('packets.filterServerOnly') }
    }
    if (!compiled.ok && mode === 'error') {
      return {
        kind: 'bad' as const,
        text: t(`packets.err.${compiled.error.code}`, {
          arg: compiled.error.arg ?? '',
          pos: compiled.error.position + 1,
        }),
      }
    }
    if (mode === 'filter') return { kind: 'ok' as const, text: t('packets.filterValid') }
    if (mode === 'text') return { kind: 'hint' as const, text: t('packets.filterText') }
    return null
  })()

  let previous: PacketRow | null = null

  return (
    <div className="card" id="packet-list" style={{ marginBottom: 20 }}>
      <div className="packet-head">
        <h2 className="card-title">{t('packets.title')}</h2>
        <div className="packet-filter-wrap">
          <input
            className={`packet-filter${mode === 'error' ? ' invalid' : mode === 'filter' ? ' valid' : ''}`}
            placeholder={t('packets.filter')}
            value={filter}
            spellCheck={false}
            autoCapitalize="off"
            autoCorrect="off"
            aria-invalid={mode === 'error'}
            aria-label={t('packets.title')}
            onChange={(event) => {
              setFilter(event.target.value)
              if (!event.target.value.trim() && remote) clearRemote()
            }}
            onKeyDown={(event) => {
              if (event.key === 'Enter' && canSearchAll) void searchAll(filter)
            }}
          />
          {canSearchAll && (
            <button
              className="chip small"
              onClick={() => void searchAll(filter)}
              disabled={remoteStatus?.kind === 'loading' || !filter.trim()}
              title={t('packets.searchAllHint', { n: data.rows.length, total: data.total })}
            >
              {t('packets.searchAll')}
            </button>
          )}
          {filter && (
            <button
              className="chip small"
              onClick={() => copy('filter', filter)}
              title={t('packets.copyFilter')}
            >
              {copied === 'filter' ? t('packets.copied') : t('packets.copy')}
            </button>
          )}
        </div>
      </div>
      {filterStatus && (
        <p className={`filter-note ${filterStatus.kind}`} role={filterStatus.kind === 'bad' ? 'alert' : undefined}>
          {filterStatus.text}
        </p>
      )}
      {remoteStatus?.kind === 'loading' && (
        <p className="filter-note hint" role="status">{t('packets.remoteLoading')}</p>
      )}
      {remoteStatus?.kind === 'error' && (
        <p className="filter-note bad" role="alert">
          {t(remoteStatus.key)}
          {remoteStatus.detail && ` ${remoteStatus.detail}`}
        </p>
      )}
      {remote && remoteStatus === null && (
        <p className="filter-note ok" role="status">
          {t(remote.hasMore ? 'packets.remoteResultMore' : 'packets.remoteResult', {
            n: remote.matched ?? remote.rows.length,
            filter: remote.filter,
          })}{' '}
          <button className="chip small" onClick={clearRemote}>{t('packets.remoteBack')}</button>
        </p>
      )}
      {remote && remoteStatus === null && remoteDuplicates > 0 && (
        <p className="filter-note hint">{t('packets.remoteDupNote', { n: remoteDuplicates })}</p>
      )}
      {canSearchAll && !remote && remoteStatus === null && (
        <p className="filter-note hint">
          {t('packets.searchAllHint', { n: data.rows.length, total: data.total })}
        </p>
      )}
      <details className="filter-help">
        <summary>?</summary>
        <p>{t('packets.filterHelp', { fields: FILTER_FIELDS.join(', ') })}</p>
      </details>

      {quick.length > 0 && (
        <div className="proto-chips" aria-label={t('packets.quick')}>
          {quick.map((entry) => (
            <button
              key={entry.key}
              className={filter === entry.filter ? 'chip active' : 'chip'}
              onClick={() => setFilter(filter === entry.filter ? '' : entry.filter)}
              title={entry.filter}
            >
              {t(`packets.${entry.key}`)} ({entry.count})
            </button>
          ))}
        </div>
      )}
      <div className="proto-chips">
        <button
          className={protocol === null ? 'chip active' : 'chip'}
          onClick={() => setProtocol(null)}
        >
          {t('packets.all')} ({baseRows.length})
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

      <div className="packet-tools">
        <label>
          {t('packets.time')}{' '}
          <select value={timeFormat} onChange={(event) => setTimeFormat(event.target.value as TimeFormat)}>
            <option value="relative">{t('packets.timeRelative')}</option>
            <option value="delta">{t('packets.timeDelta')}</option>
            <option value="absolute" disabled={startEpochValue == null}>
              {t('packets.timeAbsolute')}
            </option>
          </select>
        </label>
        {names && names.size > 0 && (
          <label title={t('packets.namesHint')}>
            <input type="checkbox" checked={resolve} onChange={(event) => setResolve(event.target.checked)} />{' '}
            {t('packets.names')}
          </label>
        )}
        <label title={t('packets.colorsHint')}>
          <input type="checkbox" checked={colors} onChange={toggleColors} /> {t('packets.colors')}
        </label>
        <button className="chip small" onClick={exportCsv} disabled={rows.length === 0} title={t('packets.exportHint')}>
          {t('packets.exportCsv')}
        </button>
      </div>
      {colors && (
        <div className="color-legend" aria-hidden="true">
          {ROW_COLORS.map((color) => (
            <span key={color} className={`legend-item row-${color}`}>
              {t(`packets.color.${color}`)}
            </span>
          ))}
        </div>
      )}

      {queryApplies && queryFilter && (
        <p className="filter-status">
          {t('packets.queryDisplayFilter', { filter: queryFilter })}
        </p>
      )}
      {!queryApplies && streamIds && (
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
            {rows.map((row: PacketRow) => {
              const shownTime = formatPacketTime(row, timeFormat, previous, startEpochValue)
              previous = row
              const color = colors ? rowColor(row) : null
              const classes = [color ? `row-${color}` : '', row.number === selected ? 'selected' : '']
                .filter(Boolean)
                .join(' ')
              return (
                <tr
                  key={row.number}
                  className={classes || undefined}
                  onClick={() => setSelected(row.number === selected ? null : row.number)}
                >
                  <td>{row.number}</td>
                  <td>{shownTime}</td>
                  <td>{displayAddress(row.src, useNames)}</td>
                  <td>{displayAddress(row.dst, useNames)}</td>
                  <td>{row.protocol}</td>
                  <td>{row.length}</td>
                  <td className="info-cell" title={row.info}>
                    {row.info}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
        {rows.length === 0 && <p className="table-empty">{t('packets.empty')}</p>}
      </div>
      <div className="table-foot">
        {t('packets.foot', { shown: rows.length, total: baseRows.length })}
        {remote
          ? t('packets.footRemote', { captured: data.total })
          : data.truncated && t('packets.footTrunc', { n: data.rows.length, captured: data.total })}
      </div>
      {selectedRow && (
        <PacketDetail
          row={selectedRow}
          copied={copied}
          onCopy={copy}
          onUseFilter={(text) => setFilter(text)}
          onClose={() => setSelected(null)}
        />
      )}
    </div>
  )
}

function PacketDetail({
  row,
  copied,
  onCopy,
  onUseFilter,
  onClose,
}: {
  row: PacketRow
  copied: string | null
  onCopy: (id: string, text: string) => void
  onUseFilter: (text: string) => void
  onClose: () => void
}) {
  const { t } = useSettings()
  const filters = filtersForRow(row)
  const labels: Record<string, string> = {
    src: 'useSrc',
    dst: 'useDst',
    hosts: 'useHosts',
    conversation: 'useConv',
    stream: 'useStream',
    port: 'usePort',
  }
  const facts: [string, string][] = []
  if (row.sport != null && row.dport != null) facts.push([t('packets.detailPorts'), `${row.sport} → ${row.dport}`])
  if ((row.tcp_flags ?? []).length > 0) facts.push([t('packets.detailFlags'), (row.tcp_flags ?? []).join(', ')])
  if (row.seq != null || row.ack != null) facts.push([t('packets.detailSeq'), `${row.seq ?? '—'} / ${row.ack ?? '—'}`])
  if (row.win != null) facts.push([t('packets.detailWin'), String(row.win)])
  if (row.payload != null) facts.push([t('packets.detailPayload'), `${row.payload} B`])
  if (row.ttl != null) facts.push([t('packets.detailTtl'), String(row.ttl)])
  if (row.rtt_ms != null) facts.push([t('packets.detailRtt'), `${row.rtt_ms} ms`])
  const analysis = (row.analysis ?? []).map((flag) => {
    const key = `packets.analysisFlag.${flag}`
    const label = t(key)
    return label === key ? flag : label
  })
  return (
    <div className="packet-detail">
      <div className="packet-detail-head">
        <strong>
          {t('packets.detail')} #{row.number}
        </strong>
        <button className="chip small" onClick={onClose} aria-label={t('packets.detailClose')}>
          ✕
        </button>
      </div>
      <dl className="kv-inline">
        {facts.map(([k, v]) => (
          <div key={k}>
            <dt>{k}</dt>
            <dd className="mono">{v}</dd>
          </div>
        ))}
        {analysis.length > 0 && (
          <div>
            <dt>{t('packets.detailAnalysis')}</dt>
            <dd>{analysis.join(', ')}</dd>
          </div>
        )}
        {row.expert_message && (
          <div>
            <dt>{t('packets.detailExpert')}</dt>
            <dd>
              {row.expert ? `${t(`expert.${row.expert}`)}: ` : ''}
              {row.expert_message}
            </dd>
          </div>
        )}
      </dl>
      <div className="use-as-filter">
        <span>{t('packets.useAs')}:</span>
        {Object.entries(filters).map(([kind, text]) => (
          <span key={kind} className="filter-pair">
            <button className="chip small" onClick={() => onUseFilter(text)} title={text}>
              {t(`packets.${labels[kind] ?? 'useConv'}`)}
            </button>
            <button
              className="chip small ghost"
              onClick={() => onCopy(`row-${kind}`, text)}
              title={`${t('packets.copyFilter')}: ${text}`}
              aria-label={`${t('packets.copyFilter')}: ${t(`packets.${labels[kind] ?? 'useConv'}`)}`}
            >
              {copied === `row-${kind}` ? '✓' : '⧉'}
            </button>
          </span>
        ))}
      </div>
    </div>
  )
}
