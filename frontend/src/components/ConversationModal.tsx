import type { AnalysisResult, Issue, PacketRow, Severity, TcpConversation, UdpConversation } from '../api'
import { formatBytes, formatDecimal, formatDuration, formatNumber } from '../format'
import { useSettings } from '../settings'
import FlowGraph from './FlowGraph'
import { issueStreamId } from './IssuesList'

export type Selection =
  | { view: 'host'; address: string }
  | { view: 'conv'; streamId: number }

interface Props {
  result: AnalysisResult
  selection: Selection
  onNavigate: (selection: Selection) => void
  onClose: () => void
}

function KV({ k, v }: { k: string; v: string }) {
  return (
    <div>
      <div className="k">{k}</div>
      <div className="v">{v}</div>
    </div>
  )
}

function ConversationDetail({
  conv,
  issues,
  packets,
}: {
  conv: TcpConversation
  issues: Issue[]
  packets: PacketRow[]
}) {
  const { t } = useSettings()
  const severityLabel = (severity: Severity) => t(`issues.${severity}`)
  return (
    <>
      <div className="kv-grid">
        <KV k={t('modal.packets')} v={formatNumber(conv.packets)} />
        <KV k={t('modal.totalBytes')} v={formatBytes(conv.bytes)} />
        <KV k={t('modal.c2s')} v={formatBytes(conv.bytes_src_to_dst)} />
        <KV k={t('modal.s2c')} v={formatBytes(conv.bytes_dst_to_src)} />
        <KV k={t('modal.duration')} v={formatDuration(conv.duration_seconds)} />
        <KV
          k={t('modal.retrans')}
          v={`${formatNumber(conv.retransmissions)} (${formatDecimal(conv.retransmission_pct, 1)}%)`}
        />
        <KV k={t('modal.zeroWin')} v={formatNumber(conv.zero_window_events)} />
        <KV k={t('modal.mssClient')} v={conv.mss_client != null ? `${conv.mss_client} B` : '—'} />
        <KV k={t('modal.mssServer')} v={conv.mss_server != null ? `${conv.mss_server} B` : '—'} />
        <KV
          k={t('modal.rtt')}
          v={conv.handshake_rtt_ms != null ? `${formatDecimal(conv.handshake_rtt_ms, 1)} ms` : '—'}
        />
      </div>
      {issues.length > 0 && (
        <>
          <div className="section-label">{t('modal.convProblems')}</div>
          {issues.map((issue) => (
            <div className="issue" key={issue.id}>
              <span className={`badge ${issue.severity}`}>{severityLabel(issue.severity)}</span>
              <div>
                <div className="title">{issue.title}</div>
                <div className="detail">{issue.detail}</div>
              </div>
            </div>
          ))}
        </>
      )}
      <FlowGraph packets={packets} endpoints={[conv.src, conv.dst]} />
    </>
  )
}

function HostDetail({
  result,
  address,
  onNavigate,
}: {
  result: AnalysisResult
  address: string
  onNavigate: (selection: Selection) => void
}) {
  const { t } = useSettings()
  const tcp = result.conversations.tcp.filter((c) => c.src === address || c.dst === address)
  const udp = result.conversations.udp.filter((c) => c.src === address || c.dst === address)
  return (
    <>
      {tcp.length > 0 && (
        <>
          <div className="section-label">{t('modal.tcpConvs')}</div>
          <ul className="row-list">
            {tcp.map((conv) => (
              <li
                key={conv.stream_id}
                className="clickable"
                title={t('modal.viewDetail')}
                onClick={() => onNavigate({ view: 'conv', streamId: conv.stream_id })}
              >
                <span className="mono">
                  {conv.src}:{conv.src_port} ⇄ {conv.dst}:{conv.dst_port}
                  {conv.retransmissions > 0 && <span className="warn-mark">⚠</span>}
                </span>
                <span className="bytes">{formatBytes(conv.bytes)}</span>
              </li>
            ))}
          </ul>
        </>
      )}
      {udp.length > 0 && (
        <>
          <div className="section-label">{t('modal.udpConvs')}</div>
          <ul className="row-list">
            {udp.map((conv: UdpConversation) => (
              <li key={conv.stream_id}>
                <span className="mono">
                  {conv.src}:{conv.src_port} ⇄ {conv.dst}:{conv.dst_port}
                </span>
                <span className="bytes">{formatBytes(conv.bytes)}</span>
              </li>
            ))}
          </ul>
        </>
      )}
    </>
  )
}

export default function ConversationModal({ result, selection, onNavigate, onClose }: Props) {
  const { t } = useSettings()
  let title: string
  let body: React.ReactNode
  if (selection.view === 'conv') {
    const conv = result.conversations.tcp.find((c) => c.stream_id === selection.streamId)
    if (!conv) return null
    title = `${conv.src}:${conv.src_port} ⇄ ${conv.dst}:${conv.dst_port}`
    const related = result.issues.filter((issue) => issueStreamId(issue) === conv.stream_id)
    const packets = result.packet_list.rows.filter((row) => row.stream === conv.stream_id)
    body = <ConversationDetail conv={conv} issues={related} packets={packets} />
  } else {
    title = t('modal.hostTitle', { addr: selection.address })
    body = <HostDetail result={result} address={selection.address} onNavigate={onNavigate} />
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" onClick={(event) => event.stopPropagation()}>
        <div className="modal-head">
          <h2 className="mono">{title}</h2>
          <button onClick={onClose} aria-label={t('common.close')}>
            ✕
          </button>
        </div>
        {body}
      </div>
    </div>
  )
}
