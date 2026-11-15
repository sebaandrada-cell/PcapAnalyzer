// Types mirroring backend/app/models.py — the API contract.
import { SseParser } from './sse'
import { supabaseClient } from './supabase'

export type Severity = 'critical' | 'warning' | 'info'

export interface FileInfo {
  name: string
  size_bytes: number
}

export interface Summary {
  packets: number
  bytes: number
  duration_seconds: number
  conversations: number
  start_time_epoch: number | null
  end_time_epoch: number | null
  avg_packets_per_second: number
  avg_bytes_per_second: number
}

export interface ProtocolStat {
  protocol: string
  packets: number
  bytes: number
  packet_pct: number
  bytes_pct: number
}

export interface TimeSeriesPoint {
  t: number
  packets: number
  bytes: number
  retransmissions: number
}

export interface TcpConversation {
  stream_id: number
  src: string
  src_port: number
  dst: string
  dst_port: number
  packets: number
  bytes: number
  bytes_src_to_dst: number
  bytes_dst_to_src: number
  start_time_epoch: number
  end_time_epoch: number
  duration_seconds: number
  retransmissions: number
  retransmission_pct: number
  zero_window_events: number
  mss_client: number | null
  mss_server: number | null
  handshake_rtt_ms: number | null
  // Wireshark TCP-analysis counters (absent in results from older backends)
  dup_acks?: number
  out_of_order?: number
  lost_segments?: number
  window_full?: number
  resets_midstream?: number
  rtt_avg_ms?: number | null
  rtt_max_ms?: number | null
}

export interface UdpConversation {
  stream_id: number
  src: string
  src_port: number
  dst: string
  dst_port: number
  packets: number
  bytes: number
  bytes_src_to_dst: number
  bytes_dst_to_src: number
  start_time_epoch: number
  end_time_epoch: number
  duration_seconds: number
}

export interface TopTalker {
  address: string
  packets: number
  bytes_sent: number
  bytes_received: number
  bytes_total: number
}

export interface Conversations {
  tcp: TcpConversation[]
  udp: UdpConversation[]
  top_talkers: TopTalker[]
}

export interface Tunnel {
  type: string
  peer_a: string
  peer_b: string
  packets: number
  packets_a_to_b: number
  packets_b_to_a: number
  bytes: number
}

export interface PacketRow {
  number: number
  time: number
  src: string
  dst: string
  protocol: string
  length: number
  info: string
  stream: number | null
  // Optional per-packet detail used by the display filter (absent in older results)
  sport?: number | null
  dport?: number | null
  ttl?: number | null
  tcp_flags?: string[]
  seq?: number | null
  ack?: number | null
  win?: number | null
  payload?: number | null
  rtt_ms?: number | null
  analysis?: string[]
  expert?: ExpertSeverity | null
  expert_message?: string | null
}

export type ExpertSeverity = 'error' | 'warning' | 'note' | 'chat'

export interface ExpertEntry {
  severity: ExpertSeverity
  group: string
  summary: string
  count: number
  first_packet: number
}

export interface ResolvedName {
  address: string
  name: string
}

export interface PacketListData {
  rows: PacketRow[]
  total: number
  truncated: boolean
}

export interface HttpRequestRow {
  time: number
  client: string
  server: string
  method: string
  host: string
  uri: string
  status: number | null
}

export interface DnsQueryRow {
  name: string
  client: string
  server: string
  status: 'ok' | 'slow' | 'unanswered' | 'servfail' | 'nxdomain'
  latency_ms: number | null
}

export interface DhcpLeaseRow {
  client_mac: string
  hostname: string | null
  ip: string | null
  server: string | null
  status: 'bound' | 'nak' | 'no_offer' | 'offered' | 'declined' | 'released'
  latency_ms: number | null
}

export interface ServiceResponseTime {
  protocol: string
  samples: number
  min_ms: number
  avg_ms: number
  max_ms: number
}

export interface TlsSession {
  stream_id: number
  client: string
  server: string
  version: string | null
  cipher: string | null
  sni: string | null
  alert: string | null
}

export interface Issue {
  id: string
  type: string
  severity: Severity
  title: string
  detail: string
  title_en?: string | null
  detail_en?: string | null
  conversation: string | null
  evidence: Record<string, unknown>
}

/** Handle of the investigation session the backend keeps for this analysis. */
export interface SessionInfo {
  id: string
  expires_at: number // epoch seconds
  ttl_minutes: number
  content_allowed: boolean
}

export interface SessionStatus extends SessionInfo {
  usage: Record<string, number>
  messages: number
}

export interface Meta {
  engine_version: string
  tshark_version: string
  analysis_duration_ms: number
  truncated_sections: string[]
}

export interface QualityNote {
  code: string
  severity: 'info' | 'warning'
  title: string
  detail: string
  title_en: string
  detail_en: string
}

/** Limits of the capture itself, assessed before the findings. */
export interface CaptureQuality {
  verdict: 'good' | 'fair' | 'poor'
  duplicate_frames: number
  duplicate_pct: number
  truncated_frames: number
  tcp_conversations_checked: number
  one_way_conversations: number
  midstream_conversations: number
  skipped_packets: number
  notes: QualityNote[]
}

export interface AnalysisResult {
  file: FileInfo
  summary: Summary
  protocols: ProtocolStat[]
  time_series: TimeSeriesPoint[]
  conversations: Conversations
  tunnels: Tunnel[]
  issues: Issue[]
  packet_list: PacketListData
  dns_queries: DnsQueryRow[]
  dhcp_leases: DhcpLeaseRow[]
  http_requests: HttpRequestRow[]
  service_response_times: ServiceResponseTime[]
  tls_sessions: TlsSession[]
  expert_info?: ExpertEntry[]
  resolved_names?: ResolvedName[]
  // Absent in results produced before 1.4.0 (e.g. an older demo.json).
  capture_quality?: CaptureQuality
  meta: Meta
  // null when sessions are disabled or the analysis ran in another process
  session?: SessionInfo | null
}

export const API_BASE: string = (import.meta.env.VITE_API_URL as string | undefined) ?? ''

async function authHeaders(): Promise<Record<string, string>> {
  if (supabaseClient) {
    const { data, error } = await supabaseClient.auth.getSession()
    if (error) throw new Error(error.message)
    return data.session
      ? { Authorization: `Bearer ${data.session.access_token}` }
      : {}
  }
  const token = sessionStorage.getItem('pcap.apiToken')
  return token ? { Authorization: `Bearer ${token}` } : {}
}

async function parseOrThrow<T>(response: Response): Promise<T> {
  if (!response.ok) {
    let detail = `Error ${response.status}`
    try {
      const body = (await response.json()) as { detail?: string }
      if (body.detail) detail = body.detail
    } catch {
      /* non-JSON error body */
    }
    throw new Error(detail)
  }
  return (await response.json()) as T
}

export async function analyzePcap(file: File): Promise<AnalysisResult> {
  const form = new FormData()
  form.append('file', file)
  const response = await fetch(`${API_BASE}/analyze`, {
    method: 'POST',
    headers: await authHeaders(),
    body: form,
  })
  return parseOrThrow<AnalysisResult>(response)
}

interface JobStatus {
  job_id: string
  status: 'queued' | 'running' | 'done' | 'error'
  result?: AnalysisResult
  error?: string
}

/** Large captures: queue the analysis and poll until it finishes. */
export async function analyzePcapAsync(file: File): Promise<AnalysisResult> {
  const form = new FormData()
  form.append('file', file)
  const submitted = await fetch(`${API_BASE}/analyze/async`, {
    method: 'POST',
    headers: await authHeaders(),
    body: form,
  })
  const { job_id } = await parseOrThrow<{ job_id: string }>(submitted)

  const deadline = Date.now() + 30 * 60 * 1000
  while (Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 1500))
    const response = await fetch(`${API_BASE}/jobs/${job_id}`, { headers: await authHeaders() })
    const job = await parseOrThrow<JobStatus>(response)
    if (job.status === 'done' && job.result) return job.result
    if (job.status === 'error') throw new Error(job.error ?? 'El análisis falló.')
  }
  throw new Error('El análisis tardó demasiado; consulta el estado de la captura o inténtalo de nuevo.')
}

/** Threshold above which the async queue is used instead of /analyze. */
export const ASYNC_THRESHOLD_BYTES = 20 * 1024 * 1024

export async function exportReport(
  analysis: AnalysisResult,
  diagnosis: string | null,
): Promise<void> {
  const response = await fetch(`${API_BASE}/report`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...await authHeaders() },
    body: JSON.stringify({ analysis, diagnosis }),
  })
  if (!response.ok) {
    throw new Error(`No se pudo generar el informe (${response.status}).`)
  }
  const blob = await response.blob()
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = `informe-${analysis.file.name.replace(/[^A-Za-z0-9._-]/g, '_')}.pdf`
  document.body.appendChild(link)
  link.click()
  link.remove()
  URL.revokeObjectURL(url)
}



// ---- investigation sessions -------------------------------------------------
export const INVESTIGATE_SENTINEL = '__investigate__'

export async function getSession(id: string): Promise<SessionStatus> {
  const response = await fetch(`${API_BASE}/sessions/${encodeURIComponent(id)}`, {
    headers: await authHeaders(),
  })
  return parseOrThrow<SessionStatus>(response)
}

export async function patchSession(id: string, contentAllowed: boolean): Promise<SessionStatus> {
  const response = await fetch(`${API_BASE}/sessions/${encodeURIComponent(id)}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json', ...await authHeaders() },
    body: JSON.stringify({ content_allowed: contentAllowed }),
  })
  return parseOrThrow<SessionStatus>(response)
}

export async function deleteSession(id: string): Promise<void> {
  const response = await fetch(`${API_BASE}/sessions/${encodeURIComponent(id)}`, {
    method: 'DELETE',
    headers: await authHeaders(),
  })
  if (!response.ok && response.status !== 404) {
    throw new Error(`No se pudo borrar la sesión (${response.status}).`)
  }
}

export interface ChatHandlers {
  onToolStart(d: { name: string; label: string }): void
  onToolEnd(d: { name: string; ms: number; is_error: boolean; truncated: boolean }): void
  onText(delta: string): void
  onUsage(d: Record<string, number>): void
  onDone(d: { stop_reason: string; limited: boolean; demo?: boolean }): void
  onError(d: { code: string; message: string }): void
}

/** A non-2xx answer before the stream started (404 session, 409 busy, 429 quota, 503 no AI). */
export class ChatHttpError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

/**
 * Ask the investigation agent and stream its events. Resolves when the stream
 * ends; rejects with ChatHttpError before the stream, or with the fetch error
 * (AbortError included) when the connection drops.
 */
export async function chatStream(
  sessionId: string,
  message: string,
  lang: 'es' | 'en',
  handlers: ChatHandlers,
  signal?: AbortSignal,
): Promise<void> {
  const response = await fetch(`${API_BASE}/sessions/${encodeURIComponent(sessionId)}/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'text/event-stream', ...await authHeaders() },
    body: JSON.stringify({ message, lang }),
    signal,
  })
  if (!response.ok) {
    let detail = `Error ${response.status}`
    try {
      const body = (await response.json()) as { detail?: string }
      if (body.detail) detail = body.detail
    } catch {
      /* non-JSON error body */
    }
    throw new ChatHttpError(response.status, detail)
  }
  if (!response.body) throw new ChatHttpError(response.status, 'Respuesta sin cuerpo.')
  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  const parser = new SseParser()
  const dispatch = (event: string, data: unknown) => {
    const d = data as Record<string, unknown>
    switch (event) {
      case 'tool_start':
        handlers.onToolStart(d as { name: string; label: string })
        break
      case 'tool_end':
        handlers.onToolEnd(d as { name: string; ms: number; is_error: boolean; truncated: boolean })
        break
      case 'text':
        handlers.onText(String(d.delta ?? ''))
        break
      case 'usage':
        handlers.onUsage(d as Record<string, number>)
        break
      case 'done':
        handlers.onDone(d as { stop_reason: string; limited: boolean; demo?: boolean })
        break
      case 'error':
        handlers.onError(d as { code: string; message: string })
        break
      default:
        break
    }
  }
  for (;;) {
    const { value, done } = await reader.read()
    if (done) break
    for (const ev of parser.push(decoder.decode(value, { stream: true }))) dispatch(ev.event, ev.data)
  }
  for (const ev of parser.push(decoder.decode())) dispatch(ev.event, ev.data)
  for (const ev of parser.flush()) dispatch(ev.event, ev.data)
}
