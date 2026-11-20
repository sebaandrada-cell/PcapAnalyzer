import type { Tunnel } from './api.ts'
import { formatBytes, formatDuration } from './format.ts'

type Translate = (key: string, params?: Record<string, string | number>) => string

// Gaps shorter than this are normal pacing, not worth showing.
const IDLE_MIN_S = 5

/** Short facts shown next to a tunnel: bytes each way, duration, longest silence, handshakes. */
export function tunnelDetails(tunnel: Tunnel, t: Translate): string[] {
  const parts = [
    `→ ${formatBytes(tunnel.bytes_a_to_b ?? 0)}`,
    `← ${formatBytes(tunnel.bytes_b_to_a ?? 0)}`,
    formatDuration(tunnel.duration_s ?? 0),
  ]
  if ((tunnel.max_idle_s ?? 0) >= IDLE_MIN_S) {
    parts.push(t('talkers.tunnelIdle', { time: formatDuration(tunnel.max_idle_s ?? 0) }))
  }
  if ((tunnel.handshakes ?? 0) > 0) {
    parts.push(t('talkers.tunnelHandshakes', { count: tunnel.handshakes ?? 0 }))
  }
  return parts
}
