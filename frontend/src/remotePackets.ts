// Searching the whole capture on the server (POST /sessions/{id}/packets).
// The packet list holds only the first packets; these helpers turn what is in
// the filter box into a real Wireshark display filter and map server errors to
// messages. Pure module: `node --test src/remotePackets.test.ts`.

export type FilterMode = 'none' | 'filter' | 'text' | 'error'

const IPV4 = /^(?:\d{1,3}\.){3}\d{1,3}$/
const IPV6 = /^[0-9a-f]*:[0-9a-f:]*$/i

/** The display filter to send for the text currently in the filter box. */
export function toServerFilter(text: string, mode: FilterMode): string {
  const value = text.trim()
  if (!value || mode === 'none') return ''
  // 'error' = the local subset could not parse it; tshark knows the full language.
  if (mode !== 'text') return value
  if (IPV4.test(value)) return `ip.addr == ${value}`
  if (value.includes(':') && IPV6.test(value)) return `ipv6.addr == ${value}`
  // Case-insensitive like the local text search: a regex with (?i), its
  // metacharacters escaped, then quoted as a display-filter string literal.
  const regex = `(?i)${value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}`
  const quoted = `"${regex.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`
  return `_ws.col.info matches ${quoted} || _ws.col.protocol matches ${quoted}`
}

/** i18n key for a failed whole-capture search. */
export function remoteErrorKey(status: number): string {
  if (status === 404) return 'packets.remoteGone'
  if (status === 422) return 'packets.remoteInvalid'
  if (status === 429) return 'packets.remoteBusy'
  if (status === 504) return 'packets.remoteTimeout'
  return 'packets.remoteFailed'
}
