// Turns a detected issue into the Wireshark display filter that shows its packets.
// Pure module (no React): `node --test src/issueFilter.test.ts`.
import type { Issue } from './api.ts'

const num = (value: unknown): number | null => (typeof value === 'number' && Number.isFinite(value) ? value : null)
const str = (value: unknown): string | null => (typeof value === 'string' && value !== '' ? value : null)
const isV6 = (address: string): boolean => address.includes(':')

/** Quote a string literal for a display filter (backslash and double quote escaped). */
export function quoteString(text: string): string {
  return `"${text.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`
}

const addr = (address: string): string => `${isV6(address) ? 'ipv6' : 'ip'}.addr == ${address}`

// Wireshark protocol names of the tunnel types the backend reports.
const TUNNEL_PROTOCOLS: Record<string, string> = {
  esp: 'esp', ike: 'isakmp', wireguard: 'wg', openvpn: 'openvpn', gre: 'gre', l2tp: 'l2tp', teredo: 'teredo',
}

/** Best display filter for an issue, or null when its evidence does not identify packets. */
export function issueFilter(issue: Issue): string | null {
  const ev = issue.evidence
  const stream = num(ev['stream_id']) ?? num(ev['tcp_stream'])
  if (stream !== null) return `tcp.stream eq ${stream}`

  if (Array.isArray(ev['stream_ids'])) {
    const ids = ev['stream_ids'].map(num).filter((id): id is number => id !== null)
    // tshark 4.x requires commas between set members.
    if (ids.length > 0) return `tcp.stream in {${ids.join(', ')}}`
  }

  const reporter = str(ev['reporter'])
  const icmpType = num(ev['icmp_type'])
  if (issue.type === 'icmp_unreachable' && reporter) {
    const family = isV6(reporter) ? 'ipv6' : 'ip'
    return `${family}.src == ${reporter} && ${isV6(reporter) ? 'icmpv6' : 'icmp'} && _ws.col.info matches "unreachable"`
  }
  if (issue.type === 'icmp_ttl_exceeded' && reporter) {
    const family = isV6(reporter) ? 'ipv6' : 'ip'
    return `${family}.src == ${reporter} && ${isV6(reporter) ? 'icmpv6' : 'icmp'} && _ws.col.info matches "time"`
  }
  if (issue.type.startsWith('icmp_') && icmpType !== null && reporter) {
    return `${isV6(reporter) ? 'ipv6' : 'ip'}.src == ${reporter} && ${isV6(reporter) ? 'icmpv6' : 'icmp'}`
  }

  if (issue.type.startsWith('dns_')) {
    const server = str(ev['server'])
    const name = str(ev['query_name'])
    if (name) return `dns && _ws.col.info contains ${quoteString(name)}`
    if (server) return `dns && ${addr(server)}`
  }

  if (issue.type.startsWith('http_')) {
    const server = str(ev['server'])
    return server ? `http && ${addr(server)}` : 'http'
  }
  if (issue.type.startsWith('dhcp_')) return 'dhcp'

  if (issue.type.startsWith('tunnel_')) {
    const proto = TUNNEL_PROTOCOLS[str(ev['tunnel_type']) ?? '']
    if (!proto) return null
    const peers = [ev['sender'] ?? ev['initiator'] ?? ev['peer_a'], ev['silent_peer'] ?? ev['responder'] ?? ev['peer_b']]
      .map(str).filter((p): p is string => Boolean(p))
    return [proto, ...peers.map(addr)].join(' && ')
  }
  if (issue.type === 'arp_storm') return 'arp && _ws.col.info contains "Who has"'

  const ip = str(ev['ip'])
  if (issue.type === 'ip_duplicate' && ip) return `arp && _ws.col.info contains ${quoteString(ip)}`

  if (issue.type.startsWith('ip_fragment')) return 'ip && _ws.col.info matches "fragment"'
  if (issue.type === 'esp_one_way' || issue.type === 'ike_no_response' || issue.type === 'ike_handshake_incomplete') {
    return issue.type === 'esp_one_way' ? 'esp' : 'isakmp'
  }
  return null
}
