import assert from 'node:assert/strict'
import { test } from 'node:test'
import type { Issue } from './api.ts'
import { compileFilter } from './displayFilter.ts'
import { issueFilter, quoteString } from './issueFilter.ts'

function issue(type: string, evidence: Record<string, unknown>): Issue {
  return { id: type, type, severity: 'warning', title: '', detail: '', conversation: null, evidence }
}

test('TCP issues map to their stream', () => {
  assert.equal(issueFilter(issue('tcp_syn_rst', { stream_id: 3 })), 'tcp.stream eq 3')
  assert.equal(issueFilter(issue('tls_handshake_failure', { tcp_stream: 7 })), 'tcp.stream eq 7')
  assert.equal(issueFilter(issue('tcp_resets', { stream_ids: [1, 4, 9] })), 'tcp.stream in {1, 4, 9}')
})

test('ICMP and DNS issues map to a filter on the reporter or the name', () => {
  assert.equal(
    issueFilter(issue('icmp_unreachable', { reporter: '10.1.0.254', icmp_type: 3, code: 1 })),
    'ip.src == 10.1.0.254 && icmp && _ws.col.info matches "unreachable"',
  )
  assert.match(issueFilter(issue('icmp_ttl_exceeded', { reporter: 'fe80::1', icmp_type: 3 }))!, /^ipv6\.src == fe80::1 && icmpv6/)
  assert.equal(
    issueFilter(issue('dns_unanswered', { query_name: 'a"b.example', server: '8.8.8.8' })),
    'dns && _ws.col.info contains "a\\"b.example"',
  )
  assert.equal(issueFilter(issue('dns_servfail', { server: '8.8.8.8' })), 'dns && ip.addr == 8.8.8.8')
})

test('issues without identifying evidence give null', () => {
  assert.equal(issueFilter(issue('mss_low', {})), null)
})

test('every generated filter compiles with the display-filter engine', () => {
  const samples = [
    issue('tcp_syn_rst', { stream_id: 3 }),
    issue('tcp_resets', { stream_ids: [1, 4] }),
    issue('icmp_unreachable', { reporter: '10.1.0.254', icmp_type: 3 }),
    issue('icmp_ttl_exceeded', { reporter: '2001:db8::1', icmp_type: 3 }),
    issue('dns_unanswered', { query_name: 'x.example', server: '1.1.1.1' }),
    issue('dns_servfail', { server: '2001:db8::53' }),
    issue('ip_duplicate', { ip: '10.0.0.9' }),
    issue('arp_storm', {}),
    issue('ip_fragmentation_high', {}),
    issue('esp_one_way', {}),
    issue('ike_no_response', {}),
  ]
  for (const sample of samples) {
    const filter = issueFilter(sample)
    assert.ok(filter, sample.type)
    const compiled = compileFilter(filter)
    assert.ok(compiled.ok, `${sample.type}: ${filter}`)
  }
})

test('quoteString escapes quotes and backslashes', () => {
  assert.equal(quoteString('a\\b"c'), '"a\\\\b\\"c"')
})

test('HTTP, DHCP and legacy TLS issues map to filters the local subset can run', () => {
  assert.equal(issueFilter(issue('http_server_errors', { server: '10.0.0.2' })), 'http && ip.addr == 10.0.0.2')
  assert.equal(issueFilter(issue('http_slow', { server: '2001:db8::2' })), 'http && ipv6.addr == 2001:db8::2')
  assert.equal(issueFilter(issue('dhcp_no_response', { clients: ['aa:bb'] })), 'dhcp')
  assert.equal(
    issueFilter(issue('tls_legacy_version', { server: '10.0.0.2', stream_ids: [4, 9] })),
    'tcp.stream in {4, 9}', // tshark 4.x rejects space-separated sets
  )
  for (const filter of ['http && ip.addr == 10.0.0.2', 'dhcp', 'tcp.stream in {4, 9}']) {
    assert.ok(compileFilter(filter, new Set(['http', 'dhcp'])).ok, filter)
  }
})

test('an ARP storm shows the ARP requests', () => {
  assert.equal(issueFilter(issue('arp_storm', { requests: 150 })), 'arp && _ws.col.info contains "Who has"')
})

test('tunnel issues filter on the tunnel protocol and its peers', () => {
  assert.equal(issueFilter(issue('tunnel_one_way', { tunnel_type: 'gre', sender: '10.0.0.1', silent_peer: '10.0.0.2' })),
    'gre && ip.addr == 10.0.0.1 && ip.addr == 10.0.0.2')
  assert.equal(issueFilter(issue('tunnel_handshake_no_response', { tunnel_type: 'wireguard', initiator: '10.0.0.1', responder: '10.0.0.2' })),
    'wg && ip.addr == 10.0.0.1 && ip.addr == 10.0.0.2')
  assert.equal(issueFilter(issue('tunnel_renegotiation', { tunnel_type: 'ike', peer_a: '10.0.0.1', peer_b: '10.0.0.2' })),
    'isakmp && ip.addr == 10.0.0.1 && ip.addr == 10.0.0.2')
  assert.equal(issueFilter(issue('tunnel_renegotiation', { tunnel_type: 'unknown' })), null)
  for (const type of ['tunnel_one_way', 'tunnel_handshake_no_response']) {
    const filter = issueFilter(issue(type, { tunnel_type: 'openvpn', sender: '10.0.0.1', silent_peer: '10.0.0.2', initiator: '10.0.0.1', responder: '10.0.0.2' }))
    assert.ok(filter && compileFilter(filter).ok, `${type}: ${filter}`)
  }
})
