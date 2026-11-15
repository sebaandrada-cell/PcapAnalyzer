// Run with: node --test src/displayFilter.test.ts   (Node >= 22.6 strips the types)
import assert from 'node:assert/strict'
import { test } from 'node:test'
import type { PacketRow } from './api.ts'
import { compileFilter, conversationFilter, filtersForRow, looksLikeFilter } from './displayFilter.ts'

const base = { time: 0, length: 60, info: '', stream: null } as const

function row(partial: Partial<PacketRow> & Pick<PacketRow, 'number' | 'src' | 'dst' | 'protocol'>): PacketRow {
  return { ...base, ...partial }
}

const syn = row({
  number: 1, src: '10.0.0.5', dst: '192.168.1.10', protocol: 'TCP', stream: 0,
  sport: 51000, dport: 443, tcp_flags: ['SYN'], seq: 0, ack: 0, win: 64240, payload: 0,
  info: '51000 → 443 [SYN] Seq=0',
})
const rst = row({
  number: 2, src: '192.168.1.10', dst: '10.0.0.5', protocol: 'TCP', stream: 0,
  sport: 443, dport: 51000, tcp_flags: ['RST', 'ACK'], seq: 1, ack: 1, win: 0, payload: 0,
  info: '443 → 51000 [RST, ACK]',
})
const retrans = row({
  number: 3, src: '10.0.0.5', dst: '172.16.0.9', protocol: 'TCP', stream: 1,
  sport: 40000, dport: 80, tcp_flags: ['ACK', 'PSH'], payload: 100, analysis: ['retransmission'],
  rtt_ms: 250, expert: 'note', expert_message: 'This frame is a (suspected) retransmission',
})
const dns = row({
  number: 4, src: '10.0.0.5', dst: '8.8.8.8', protocol: 'DNS', sport: 53211, dport: 53,
  info: 'Standard query 0x1 A example.com',
})
const v6 = row({ number: 5, src: 'fe80::1', dst: 'ff02::2', protocol: 'ICMPv6', info: 'Router Solicitation' })
const tls = row({ number: 6, src: '10.0.0.5', dst: '1.1.1.1', protocol: 'TLSv1.3', stream: 2, sport: 5000, dport: 443 })
const rows = [syn, rst, retrans, dns, v6, tls]

function match(filter: string): number[] {
  const compiled = compileFilter(filter)
  assert.ok(compiled.ok, `"${filter}" should compile: ${JSON.stringify(!compiled.ok && compiled.error)}`)
  return rows.filter(compiled.test).map((r) => r.number)
}

function errorOf(filter: string): string {
  const compiled = compileFilter(filter)
  assert.ok(!compiled.ok, `"${filter}" should not compile`)
  return compiled.error.code
}

test('frames duplicated by the capture do not count as TCP analysis problems', () => {
  const compiled = compileFilter('tcp.analysis.flags')
  assert.ok(compiled.ok)
  assert.equal(compiled.test({ ...syn, analysis: ['duplicate_frame'] }), false)
  assert.equal(compiled.test({ ...syn, analysis: ['retransmission'] }), true)
})

test('empty filter matches everything', () => {
  const compiled = compileFilter('   ')
  assert.ok(compiled.ok && compiled.empty)
  assert.deepEqual(rows.filter(compiled.test).length, rows.length)
})

test('bare protocol names', () => {
  assert.deepEqual(match('tcp'), [1, 2, 3, 6])
  assert.deepEqual(match('dns'), [4])
  assert.deepEqual(match('udp'), [4])
  assert.deepEqual(match('icmpv6'), [5])
  assert.deepEqual(match('tls'), [6])
  assert.deepEqual(match('ip'), [1, 2, 3, 4, 6])
  assert.deepEqual(match('ipv6'), [5])
})

test('address fields, CIDR and families', () => {
  assert.deepEqual(match('ip.src == 10.0.0.5'), [1, 3, 4, 6])
  assert.deepEqual(match('ip.addr == 192.168.1.10'), [1, 2])
  assert.deepEqual(match('ip.addr == 10.0.0.0/8'), [1, 2, 3, 4, 6])
  assert.deepEqual(match('ip.dst == 192.168.0.0/16'), [1])
  assert.deepEqual(match('ip.addr != 10.0.0.5'), [])
  assert.deepEqual(match('ipv6.addr == fe80::/10'), [5])
  assert.deepEqual(match('ipv6.dst == ff02::2'), [5])
})

test('ports, numbers, ranges and sets', () => {
  assert.deepEqual(match('tcp.port == 443'), [1, 2, 6])
  assert.deepEqual(match('tcp.dstport == 443'), [1, 6])
  assert.deepEqual(match('udp.port == 53'), [4])
  assert.deepEqual(match('tcp.port in {80 443}'), [1, 2, 3, 6])
  assert.deepEqual(match('tcp.port in {80, 443}'), [1, 2, 3, 6]) // tshark 4.x syntax
  assert.deepEqual(match('tcp.port in {8000..8100}'), [])
  assert.deepEqual(match('tcp.port in {50000..52000}'), [1, 2])
  assert.deepEqual(match('frame.number >= 4'), [4, 5, 6])
  assert.deepEqual(match('frame.number lt 3'), [1, 2])
  assert.deepEqual(match('tcp.len > 0'), [3])
  assert.deepEqual(match('tcp.stream eq 1'), [3])
})

test('hexadecimal literals', () => {
  assert.deepEqual(match('tcp.port == 0x1bb'), [1, 2, 6])
})

test('TCP flags and analysis flags', () => {
  assert.deepEqual(match('tcp.flags.syn == 1'), [1])
  assert.deepEqual(match('tcp.flags.reset'), [2])
  assert.deepEqual(match('tcp.analysis.retransmission'), [3])
  assert.deepEqual(match('tcp.analysis.flags'), [3])
  assert.deepEqual(match('tcp.window_size == 0'), [2])
  assert.deepEqual(match('tcp.analysis.ack_rtt > 0.2'), [3])
})

test('boolean flag == 0 only matches TCP packets where the bit is clear', () => {
  assert.deepEqual(match('tcp.flags.reset == 0'), [1, 3, 6])
})

test('logical operators and precedence', () => {
  assert.deepEqual(match('tcp && !tcp.flags.syn'), [2, 3, 6])
  assert.deepEqual(match('tcp.flags.syn || dns'), [1, 4])
  assert.deepEqual(match('tcp.flags.syn or dns'), [1, 4])
  assert.deepEqual(match('not tcp and frame.number < 5'), [4])
  assert.deepEqual(match('(tcp || dns) && ip.dst == 8.8.8.8'), [4])
  assert.deepEqual(match('dns || tcp.flags.syn && ip.src == 1.2.3.4'), [4])
})

test('string operators', () => {
  assert.deepEqual(match('_ws.col.info contains "SYN"'), [1])
  assert.deepEqual(match('_ws.col.info matches "^standard"'), [4])
  assert.deepEqual(match('_ws.col.protocol == "DNS"'), [4])
  assert.deepEqual(match('_ws.expert.message contains "retransmission"'), [3])
  assert.deepEqual(match('_ws.expert.severity >= 4194304'), [3])
})

test('expert existence', () => {
  assert.deepEqual(match('_ws.expert'), [3])
})

test('"!=" needs the field to exist (Wireshark semantics)', () => {
  assert.deepEqual(match('tcp.dstport != 443'), [2, 3])
})

test('syntax errors carry a code and a position', () => {
  assert.equal(errorOf('ip.addr =='), 'unexpected-end')
  assert.equal(errorOf('(tcp'), 'unclosed-paren')
  assert.equal(errorOf('tcp &&'), 'unexpected-end')
  assert.equal(errorOf('tcp.port == "x"'), 'bad-value')
  assert.equal(errorOf('ip.addr == 300.1.1.1'), 'bad-value')
  assert.equal(errorOf('ip.addr == 10.0.0.0/40'), 'bad-value')
  assert.equal(errorOf('tcp.nonsense == 1'), 'unknown-field')
  assert.equal(errorOf('notaprotocol'), 'unknown-field')
  assert.equal(errorOf('_ws.col.info contains 5'), 'bad-value')
  assert.equal(errorOf('_ws.col.info matches "("'), 'bad-regex')
  assert.equal(errorOf('_ws.col.info > "a"'), 'bad-operator')
  assert.equal(errorOf('tcp.port contains "a"'), 'bad-operator')
  assert.equal(errorOf('"abc'), 'unterminated-string')
  assert.equal(errorOf('tcp.port in {80'), 'unclosed-set')
  assert.equal(errorOf('tcp @'), 'unexpected-char')
  assert.equal(errorOf('tcp tcp'), 'unexpected-token')
  const compiled = compileFilter('tcp.port == "x"')
  assert.ok(!compiled.ok && compiled.error.position === 12)
})

test('protocols seen in the data are accepted as bare words', () => {
  assert.ok(!compileFilter('customproto').ok)
  const compiled = compileFilter('customproto', new Set(['customproto']))
  assert.ok(compiled.ok)
})

test('looksLikeFilter distinguishes filters from plain words', () => {
  assert.equal(looksLikeFilter('10.0.0.5'), false)
  assert.equal(looksLikeFilter('example.com'), false)
  assert.equal(looksLikeFilter('ip.addr == 10.0.0.5'), true)
  assert.equal(looksLikeFilter('tcp && !dns'), true)
  assert.equal(looksLikeFilter('tcp.port in {1 2}'), true)
})

test('filters built from a row are valid and select that row', () => {
  for (const source of [syn, rst, retrans, dns, v6]) {
    for (const [name, filter] of Object.entries(filtersForRow(source))) {
      const compiled = compileFilter(filter)
      assert.ok(compiled.ok, `${name}: ${filter}`)
      assert.ok(compiled.test(source), `${name}: "${filter}" must match its own row`)
    }
  }
  assert.equal(
    conversationFilter(syn, 'tcp'),
    'ip.addr == 10.0.0.5 && ip.addr == 192.168.1.10 && tcp.port == 51000 && tcp.port == 443',
  )
  const conversation = compileFilter(conversationFilter(syn, 'tcp'))
  assert.ok(conversation.ok && conversation.test(syn) && conversation.test(rst) && !conversation.test(retrans))
})
