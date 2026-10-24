import assert from 'node:assert/strict'
import { test } from 'node:test'
import type { PacketRow } from './api.ts'
import { csvCell, displayAddress, formatPacketTime, nameMap, packetsToCsv, rowColor } from './packetView.ts'

const row = (partial: Partial<PacketRow> = {}): PacketRow => ({
  number: 1, time: 1.5, src: '10.0.0.1', dst: '10.0.0.2', protocol: 'TCP', length: 60, info: 'x', stream: 0, ...partial,
})

test('colouring rules, first match wins', () => {
  assert.equal(rowColor(row({ analysis: ['retransmission'] })), 'bad')
  assert.equal(rowColor(row({ analysis: ['keep_alive'] })), null)
  assert.equal(rowColor(row({ tcp_flags: ['RST', 'ACK'] })), 'rst')
  assert.equal(rowColor(row({ tcp_flags: ['SYN'] })), 'synfin')
  assert.equal(rowColor(row({ protocol: 'ICMP', stream: null })), 'icmp')
  assert.equal(rowColor(row({ protocol: 'DNS', stream: null })), 'dns')
  assert.equal(rowColor(row({ protocol: 'TLSv1.3' })), 'tls')
  assert.equal(rowColor(row({ expert: 'error' })), 'bad')
  assert.equal(rowColor(row({ expert: 'note' })), null)
  assert.equal(rowColor(row({ analysis: ['retransmission'], tcp_flags: ['RST'] })), 'bad')
})

test('time formats', () => {
  const a = row({ time: 1.5 })
  const b = row({ number: 2, time: 1.75 })
  assert.equal(formatPacketTime(a, 'relative', null, null), '1.500000')
  assert.equal(formatPacketTime(b, 'delta', a, null), '0.250000')
  assert.equal(formatPacketTime(a, 'delta', null, null), '0.000000')
  // 2026-01-01T00:00:00Z + 1.5 s, shown in UTC
  assert.equal(formatPacketTime(a, 'absolute', null, 1767225600), '00:00:01.500')
  assert.equal(formatPacketTime(a, 'absolute', null, null), '1.500000')
})

test('name resolution falls back to the address', () => {
  const names = nameMap([{ address: '10.0.0.2', name: 'intranet.example.com' }])
  assert.equal(displayAddress('10.0.0.2', names), 'intranet.example.com')
  assert.equal(displayAddress('10.0.0.9', names), '10.0.0.9')
  assert.equal(displayAddress('10.0.0.2', null), '10.0.0.2')
})

test('CSV cells are quoted and formula-injection safe', () => {
  assert.equal(csvCell('plain'), 'plain')
  assert.equal(csvCell('a,b'), '"a,b"')
  assert.equal(csvCell('say "hi"'), '"say ""hi"""')
  assert.equal(csvCell('=HYPERLINK("http://evil")'), '"\'=HYPERLINK(""http://evil"")"')
  assert.equal(csvCell('+1'), "'+1")
  assert.equal(csvCell('@SUM(A1)'), "'@SUM(A1)")
  assert.equal(csvCell(-5), '-5') // real negative numbers stay numbers
  assert.equal(csvCell(null), '')
})

test('CSV export has a header and one line per row', () => {
  const csv = packetsToCsv([row({ info: '=cmd|calc' }), row({ number: 2, info: 'a,b' })])
  const lines = csv.trimEnd().split('\r\n')
  assert.equal(lines.length, 3)
  assert.ok(lines[0].startsWith('No.,Time,Source'))
  assert.ok(lines[1].includes("'=cmd|calc"))
  assert.ok(lines[2].includes('"a,b"'))
})
