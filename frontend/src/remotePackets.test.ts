import assert from 'node:assert/strict'
import { test } from 'node:test'
import { remoteErrorKey, toServerFilter } from './remotePackets.ts'

test('a display filter is sent as typed, even when the local subset cannot parse it', () => {
  assert.equal(toServerFilter('  tcp.flags.reset == 1 ', 'filter'), 'tcp.flags.reset == 1')
  assert.equal(toServerFilter('http.request and tcp.len > 0', 'error'), 'http.request and tcp.len > 0')
  assert.equal(toServerFilter('   ', 'none'), '')
})

test('plain text becomes a column search, with quotes and backslashes escaped', () => {
  assert.equal(
    toServerFilter('Client Hello', 'text'),
    '_ws.col.info contains "Client Hello" || _ws.col.protocol contains "Client Hello"',
  )
  assert.equal(
    toServerFilter('say "hi" \\ bye', 'text'),
    '_ws.col.info contains "say \\"hi\\" \\\\ bye" || _ws.col.protocol contains "say \\"hi\\" \\\\ bye"',
  )
})

test('a bare address searches both directions', () => {
  assert.equal(toServerFilter('10.0.0.1', 'text'), 'ip.addr == 10.0.0.1')
  assert.equal(toServerFilter('fe80::1', 'text'), 'ipv6.addr == fe80::1')
  assert.equal(toServerFilter('10.0.0', 'text'), '_ws.col.info contains "10.0.0" || _ws.col.protocol contains "10.0.0"')
})

test('server errors map to a message key', () => {
  assert.equal(remoteErrorKey(404), 'packets.remoteGone')
  assert.equal(remoteErrorKey(422), 'packets.remoteInvalid')
  assert.equal(remoteErrorKey(429), 'packets.remoteBusy')
  assert.equal(remoteErrorKey(504), 'packets.remoteTimeout')
  assert.equal(remoteErrorKey(500), 'packets.remoteFailed')
})
