import { test } from 'node:test'
import assert from 'node:assert/strict'
import { tunnelDetails } from './tunnelView.ts'
import { translate } from './i18n.ts'
import { setFormatLang } from './format.ts'

const tunnel = {
  type: 'wireguard', peer_a: '10.0.0.1', peer_b: '203.0.113.9', packets: 4,
  packets_a_to_b: 2, packets_b_to_a: 2, bytes: 1000, bytes_a_to_b: 400, bytes_b_to_a: 600,
  duration_s: 31, max_idle_s: 30, handshakes: 1,
}

test('tunnel details show direction bytes, duration, idle gap and handshakes', () => {
  setFormatLang('en')
  const t = (key: string, params?: Record<string, string | number>) => translate('en', key, params)
  assert.deepEqual(tunnelDetails(tunnel, t), ['→ 400 B', '← 600 B', '31 s', 'max idle 30 s', '1 handshake(s)'])
})

test('short idle gaps and zero handshakes are left out', () => {
  setFormatLang('es')
  const t = (key: string, params?: Record<string, string | number>) => translate('es', key, params)
  const quiet = { ...tunnel, max_idle_s: 0.5, handshakes: 0 }
  assert.deepEqual(tunnelDetails(quiet, t), ['→ 400 B', '← 600 B', '31 s'])
})
