import assert from 'node:assert/strict'
import { test } from 'node:test'
import { initialState, reduce, type PanelState } from './investigationState.ts'

const usage = (i: number, o: number) => ({ input_tokens: i, output_tokens: o, cache_read_tokens: 0, cache_write_tokens: 0 })

function run(state: PanelState, actions: Parameters<typeof reduce>[1][]): PanelState {
  return actions.reduce(reduce, state)
}

test('automatic investigation lifecycle', () => {
  const s = run(initialState('sid', 1000, false), [
    { type: 'start', question: null },
    { type: 'tool_start', name: 'capture_overview', label: 'capture_overview' },
    { type: 'tool_end', name: 'capture_overview', ms: 12, is_error: false, truncated: false },
    { type: 'tool_start', name: 'filter_packets', label: 'filter_packets: tcp' },
    { type: 'text', delta: '## Veredicto\n' },
    { type: 'text', delta: 'Todo bien [[pkt: 1]]' },
    { type: 'tool_end', name: 'filter_packets', ms: 40, is_error: true, truncated: false },
    { type: 'usage', usage: usage(100, 50) },
    { type: 'done', limited: false },
  ])
  assert.equal(s.turns.length, 1)
  const turn = s.turns[0]
  assert.equal(turn.question, null)
  assert.equal(turn.text, '## Veredicto\nTodo bien [[pkt: 1]]')
  assert.deepEqual(turn.steps.map((st) => [st.name, st.done, st.isError, st.ms]), [
    ['capture_overview', true, false, 12],
    ['filter_packets', true, true, 40],
  ])
  assert.equal(turn.streaming, false)
  assert.equal(s.investigated, true)
  assert.deepEqual(s.totalUsage, usage(100, 50))
})

test('session_expired keeps the text but blocks input', () => {
  const s = run(initialState('sid', 1000, false), [
    { type: 'start', question: '¿por qué?' },
    { type: 'text', delta: 'parte' },
    { type: 'error', code: 'session_expired', message: 'ya no está' },
  ])
  assert.equal(s.expired, true)
  assert.equal(s.blockedReason, 'expired')
  assert.equal(s.turns[0].text, 'parte')
  assert.deepEqual(s.turns[0].error, { code: 'session_expired', message: 'ya no está' })
  assert.equal(s.turns[0].streaming, false)
})

test('409 on the automatic turn means it already ran', () => {
  const s = run(initialState('sid', 1000, false), [
    { type: 'start', question: null },
    { type: 'http_error', status: 409, message: 'ya se hizo' },
  ])
  assert.equal(s.turns.length, 0)
  assert.equal(s.investigated, true)
  assert.equal(s.notice, 'already_investigated')
})

test('http errors on a user turn are shown on that turn', () => {
  const s = run(initialState('sid', 1000, false), [
    { type: 'start', question: 'hola' },
    { type: 'http_error', status: 429, message: 'cupo' },
  ])
  assert.deepEqual(s.turns[0].error, { code: 'http_429', message: 'cupo' })
  assert.equal(s.turns[0].streaming, false)
})

test('interrupted turn keeps partial text, tokens cap blocks input, usage accumulates', () => {
  let s = run(initialState('sid', 1000, false), [
    { type: 'start', question: 'a' },
    { type: 'text', delta: 'x' },
    { type: 'interrupted' },
  ])
  assert.equal(s.turns[0].interrupted, true)
  assert.equal(s.turns[0].text, 'x')
  s = run(s, [
    { type: 'start', question: 'b' },
    { type: 'usage', usage: usage(10, 5) },
    { type: 'done', limited: true },
    { type: 'start', question: 'c' },
    { type: 'usage', usage: usage(1, 1) },
    { type: 'error', code: 'session_tokens', message: 'límite' },
  ])
  assert.equal(s.turns[1].limited, true)
  assert.equal(s.blockedReason, 'tokens')
  assert.deepEqual(s.totalUsage, usage(11, 6))
  const refreshed = reduce(s, { type: 'session', info: { expires_at: 2000, content_allowed: true } })
  assert.equal(refreshed.expiresAt, 2000)
  assert.equal(refreshed.contentAllowed, true)
  assert.equal(reduce(refreshed, { type: 'expired' }).blockedReason, 'expired')
  assert.deepEqual(reduce(refreshed, { type: 'reset' }), initialState(null, null, false))
})

test('stream_end without done marks the turn interrupted (resend available)', () => {
  const s = run(initialState('sid', 1000, false), [
    { type: 'start', question: 'a' },
    { type: 'text', delta: 'parcial' },
    { type: 'stream_end' },
  ])
  assert.equal(s.turns[0].streaming, false)
  assert.equal(s.turns[0].interrupted, true)
  const clean = run(initialState('sid', 1000, false), [
    { type: 'start', question: 'b' },
    { type: 'done', limited: false },
    { type: 'stream_end' },
  ])
  assert.equal(clean.turns[0].interrupted, false)
})

test('a session refresh with a future expiry clears a premature expiry block', () => {
  const future = Date.now() / 1000 + 3600
  const s = run(initialState('sid', 1000, false), [
    { type: 'start', question: 'a' },
    { type: 'expired' },
    { type: 'done', limited: false },
    { type: 'session', info: { expires_at: future, content_allowed: false } },
  ])
  assert.equal(s.expired, false)
  assert.equal(s.blockedReason, null)
  const tokens = run(s, [{ type: 'start', question: 'b' }, { type: 'error', code: 'session_tokens', message: 'x' },
                        { type: 'session', info: { expires_at: future, content_allowed: false } }])
  assert.equal(tokens.blockedReason, 'tokens') // only the expiry block is cleared
})
