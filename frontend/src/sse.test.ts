import assert from 'node:assert/strict'
import { test } from 'node:test'
import { SseParser } from './sse.ts'

test('parses complete frames and keeps the partial tail', () => {
  const p = new SseParser()
  assert.deepEqual(p.push('event: text\ndata: {"delta":"ho'), [])
  assert.deepEqual(
    p.push('la"}\n\nevent: done\ndata: {"stop_reason":"end_turn","limited":false}\n\n'),
    [
      { event: 'text', data: { delta: 'hola' } },
      { event: 'done', data: { stop_reason: 'end_turn', limited: false } },
    ],
  )
})

test('tolerates CRLF, comments and a trailing frame without blank line', () => {
  const p = new SseParser()
  assert.deepEqual(
    p.push(': keepalive\r\nevent: usage\r\ndata: {"input_tokens":1}\r\n\r\nevent: done\ndata: {}'),
    [{ event: 'usage', data: { input_tokens: 1 } }],
  )
  assert.deepEqual(p.flush(), [{ event: 'done', data: {} }])
})

test('a truncated stream yields only the frames that completed', () => {
  const p = new SseParser()
  assert.deepEqual(p.push('event: text\ndata: {"delta":"a"}\n\nevent: text\ndata: {"del'), [
    { event: 'text', data: { delta: 'a' } },
  ])
  assert.deepEqual(p.flush(), []) // unparseable tail is dropped, never thrown
})

test('multi-line data is joined with newlines and events default to "message"', () => {
  const p = new SseParser()
  assert.deepEqual(p.push('data: {"a":\ndata: 1}\n\n'), [{ event: 'message', data: { a: 1 } }])
})
