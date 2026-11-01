import assert from 'node:assert/strict'
import { test } from 'node:test'
import { filterApplicability, parseBlocks, parseInline } from './evidence.ts'

test('parses evidence marks and keeps malformed ones literal', () => {
  assert.deepEqual(parseInline('RST a los 5 ms [[pkt: 11]] y [[pkt: 10-11]] [[filter: tcp.stream eq 1]].'), [
    { kind: 'text', text: 'RST a los 5 ms ' },
    { kind: 'pkt', from: 11, to: 11 },
    { kind: 'text', text: ' y ' },
    { kind: 'pkt', from: 10, to: 11 },
    { kind: 'text', text: ' ' },
    { kind: 'filter', filter: 'tcp.stream eq 1' },
    { kind: 'text', text: '.' },
  ])
  assert.deepEqual(parseInline('[[pkt: abc]] [[filter: ]] [[pkt: 3'), [
    { kind: 'text', text: '[[pkt: abc]] [[filter: ]] [[pkt: 3' },
  ])
  assert.deepEqual(parseInline('ver **esto** y `tcp.port == 80`'), [
    { kind: 'text', text: 'ver ' },
    { kind: 'bold', text: 'esto' },
    { kind: 'text', text: ' y ' },
    { kind: 'code', text: 'tcp.port == 80' },
  ])
})

test('html stays text', () => {
  assert.deepEqual(parseInline('<img src=x onerror=alert(1)>'), [
    { kind: 'text', text: '<img src=x onerror=alert(1)>' },
  ])
})

test('blocks: headings, bullets, paragraphs, fences', () => {
  const blocks = parseBlocks('## Veredicto\nTodo bien.\n\n- uno [[pkt: 1]]\n- dos\n\n```\ntcp.stream eq 1\n```')
  assert.deepEqual(blocks.map((b) => b.kind), ['heading', 'paragraph', 'bullet', 'bullet', 'code'])
  assert.equal((blocks[0] as { level: number }).level, 2)
  assert.deepEqual((blocks[2] as { inlines: unknown[] }).inlines[1], { kind: 'pkt', from: 1, to: 1 })
  assert.equal((blocks[4] as { text: string }).text, 'tcp.stream eq 1')
})

test('filter applicability uses the local engine', () => {
  assert.equal(filterApplicability('tcp.stream eq 1', new Set()), 'local')
  assert.equal(filterApplicability('tls.handshake.type == 1', new Set()), 'copy-only')
  assert.equal(filterApplicability('tcp.port ==== 1', new Set()), 'copy-only')
})
