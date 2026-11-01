// Evidence marks and the minimal markdown the agent writes, parsed into data
// the UI renders as text and buttons. Nothing here produces HTML. Pure module:
// `node --test src/evidence.test.ts`.
import { compileFilter } from './displayFilter.ts'

export type Inline =
  | { kind: 'text'; text: string }
  | { kind: 'bold'; text: string }
  | { kind: 'code'; text: string }
  | { kind: 'pkt'; from: number; to: number }
  | { kind: 'filter'; filter: string }

export type Block =
  | { kind: 'heading'; level: 2 | 3; inlines: Inline[] }
  | { kind: 'bullet'; inlines: Inline[] }
  | { kind: 'paragraph'; inlines: Inline[] }
  | { kind: 'code'; text: string }

const PKT_RE = /^\[\[pkt:\s*(\d+)(?:\s*[-–]\s*(\d+))?\s*\]\]/
const FILTER_RE = /^\[\[filter:\s*([^\]]+?)\s*\]\]/

/** Split a line into text, **bold**, `code` and evidence marks; malformed marks stay text. */
export function parseInline(text: string): Inline[] {
  const out: Inline[] = []
  let buffer = ''
  const flush = () => {
    if (buffer) out.push({ kind: 'text', text: buffer })
    buffer = ''
  }
  let i = 0
  while (i < text.length) {
    const rest = text.slice(i)
    if (rest.startsWith('[[')) {
      const pkt = PKT_RE.exec(rest)
      if (pkt) {
        const from = Number(pkt[1])
        const to = pkt[2] === undefined ? from : Number(pkt[2])
        flush()
        out.push({ kind: 'pkt', from: Math.min(from, to), to: Math.max(from, to) })
        i += pkt[0].length
        continue
      }
      const filter = FILTER_RE.exec(rest)
      if (filter && filter[1].trim()) {
        flush()
        out.push({ kind: 'filter', filter: filter[1].trim() })
        i += filter[0].length
        continue
      }
    }
    if (rest.startsWith('**')) {
      const end = rest.indexOf('**', 2)
      if (end > 2) {
        flush()
        out.push({ kind: 'bold', text: rest.slice(2, end) })
        i += end + 2
        continue
      }
    }
    if (rest.startsWith('`')) {
      const end = rest.indexOf('`', 1)
      if (end > 1) {
        flush()
        out.push({ kind: 'code', text: rest.slice(1, end) })
        i += end + 1
        continue
      }
    }
    buffer += text[i]
    i += 1
  }
  flush()
  return out
}

/** Headings (##/###), bullets (-/*), fenced code and paragraphs. */
export function parseBlocks(markdown: string): Block[] {
  const blocks: Block[] = []
  const lines = markdown.replace(/\r\n/g, '\n').split('\n')
  let paragraph: string[] = []
  const flushParagraph = () => {
    if (paragraph.length) blocks.push({ kind: 'paragraph', inlines: parseInline(paragraph.join(' ')) })
    paragraph = []
  }
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i]
    const trimmed = line.trim()
    if (trimmed.startsWith('```')) {
      flushParagraph()
      const code: string[] = []
      i += 1
      while (i < lines.length && !lines[i].trim().startsWith('```')) {
        code.push(lines[i])
        i += 1
      }
      blocks.push({ kind: 'code', text: code.join('\n') })
      continue
    }
    const heading = /^(#{1,6})\s+(.*)$/.exec(trimmed)
    if (heading) {
      flushParagraph()
      blocks.push({ kind: 'heading', level: heading[1].length <= 2 ? 2 : 3, inlines: parseInline(heading[2]) })
      continue
    }
    const bullet = /^[-*•]\s+(.*)$/.exec(trimmed)
    if (bullet) {
      flushParagraph()
      blocks.push({ kind: 'bullet', inlines: parseInline(bullet[1]) })
      continue
    }
    if (trimmed === '') {
      flushParagraph()
      continue
    }
    paragraph.push(trimmed)
  }
  flushParagraph()
  return blocks
}

/** 'local' when the packet list can apply the filter itself; otherwise it can only be copied to Wireshark. */
export function filterApplicability(filter: string, knownProtocols: ReadonlySet<string>): 'local' | 'copy-only' {
  const compiled = compileFilter(filter, knownProtocols)
  return compiled.ok && !compiled.empty ? 'local' : 'copy-only'
}
