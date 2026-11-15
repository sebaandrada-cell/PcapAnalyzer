// A subset of Wireshark's display-filter language, evaluated in the browser
// against the rows of the packet list.
//
// The capture file is discarded after analysis, so filters cannot be run by
// tshark: they run over the fields each row carries (addresses, ports, TCP
// flags/seq/ack/window, Wireshark's TCP-analysis flags, expert severity, ...).
// A filter that uses a field the rows do not have is reported as such instead of
// silently matching nothing. Everything else behaves like Wireshark:
//
//   ip.addr == 10.0.0.0/8 && tcp.port in {80 443 8000..8100}
//   tcp.analysis.retransmission || tcp.flags.reset == 1
//   !(dns) and frame.number > 100
//   _ws.col.info contains "SYN" or _ws.col.info matches "^\\[TCP"
//
// Pure module on purpose (no React, no DOM): `node --test src/displayFilter.test.ts`.
import type { PacketRow } from './api.ts'

// ── public types ──────────────────────────────────────────────────────────
export interface FilterError {
  /** Stable id, translated by the UI: `filter.err.<code>`. */
  code: string
  arg?: string
  position: number
}

export type Compiled =
  | { ok: true; empty: boolean; test: (row: PacketRow) => boolean }
  | { ok: false; error: FilterError }

class FilterSyntaxError extends Error {
  code: string
  arg?: string
  position: number
  constructor(code: string, position: number, arg?: string) {
    super(code)
    this.code = code
    this.arg = arg
    this.position = position
  }
}

// ── tokenizer ─────────────────────────────────────────────────────────────
type Token =
  | { t: 'num'; v: number; pos: number }
  | { t: 'str'; v: string; pos: number }
  | { t: 'ip'; v: string; pos: number }
  | { t: 'word'; v: string; pos: number }
  | { t: 'sym'; v: string; pos: number }
  | { t: 'end'; pos: number }

const IPV4_RE = /^\d{1,3}(?:\.\d{1,3}){3}(?:\/\d{1,2})?/
const IPV6_RE = /^[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:\/\d{1,3})?/
const HEX_RE = /^0[xX][0-9A-Fa-f]+/
const NUM_RE = /^\d+(?:\.\d+)?/
const WORD_RE = /^[A-Za-z_][A-Za-z0-9_.]*/
const SYMBOLS = ['&&', '||', '==', '!=', '>=', '<=', '..', '>', '<', '!', '~', '(', ')', '{', '}']

function tokenize(source: string): Token[] {
  const tokens: Token[] = []
  let i = 0
  while (i < source.length) {
    const ch = source[i]
    if (/\s/.test(ch)) {
      i += 1
      continue
    }
    const rest = source.slice(i)
    if (ch === '"') {
      let value = ''
      let j = i + 1
      let closed = false
      while (j < source.length) {
        const c = source[j]
        if (c === '\\' && j + 1 < source.length) {
          value += source[j + 1]
          j += 2
          continue
        }
        if (c === '"') {
          closed = true
          break
        }
        value += c
        j += 1
      }
      if (!closed) throw new FilterSyntaxError('unterminated-string', i)
      tokens.push({ t: 'str', v: value, pos: i })
      i = j + 1
      continue
    }
    // Longest/most specific literal first: IPv6, IPv4, hex, number, word, symbol.
    const ipv6 = IPV6_RE.exec(rest)
    if (ipv6 && ipv6[0].length >= 3) {
      tokens.push({ t: 'ip', v: ipv6[0], pos: i })
      i += ipv6[0].length
      continue
    }
    const ipv4 = IPV4_RE.exec(rest)
    if (ipv4) {
      tokens.push({ t: 'ip', v: ipv4[0], pos: i })
      i += ipv4[0].length
      continue
    }
    const hex = HEX_RE.exec(rest)
    if (hex) {
      tokens.push({ t: 'num', v: parseInt(hex[0], 16), pos: i })
      i += hex[0].length
      continue
    }
    const num = NUM_RE.exec(rest)
    if (num) {
      tokens.push({ t: 'num', v: Number(num[0]), pos: i })
      i += num[0].length
      continue
    }
    const word = WORD_RE.exec(rest)
    if (word) {
      tokens.push({ t: 'word', v: word[0], pos: i })
      i += word[0].length
      continue
    }
    const sym = SYMBOLS.find((s) => rest.startsWith(s))
    if (sym) {
      tokens.push({ t: 'sym', v: sym, pos: i })
      i += sym.length
      continue
    }
    throw new FilterSyntaxError('unexpected-char', i, ch)
  }
  tokens.push({ t: 'end', pos: source.length })
  return tokens
}

// ── IP helpers ────────────────────────────────────────────────────────────
function ipv4ToInt(text: string): number | null {
  const parts = text.split('.')
  if (parts.length !== 4) return null
  let value = 0
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null
    const octet = Number(part)
    if (octet > 255) return null
    value = value * 256 + octet
  }
  return value
}

function ipv6ToGroups(text: string): number[] | null {
  if (!/^[0-9A-Fa-f:]+$/.test(text) || (text.match(/::/g) ?? []).length > 1) return null
  const [head, tail] = text.split('::')
  const left = head ? head.split(':') : []
  const right = tail !== undefined && tail ? tail.split(':') : []
  const compressed = text.includes('::')
  if (!compressed && left.length !== 8) return null
  if (compressed && left.length + right.length > 7) return null
  const groups = compressed
    ? [...left, ...new Array<string>(8 - left.length - right.length).fill('0'), ...right]
    : left
  if (groups.some((g) => g === '' || g.length > 4)) return null
  return groups.map((g) => parseInt(g, 16))
}

/** A literal such as `10.0.0.1`, `10.0.0.0/8` or `fe80::1/64` as a predicate. */
function ipMatcher(literal: string, position: number): (address: string) => boolean {
  const [base, lenText] = literal.split('/')
  const v4 = ipv4ToInt(base)
  if (v4 !== null) {
    const bits = lenText === undefined ? 32 : Number(lenText)
    if (bits > 32) throw new FilterSyntaxError('bad-value', position, literal)
    const size = 2 ** (32 - bits)
    return (address) => {
      const value = ipv4ToInt(address)
      return value !== null && Math.floor(value / size) === Math.floor(v4 / size)
    }
  }
  const v6 = ipv6ToGroups(base)
  if (v6 === null) throw new FilterSyntaxError('bad-value', position, literal)
  const bits = lenText === undefined ? 128 : Number(lenText)
  if (bits > 128) throw new FilterSyntaxError('bad-value', position, literal)
  return (address) => {
    const groups = ipv6ToGroups(address)
    if (groups === null) return false
    for (let bit = 0; bit < bits; bit += 1) {
      const index = Math.floor(bit / 16)
      const mask = 1 << (15 - (bit % 16))
      if ((groups[index] & mask) !== (v6[index] & mask)) return false
    }
    return true
  }
}

const isV4 = (address: string): boolean => address.includes('.') && !address.includes(':')
const isV6 = (address: string): boolean => address.includes(':')

// ── fields ────────────────────────────────────────────────────────────────
type FieldType = 'bool' | 'number' | 'string' | 'ip'
type Value = boolean | number | string | undefined
interface FieldDef {
  type: FieldType
  get: (row: PacketRow) => Value | Value[]
}

const isTcp = (row: PacketRow): boolean => row.stream != null
const isUdp = (row: PacketRow): boolean => !isTcp(row) && row.sport != null && row.seq == null
const analysis = (row: PacketRow, name: string): true | undefined =>
  (row.analysis ?? []).includes(name) ? true : undefined
const flagBit = (row: PacketRow, name: string): boolean | undefined =>
  isTcp(row) ? (row.tcp_flags ?? []).includes(name) : undefined
const numberOrUndefined = (value: number | null | undefined): number | undefined =>
  value == null ? undefined : value
const tcpOnly = <T,>(row: PacketRow, value: T): T | undefined => (isTcp(row) ? value : undefined)
const udpOnly = <T,>(row: PacketRow, value: T): T | undefined => (isUdp(row) ? value : undefined)
const ipv4Of = (address: string): string | undefined => (isV4(address) ? address : undefined)
const ipv6Of = (address: string): string | undefined => (isV6(address) ? address : undefined)
const EXPERT_SEVERITY: Record<string, number> = {
  chat: 2097152,
  note: 4194304,
  warning: 6291456,
  error: 8388608,
}

const FIELDS: Record<string, FieldDef> = {
  'frame.number': { type: 'number', get: (r) => r.number },
  'frame.time_relative': { type: 'number', get: (r) => r.time },
  'frame.len': { type: 'number', get: (r) => r.length },
  '_ws.col.info': { type: 'string', get: (r) => r.info },
  '_ws.col.protocol': { type: 'string', get: (r) => r.protocol },
  'ip.src': { type: 'ip', get: (r) => ipv4Of(r.src) },
  'ip.dst': { type: 'ip', get: (r) => ipv4Of(r.dst) },
  'ip.addr': { type: 'ip', get: (r) => [ipv4Of(r.src), ipv4Of(r.dst)] },
  'ip.ttl': { type: 'number', get: (r) => numberOrUndefined(r.ttl) },
  'ipv6.src': { type: 'ip', get: (r) => ipv6Of(r.src) },
  'ipv6.dst': { type: 'ip', get: (r) => ipv6Of(r.dst) },
  'ipv6.addr': { type: 'ip', get: (r) => [ipv6Of(r.src), ipv6Of(r.dst)] },
  'tcp.stream': { type: 'number', get: (r) => numberOrUndefined(r.stream) },
  'tcp.srcport': { type: 'number', get: (r) => tcpOnly(r, numberOrUndefined(r.sport)) },
  'tcp.dstport': { type: 'number', get: (r) => tcpOnly(r, numberOrUndefined(r.dport)) },
  'tcp.port': {
    type: 'number',
    get: (r) => (isTcp(r) ? [numberOrUndefined(r.sport), numberOrUndefined(r.dport)] : undefined),
  },
  'tcp.len': { type: 'number', get: (r) => tcpOnly(r, numberOrUndefined(r.payload)) },
  'tcp.seq': { type: 'number', get: (r) => tcpOnly(r, numberOrUndefined(r.seq)) },
  'tcp.ack': { type: 'number', get: (r) => tcpOnly(r, numberOrUndefined(r.ack)) },
  'tcp.window_size': { type: 'number', get: (r) => tcpOnly(r, numberOrUndefined(r.win)) },
  'tcp.flags.syn': { type: 'bool', get: (r) => flagBit(r, 'SYN') },
  'tcp.flags.ack': { type: 'bool', get: (r) => flagBit(r, 'ACK') },
  'tcp.flags.fin': { type: 'bool', get: (r) => flagBit(r, 'FIN') },
  'tcp.flags.reset': { type: 'bool', get: (r) => flagBit(r, 'RST') },
  'tcp.flags.push': { type: 'bool', get: (r) => flagBit(r, 'PSH') },
  'tcp.analysis.retransmission': { type: 'bool', get: (r) => analysis(r, 'retransmission') },
  'tcp.analysis.fast_retransmission': { type: 'bool', get: (r) => analysis(r, 'fast_retransmission') },
  'tcp.analysis.spurious_retransmission': {
    type: 'bool',
    get: (r) => analysis(r, 'spurious_retransmission'),
  },
  'tcp.analysis.duplicate_ack': { type: 'bool', get: (r) => analysis(r, 'dup_ack') },
  'tcp.analysis.out_of_order': { type: 'bool', get: (r) => analysis(r, 'out_of_order') },
  'tcp.analysis.lost_segment': { type: 'bool', get: (r) => analysis(r, 'lost_segment') },
  'tcp.analysis.window_full': { type: 'bool', get: (r) => analysis(r, 'window_full') },
  'tcp.analysis.zero_window': { type: 'bool', get: (r) => analysis(r, 'zero_window') },
  'tcp.analysis.zero_window_probe': { type: 'bool', get: (r) => analysis(r, 'zero_window_probe') },
  'tcp.analysis.window_update': { type: 'bool', get: (r) => analysis(r, 'window_update') },
  'tcp.analysis.keep_alive': { type: 'bool', get: (r) => analysis(r, 'keep_alive') },
  'tcp.analysis.flags': {
    type: 'bool',
    // "duplicate_frame" is our own mark for a capture artefact, not a TCP problem.
    get: (r) => ((r.analysis ?? []).some((flag) => flag !== 'duplicate_frame') ? true : undefined),
  },
  // Wireshark expresses RELATIVE_TIME in seconds.
  'tcp.analysis.ack_rtt': {
    type: 'number',
    get: (r) => (r.rtt_ms == null ? undefined : r.rtt_ms / 1000),
  },
  'udp.srcport': { type: 'number', get: (r) => udpOnly(r, numberOrUndefined(r.sport)) },
  'udp.dstport': { type: 'number', get: (r) => udpOnly(r, numberOrUndefined(r.dport)) },
  'udp.port': {
    type: 'number',
    get: (r) => (isUdp(r) ? [numberOrUndefined(r.sport), numberOrUndefined(r.dport)] : undefined),
  },
  '_ws.expert': { type: 'bool', get: (r) => (r.expert ? true : undefined) },
  '_ws.expert.severity': {
    type: 'number',
    get: (r) => (r.expert ? EXPERT_SEVERITY[r.expert] : undefined),
  },
  '_ws.expert.message': { type: 'string', get: (r) => r.expert_message ?? undefined },
}

/** Field names the filter understands (for help and autocompletion). */
export const FILTER_FIELDS: string[] = Object.keys(FIELDS).sort()

/** Protocol names accepted as a bare word (`dns`, `tcp`...). Others must be seen in the data. */
const BUILTIN_PROTOCOLS = new Set([
  'tcp', 'udp', 'ip', 'ipv6', 'icmp', 'icmpv6', 'arp', 'dns', 'mdns', 'llmnr', 'http',
  'http2', 'tls', 'ssl', 'dhcp', 'bootp', 'isakmp', 'esp', 'ntp', 'ssh', 'ftp', 'smtp',
  'imap', 'pop', 'snmp', 'syslog', 'quic', 'stun', 'rtp', 'sip', 'ssdp', 'nbns', 'smb',
  'smb2', 'igmp', 'stp', 'lldp', 'vrrp', 'ospf', 'bgp', 'eigrp', 'gre', 'l2tp', 'openvpn',
  'wireguard',
])

const protocolKey = (row: PacketRow): string => {
  const name = row.protocol.toLowerCase()
  if (name.startsWith('tlsv')) return 'tls'
  if (name.startsWith('sslv')) return 'ssl'
  return name
}

function protocolTest(name: string): (row: PacketRow) => boolean {
  switch (name) {
    case 'tcp':
      return isTcp
    case 'udp':
      return isUdp
    case 'ip':
      return (r) => isV4(r.src) || isV4(r.dst)
    case 'ipv6':
      return (r) => isV6(r.src) || isV6(r.dst)
    case 'ssl':
    case 'tls':
      return (r) => ['tls', 'ssl'].includes(protocolKey(r))
    default:
      return (r) => protocolKey(r) === name
  }
}

// ── AST ───────────────────────────────────────────────────────────────────
type Node = (row: PacketRow) => boolean

// ── parser ────────────────────────────────────────────────────────────────
const WORD_OPERATORS: Record<string, string> = {
  eq: '==', ne: '!=', gt: '>', lt: '<', ge: '>=', le: '<=',
  contains: 'contains', matches: 'matches', in: 'in',
}
const RELATIONAL = new Set(['>', '<', '>=', '<='])

class Parser {
  private tokens: Token[]
  private index = 0
  private known: ReadonlySet<string>

  constructor(tokens: Token[], known: ReadonlySet<string>) {
    this.tokens = tokens
    this.known = known
  }

  private peek(): Token {
    return this.tokens[this.index]
  }

  private next(): Token {
    const token = this.tokens[this.index]
    if (token.t !== 'end') this.index += 1
    return token
  }

  private isSym(value: string): boolean {
    const token = this.peek()
    return token.t === 'sym' && token.v === value
  }

  private isWord(...values: string[]): boolean {
    const token = this.peek()
    return token.t === 'word' && values.includes(token.v.toLowerCase())
  }

  parse(): Node {
    const node = this.parseOr()
    const token = this.peek()
    if (token.t !== 'end') throw new FilterSyntaxError('unexpected-token', token.pos, tokenText(token))
    return node
  }

  private parseOr(): Node {
    let left = this.parseAnd()
    while (this.isSym('||') || this.isWord('or')) {
      this.next()
      const l = left
      const r = this.parseAnd()
      left = (row) => l(row) || r(row)
    }
    return left
  }

  private parseAnd(): Node {
    let left = this.parseNot()
    while (this.isSym('&&') || this.isWord('and')) {
      this.next()
      const l = left
      const r = this.parseNot()
      left = (row) => l(row) && r(row)
    }
    return left
  }

  private parseNot(): Node {
    if (this.isSym('!') || this.isWord('not')) {
      this.next()
      const inner = this.parseNot()
      return (row) => !inner(row)
    }
    return this.parsePrimary()
  }

  private parsePrimary(): Node {
    const token = this.peek()
    if (token.t === 'sym' && token.v === '(') {
      this.next()
      const inner = this.parseOr()
      if (!this.isSym(')')) throw new FilterSyntaxError('unclosed-paren', this.peek().pos)
      this.next()
      return inner
    }
    if (token.t === 'end') throw new FilterSyntaxError('unexpected-end', token.pos)
    if (token.t !== 'word') throw new FilterSyntaxError('unexpected-token', token.pos, tokenText(token))
    this.next()
    const name = token.v

    const field = FIELDS[name]
    if (!field) {
      if (name.includes('.')) throw new FilterSyntaxError('unknown-field', token.pos, name)
      const lower = name.toLowerCase()
      if (!BUILTIN_PROTOCOLS.has(lower) && !this.known.has(lower)) {
        throw new FilterSyntaxError('unknown-field', token.pos, name)
      }
      return protocolTest(lower) // bare protocol name: `dns`, `tcp`...
    }

    const operator = this.readOperator()
    if (operator === null) {
      // existence test; for booleans it means "the flag is set"
      return field.type === 'bool'
        ? (row) => toArray(field.get(row)).some((v) => v === true)
        : (row) => toArray(field.get(row)).length > 0
    }
    return this.parseComparison(name, field, operator, token.pos)
  }

  private readOperator(): string | null {
    const token = this.peek()
    if (token.t === 'sym' && ['==', '!=', '>=', '<=', '>', '<', '~'].includes(token.v)) {
      this.next()
      return token.v === '~' ? 'matches' : token.v
    }
    if (token.t === 'word' && token.v.toLowerCase() in WORD_OPERATORS) {
      this.next()
      return WORD_OPERATORS[token.v.toLowerCase()]
    }
    return null
  }

  private parseComparison(name: string, field: FieldDef, op: string, position: number): Node {
    if (op === 'in') return this.parseSet(name, field, position)
    if (RELATIONAL.has(op) && field.type !== 'number') {
      throw new FilterSyntaxError('bad-operator', position, `${op} ${name}`)
    }
    if ((op === 'contains' || op === 'matches') && field.type !== 'string') {
      throw new FilterSyntaxError('bad-operator', position, `${op} ${name}`)
    }
    const token = this.next()
    if (token.t === 'end') throw new FilterSyntaxError('unexpected-end', token.pos)

    if (op === 'matches') {
      if (token.t !== 'str') throw new FilterSyntaxError('bad-value', token.pos, tokenText(token))
      let regex: RegExp
      try {
        regex = new RegExp(token.v, 'i') // Wireshark's matches is case-insensitive
      } catch {
        throw new FilterSyntaxError('bad-regex', token.pos, token.v)
      }
      return (row) => toArray(field.get(row)).some((v) => regex.test(String(v)))
    }
    if (op === 'contains') {
      if (token.t !== 'str') throw new FilterSyntaxError('bad-value', token.pos, tokenText(token))
      const needle = token.v
      return (row) => toArray(field.get(row)).some((v) => String(v).includes(needle))
    }

    const equals = this.equalityMatcher(field, token)
    const compare = (value: Value): boolean => {
      if (RELATIONAL.has(op)) {
        const limit = (token as { v: number }).v
        if (typeof value !== 'number') return false
        return op === '>' ? value > limit : op === '<' ? value < limit : op === '>=' ? value >= limit : value <= limit
      }
      return equals(value)
    }
    if (op === '!=') {
      // Wireshark: absent field -> false; present -> none of its values equal
      return (row) => {
        const values = toArray(field.get(row))
        return values.length > 0 && !values.some(equals)
      }
    }
    if (RELATIONAL.has(op) && token.t !== 'num') {
      throw new FilterSyntaxError('bad-value', token.pos, tokenText(token))
    }
    return (row) => toArray(field.get(row)).some(compare)
  }

  /** Predicate "does this value equal the literal?" for the field's type. */
  private equalityMatcher(field: FieldDef, token: Token): (value: Value) => boolean {
    switch (field.type) {
      case 'number':
        if (token.t !== 'num') throw new FilterSyntaxError('bad-value', token.pos, tokenText(token))
        return (v) => typeof v === 'number' && v === token.v
      case 'bool': {
        const truthy =
          token.t === 'num' ? token.v === 1 : token.t === 'word' && token.v.toLowerCase() === 'true'
        const falsy =
          token.t === 'num' ? token.v === 0 : token.t === 'word' && token.v.toLowerCase() === 'false'
        if (!truthy && !falsy) throw new FilterSyntaxError('bad-value', token.pos, tokenText(token))
        return (v) => typeof v === 'boolean' && v === truthy
      }
      case 'ip': {
        if (token.t !== 'ip' && token.t !== 'str') {
          throw new FilterSyntaxError('bad-value', token.pos, tokenText(token))
        }
        const matches = ipMatcher(token.v, token.pos)
        return (v) => typeof v === 'string' && matches(v)
      }
      default:
        if (token.t !== 'str') throw new FilterSyntaxError('bad-value', token.pos, tokenText(token))
        return (v) => v === token.v
    }
  }

  private parseSet(name: string, field: FieldDef, position: number): Node {
    const open = this.next()
    if (open.t !== 'sym' || open.v !== '{') throw new FilterSyntaxError('bad-value', open.pos, tokenText(open))
    const members: Array<(value: Value) => boolean> = []
    while (!this.isSym('}')) {
      const token = this.next()
      if (token.t === 'end') throw new FilterSyntaxError('unclosed-set', token.pos)
      if (token.t === 'num' && this.isSym('..')) {
        this.next()
        const upper = this.next()
        if (upper.t !== 'num' || field.type !== 'number') {
          throw new FilterSyntaxError('bad-value', upper.pos, tokenText(upper))
        }
        const low = token.v
        const high = upper.v
        members.push((v) => typeof v === 'number' && v >= low && v <= high)
        continue
      }
      members.push(this.equalityMatcher(field, token))
    }
    this.next() // closing brace
    if (members.length === 0) throw new FilterSyntaxError('bad-value', position, name)
    return (row) => toArray(field.get(row)).some((v) => members.some((m) => m(v)))
  }
}

function toArray(value: Value | Value[]): Value[] {
  return (Array.isArray(value) ? value : [value]).filter((v) => v !== undefined)
}

function tokenText(token: Token): string {
  switch (token.t) {
    case 'end':
      return ''
    case 'num':
      return String(token.v)
    default:
      return token.v
  }
}

// ── public API ────────────────────────────────────────────────────────────
/**
 * Compile a display filter. `knownProtocols` (lower-case names present in the
 * data) lets bare protocol words that are not in the built-in list still work.
 */
export function compileFilter(
  source: string,
  knownProtocols: ReadonlySet<string> = new Set(),
): Compiled {
  if (source.trim() === '') return { ok: true, empty: true, test: () => true }
  try {
    const node = new Parser(tokenize(source), knownProtocols).parse()
    return { ok: true, empty: false, test: node }
  } catch (error) {
    if (error instanceof FilterSyntaxError) {
      return { ok: false, error: { code: error.code, arg: error.arg, position: error.position } }
    }
    throw error
  }
}

/** True when the text clearly *tries* to be a filter (so errors deserve to be shown). */
export function looksLikeFilter(source: string): boolean {
  return /(==|!=|>=|<=|&&|\|\||[<>(){}!~]|\b(and|or|not|eq|ne|gt|lt|ge|le|contains|matches|in)\b)/i.test(source)
}

// ── building filters from what the user clicks ────────────────────────────
type EndpointRow = Pick<PacketRow, 'src' | 'dst' | 'sport' | 'dport'>

const addressField = (address: string): string => (isV6(address) ? 'ipv6' : 'ip')
const quote = (address: string): string => address

/** Filters offered by "apply as filter" on a packet row. */
export function filtersForRow(row: PacketRow): Record<string, string> {
  const filters: Record<string, string> = {}
  if (row.src && row.src !== '—') filters.src = `${addressField(row.src)}.src == ${quote(row.src)}`
  if (row.dst && row.dst !== '—') filters.dst = `${addressField(row.dst)}.dst == ${quote(row.dst)}`
  if (row.src && row.dst && row.src !== '—' && row.dst !== '—') {
    filters.hosts = `${addressField(row.src)}.addr == ${quote(row.src)} && ${addressField(row.dst)}.addr == ${quote(row.dst)}`
  }
  const proto = isTcp(row) ? 'tcp' : isUdp(row) ? 'udp' : null
  if (proto && row.sport != null && row.dport != null) {
    filters.conversation = conversationFilter(row, proto)
    filters.port = `${proto}.port == ${row.dport}`
  }
  if (row.stream != null) filters.stream = `tcp.stream eq ${row.stream}`
  return filters
}

/** `ip.addr == A && ip.addr == B && tcp.port == X && tcp.port == Y` */
export function conversationFilter(row: EndpointRow, proto: 'tcp' | 'udp'): string {
  const family = addressField(row.src)
  return (
    `${family}.addr == ${quote(row.src)} && ${addressField(row.dst)}.addr == ${quote(row.dst)}` +
    ` && ${proto}.port == ${row.sport} && ${proto}.port == ${row.dport}`
  )
}
