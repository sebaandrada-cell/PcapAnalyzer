// Presentation helpers for the packet list: colouring rules, time formats,
// name resolution and CSV export. Pure module: `node --test src/packetView.test.ts`.
import type { PacketRow, ResolvedName } from './api.ts'

export type TimeFormat = 'relative' | 'delta' | 'absolute'
export type RowColor = 'bad' | 'rst' | 'synfin' | 'icmp' | 'dns' | 'tls'

/** Colouring rules, first match wins (same idea as Wireshark's default coloring rules). */
export function rowColor(row: PacketRow): RowColor | null {
  const flags = row.tcp_flags ?? []
  const analysis = row.analysis ?? []
  const protocol = row.protocol.toLowerCase()
  if (row.expert === 'error') return 'bad'
  if (analysis.some((a) => a !== 'window_update' && a !== 'keep_alive')) return 'bad'
  if (flags.includes('RST')) return 'rst'
  if (row.expert === 'warning') return 'bad'
  if (flags.includes('SYN') || flags.includes('FIN')) return 'synfin'
  if (protocol.startsWith('icmp')) return 'icmp'
  if (protocol === 'dns' || protocol === 'mdns' || protocol === 'llmnr') return 'dns'
  if (protocol.startsWith('tls') || protocol.startsWith('ssl')) return 'tls'
  return null
}

export const ROW_COLORS: RowColor[] = ['bad', 'rst', 'synfin', 'icmp', 'dns', 'tls']

/** Time cell for a row. `previous` is the previous *displayed* row (for delta). */
export function formatPacketTime(
  row: PacketRow,
  format: TimeFormat,
  previous: PacketRow | null,
  startEpoch: number | null,
): string {
  if (format === 'delta') return (previous ? Math.max(0, row.time - previous.time) : 0).toFixed(6)
  if (format === 'absolute' && startEpoch != null) {
    const date = new Date((startEpoch + row.time) * 1000)
    if (Number.isNaN(date.getTime())) return row.time.toFixed(6)
    const pad = (n: number, w = 2) => String(n).padStart(w, '0')
    return (
      `${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())}` +
      `.${pad(date.getUTCMilliseconds(), 3)}`
    )
  }
  return row.time.toFixed(6)
}

export function nameMap(names: ResolvedName[] | undefined): Map<string, string> {
  return new Map((names ?? []).map((entry) => [entry.address, entry.name]))
}

export function displayAddress(address: string, names: Map<string, string> | null): string {
  return names?.get(address) ?? address
}

/** Neutralise spreadsheet formulas in cells that start with =, +, -, @, tab or CR. */
export function csvCell(value: string | number | null | undefined): string {
  let text = value == null ? '' : String(value)
  if (/^[=+\-@\t\r]/.test(text) && typeof value === 'string') text = `'${text}`
  return /[",\n\r]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text
}

export const CSV_HEADER = [
  'No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info', 'TCP stream',
  'Src port', 'Dst port', 'TCP flags', 'Analysis', 'Expert',
]

export function packetsToCsv(
  rows: PacketRow[],
  names: Map<string, string> | null = null,
): string {
  const lines = [CSV_HEADER.map(csvCell).join(',')]
  for (const row of rows) {
    lines.push(
      [
        row.number,
        row.time.toFixed(6),
        displayAddress(row.src, names),
        displayAddress(row.dst, names),
        row.protocol,
        row.length,
        row.info,
        row.stream,
        row.sport,
        row.dport,
        (row.tcp_flags ?? []).join(' '),
        (row.analysis ?? []).join(' '),
        row.expert_message ?? row.expert ?? '',
      ]
        .map(csvCell)
        .join(','),
    )
  }
  return `${lines.join('\r\n')}\r\n`
}
