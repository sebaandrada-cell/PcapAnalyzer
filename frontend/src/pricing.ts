// Rough cost of a session from the usage the backend reports. Prices are USD
// per million tokens and are an estimate shown as such. Pure module.
export interface Usage {
  input_tokens: number
  output_tokens: number
  cache_read_tokens: number
  cache_write_tokens: number
}

interface Price {
  input: number
  output: number
  cacheRead: number
  cacheWrite: number
}

// Longest prefix wins, so "claude-opus-5-5" matches before "claude-opus-5".
const PRICES: Array<[string, Price]> = [
  ['claude-fable-5-1', { input: 10, output: 50, cacheRead: 0.25, cacheWrite: 12.5 }],
  ['claude-fable-5', { input: 10, output: 50, cacheRead: 0.25, cacheWrite: 12.5 }],
  ['claude-opus-5-5', { input: 4, output: 20, cacheRead: 0.2, cacheWrite: 5 }],
  ['claude-opus-5', { input: 5, output: 25, cacheRead: 0.5, cacheWrite: 6.25 }],
  ['claude-opus-4', { input: 5, output: 25, cacheRead: 0.5, cacheWrite: 6.25 }],
  ['claude-sonnet-5-5', { input: 2, output: 10, cacheRead: 0.2, cacheWrite: 2.5 }],
  ['claude-sonnet-5', { input: 2, output: 10, cacheRead: 0.2, cacheWrite: 2.5 }],
  ['claude-sonnet-4', { input: 3, output: 15, cacheRead: 0.3, cacheWrite: 3.75 }],
  ['claude-haiku-5-5', { input: 0.1, output: 0.5, cacheRead: 0.01, cacheWrite: 0.125 }],
  ['claude-haiku-4', { input: 1, output: 5, cacheRead: 0.1, cacheWrite: 1.25 }],
]

export const EMPTY_USAGE: Usage = { input_tokens: 0, output_tokens: 0, cache_read_tokens: 0, cache_write_tokens: 0 }

export function addUsage(a: Usage, b: Partial<Usage>): Usage {
  return {
    input_tokens: a.input_tokens + (b.input_tokens ?? 0),
    output_tokens: a.output_tokens + (b.output_tokens ?? 0),
    cache_read_tokens: a.cache_read_tokens + (b.cache_read_tokens ?? 0),
    cache_write_tokens: a.cache_write_tokens + (b.cache_write_tokens ?? 0),
  }
}

export function estimateCostUsd(usage: Usage, model: string): number | null {
  const match = PRICES.filter(([prefix]) => model.startsWith(prefix)).sort((a, b) => b[0].length - a[0].length)[0]
  if (!match) return null
  const p = match[1]
  const usd =
    (usage.input_tokens * p.input +
      usage.output_tokens * p.output +
      usage.cache_read_tokens * p.cacheRead +
      usage.cache_write_tokens * p.cacheWrite) /
    1_000_000
  return Math.round(usd * 10_000) / 10_000
}
