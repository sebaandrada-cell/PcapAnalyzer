import assert from 'node:assert/strict'
import { test } from 'node:test'
import { estimateCostUsd } from './pricing.ts'

test('cost table', () => {
  const u = { input_tokens: 1_000_000, output_tokens: 100_000, cache_read_tokens: 500_000, cache_write_tokens: 0 }
  assert.equal(estimateCostUsd(u, 'claude-opus-5-5'), 4 + 2 + 0.1)
  assert.equal(estimateCostUsd(u, 'claude-sonnet-5-5'), 2 + 1 + 0.1)
  assert.equal(estimateCostUsd(u, 'gpt-x'), null)
  assert.equal(estimateCostUsd({ input_tokens: 0, output_tokens: 0, cache_read_tokens: 0, cache_write_tokens: 0 }, 'claude-opus-5-5'), 0)
})
