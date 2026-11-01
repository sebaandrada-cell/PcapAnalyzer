// Run with: node --test api/contacto.test.js
import assert from 'node:assert/strict'
import { afterEach, beforeEach, test } from 'node:test'
import handler, { MAX_BODY, allowedOrigins, validate } from './contacto.js'

const ORIGIN = 'https://pcap-analyzer-seven.vercel.app'
const ENV_KEYS = ['RESEND_API_KEY', 'CONTACT_TO', 'TURNSTILE_SECRET', 'CONTACT_ORIGINS', 'CONTACT_FROM']
const saved = {}
const realFetch = globalThis.fetch
let calls

beforeEach(() => {
  for (const k of ENV_KEYS) saved[k] = process.env[k]
  calls = []
})
afterEach(() => {
  for (const k of ENV_KEYS) {
    if (saved[k] === undefined) delete process.env[k]
    else process.env[k] = saved[k]
  }
  globalThis.fetch = realFetch
})

function configure() {
  process.env.RESEND_API_KEY = 're_test'
  process.env.CONTACT_TO = ' "destino@example.com" '
  process.env.TURNSTILE_SECRET = 'ts_secret'
}

function makeRes() {
  const res = { headers: {}, statusCode: 0, body: undefined, ended: false }
  res.setHeader = (k, v) => { res.headers[k] = v }
  res.status = (c) => { res.statusCode = c; return res }
  res.json = (b) => { res.body = b; return res }
  res.end = () => { res.ended = true; return res }
  return res
}

function makeReq(body, extra = {}) {
  const raw = JSON.stringify(body)
  return {
    method: 'POST',
    headers: { origin: ORIGIN, 'content-length': String(Buffer.byteLength(raw)), 'x-real-ip': '203.0.113.' + Math.floor(Math.random() * 250), ...extra.headers },
    body,
    ...extra.top,
  }
}

const GOOD = { email: 'persona@example.com', nombre: 'Ana', mensaje: 'Hola, tengo una duda.', idioma: 'en', 'cf-turnstile-response': 'tok' }

function mockFetch(handlers) {
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), init })
    for (const [match, resp] of handlers) if (String(url).includes(match)) return resp(init)
    throw new Error('unexpected fetch ' + url)
  }
}
const ok = (data) => async () => ({ ok: true, status: 200, json: async () => data, text: async () => JSON.stringify(data) })

test('validate normalises and rejects bad input', () => {
  assert.equal(validate({ email: 'mal', mensaje: 'hola mundo' }).error, 'email')
  assert.equal(validate({ email: 'a@b.co', mensaje: 'hi' }).error, 'mensaje')
  const v = validate({ email: ' a@b.co ', nombre: 'A\nB', mensaje: 'hola mundo', idioma: 'fr' }).value
  assert.equal(v.email, 'a@b.co')
  assert.equal(v.name, 'A B')
  assert.equal(v.lang, 'es')
})

test('allowedOrigins adds CONTACT_ORIGINS', () => {
  assert.ok(allowedOrigins({}).includes(ORIGIN))
  assert.ok(allowedOrigins({ CONTACT_ORIGINS: 'https://x.test , https://y.test' }).includes('https://y.test'))
})

test('rejects wrong method, wrong origin and missing/oversized length', async () => {
  let res = makeRes(); await handler({ method: 'GET', headers: { origin: ORIGIN } }, res); assert.equal(res.statusCode, 405)
  res = makeRes(); await handler(makeReq(GOOD, { headers: { origin: 'https://evil.test' } }), res); assert.equal(res.statusCode, 403)
  res = makeRes(); await handler(makeReq(GOOD, { headers: { 'content-length': '' } }), res); assert.equal(res.statusCode, 411)
  res = makeRes(); await handler(makeReq(GOOD, { headers: { 'content-length': String(MAX_BODY + 1) } }), res); assert.equal(res.statusCode, 413)
})

test('OPTIONS answers 204 and sets CORS for an allowed origin', async () => {
  const res = makeRes(); await handler({ method: 'OPTIONS', headers: { origin: ORIGIN } }, res)
  assert.equal(res.statusCode, 204)
  assert.equal(res.headers['Access-Control-Allow-Origin'], ORIGIN)
})

test('honeypot is accepted silently and sends nothing', async () => {
  mockFetch([])
  const res = makeRes(); await handler(makeReq({ ...GOOD, web: 'spam' }), res)
  assert.equal(res.statusCode, 202)
  assert.equal(calls.length, 0)
})

test('503 when not configured (no keys), nothing is fetched', async () => {
  mockFetch([])
  const res = makeRes(); await handler(makeReq(GOOD), res)
  assert.equal(res.statusCode, 503)
  assert.equal(calls.length, 0)
})

test('403 without a Turnstile token and when Turnstile says no', async () => {
  configure()
  mockFetch([['turnstile', ok({ success: false })]])
  let res = makeRes(); await handler(makeReq({ ...GOOD, 'cf-turnstile-response': '' }), res); assert.equal(res.statusCode, 403)
  res = makeRes(); await handler(makeReq(GOOD), res); assert.equal(res.statusCode, 403)
  assert.ok(!calls.some((c) => c.url.includes('resend')), 'must not email when the captcha fails')
})

test('sends the email with a cleaned recipient and reply_to', async () => {
  configure()
  mockFetch([['turnstile', ok({ success: true })], ['resend', ok({ id: 'x' })]])
  const res = makeRes(); await handler(makeReq(GOOD), res)
  assert.equal(res.statusCode, 202)
  const mail = JSON.parse(calls.find((c) => c.url.includes('resend')).init.body)
  assert.deepEqual(mail.to, ['destino@example.com'])
  assert.equal(mail.reply_to, 'persona@example.com')
  assert.match(mail.text, /Hola, tengo una duda\./)
  assert.match(calls.find((c) => c.url.includes('resend')).init.headers.Authorization, /^Bearer re_test$/)
})

test('502 when Resend fails, and the failure does not count against the limit', async () => {
  configure()
  const ip = { headers: { 'x-real-ip': '198.51.100.9' } }
  mockFetch([['turnstile', ok({ success: true })], ['resend', async () => ({ ok: false, status: 422, text: async () => 'bad' })]])
  const quiet = console.error; console.error = () => {}
  try {
    for (let i = 0; i < 5; i++) { const r = makeRes(); await handler(makeReq(GOOD, ip), r); assert.equal(r.statusCode, 502) }
  } finally { console.error = quiet }
})

test('429 after 3 successful sends from the same IP', async () => {
  configure()
  const ip = { headers: { 'x-real-ip': '198.51.100.77' } }
  mockFetch([['turnstile', ok({ success: true })], ['resend', ok({ id: 'x' })]])
  for (let i = 0; i < 3; i++) { const r = makeRes(); await handler(makeReq(GOOD, ip), r); assert.equal(r.statusCode, 202) }
  const res = makeRes(); await handler(makeReq(GOOD, ip), res)
  assert.equal(res.statusCode, 429)
})
