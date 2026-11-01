// Vercel function: receives the public contact form and forwards it by email.
// The destination address is NOT in the code or the site: it lives in environment variables.
// Environment variables (Vercel → Settings → Environment Variables):
//   RESEND_API_KEY     Resend API key (resend.com)
//   CONTACT_TO         mailbox that receives the messages
//   CONTACT_FROM       (optional) sender; defaults to Resend's test sender
//   TURNSTILE_SECRET   SECRET key of the Cloudflare Turnstile widget. Without it the form does not send.
//   CONTACT_ORIGINS    (optional) extra allowed origins, comma separated
const BASE_ORIGINS = [
  'https://pcap-analyzer-seven.vercel.app',
  'https://pcap-analyzer-noviembrepunk.vercel.app',
]
export const MAX_BODY = 6000 // bytes; a Turnstile token can reach ~2 KB
export const MAX_MESSAGE = 2000
export const MAX_NAME = 80
const WINDOW_MS = 10 * 60 * 1000
const MAX_PER_WINDOW = 3
const EMAIL = /^[^\s@<>"]+@[^\s@<>"]+\.[^\s@<>"]{2,}$/

// NOTE: this Map only slows requests inside one serverless instance; it is not a real limit.
// The real limits are Turnstile (fails closed) + the honeypot + the body-size cap.
// The Origin header can be forged outside a browser: it only avoids accidental use.
const sent = new Map()

const clean = (s, max) => String(s || '').replace(/[\r\n\t]+/g, ' ').trim().slice(0, max)

export function allowedOrigins(env = process.env) {
  const extra = String(env.CONTACT_ORIGINS || '')
    .split(',')
    .map((o) => o.trim())
    .filter(Boolean)
  return [...BASE_ORIGINS, ...extra]
}

// Validates and normalises the body. Returns { error } or { value }.
export function validate(body) {
  const email = clean(body.email, 200)
  const name = clean(body.nombre, MAX_NAME)
  const message = String(body.mensaje || '').trim().slice(0, MAX_MESSAGE)
  const lang = ['es', 'en'].includes(body.idioma) ? body.idioma : 'es'
  if (!EMAIL.test(email)) return { error: 'email' }
  if (message.length < 5) return { error: 'mensaje' }
  return { value: { email, name, message, lang } }
}

export default async function handler(req, res) {
  const origins = allowedOrigins()
  const origin = origins.includes(req.headers.origin) ? req.headers.origin : origins[0]
  res.setHeader('Access-Control-Allow-Origin', origin)
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type')
  res.setHeader('Vary', 'Origin')
  res.setHeader('Cache-Control', 'no-store')
  if (req.method === 'OPTIONS') return res.status(204).end()
  if (req.method !== 'POST') return res.status(405).json({ error: 'metodo' })
  if (!origins.includes(req.headers.origin)) return res.status(403).json({ error: 'origen' })

  // No Content-Length or too large: out, before touching the body.
  const length = Number(req.headers['content-length'])
  if (!Number.isFinite(length) || length <= 0) return res.status(411).json({ error: 'largo' })
  if (length > MAX_BODY) return res.status(413).json({ error: 'grande' })

  let body
  try {
    body = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : req.body || {}
  } catch {
    return res.status(400).json({ error: 'datos' })
  }

  // Honeypot: people never see or fill it. Answer "ok" so bots learn nothing.
  if (body.web) return res.status(202).json({ ok: true })

  const checked = validate(body)
  if (checked.error) return res.status(400).json({ error: checked.error })
  const { email, name, message, lang } = checked.value

  // CONTACT_TO is cleaned: stray spaces, newlines or quotes make Resend reject the "to" field.
  const to = String(process.env.CONTACT_TO || '').trim().replace(/^["'<\s]+|["'>\s]+$/g, '')
  const apiKey = process.env.RESEND_API_KEY
  const turnstileSecret = process.env.TURNSTILE_SECRET
  if (!to || !apiKey || !turnstileSecret) return res.status(503).json({ error: 'no_configurado' })

  // Turnstile fails closed: without a valid token there is no email.
  const token = String(body['cf-turnstile-response'] || '').slice(0, 2100)
  if (!token) return res.status(403).json({ error: 'captcha' })
  const ip = String(req.headers['x-vercel-forwarded-for'] || req.headers['x-real-ip'] || '').split(',')[0].trim()
  try {
    const v = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ secret: turnstileSecret, response: token, ...(ip ? { remoteip: ip } : {}) }),
      signal: AbortSignal.timeout(5000),
    })
    const j = await v.json()
    if (!j.success) return res.status(403).json({ error: 'captcha' })
  } catch {
    return res.status(502).json({ error: 'captcha' })
  }

  const key = ip || 'unknown'
  const now = Date.now()
  const previous = (sent.get(key) || []).filter((t) => now - t < WINDOW_MS)
  if (previous.length >= MAX_PER_WINDOW) return res.status(429).json({ error: 'espera' })
  previous.push(now)
  sent.set(key, previous)
  if (sent.size > 500) sent.clear() // keeps the Map from growing without bound

  const text = [
    'Mensaje desde el formulario de contacto de PcapAnalyzer',
    '',
    'Nombre: ' + (name || '(no indicado)'),
    'Email: ' + email,
    'Idioma de la página: ' + lang,
    '',
    message,
  ].join('\n')

  let r
  try {
    r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from: process.env.CONTACT_FROM || 'PcapAnalyzer <onboarding@resend.dev>',
        to: [to],
        reply_to: email,
        subject: 'Contacto PcapAnalyzer',
        text,
      }),
    })
  } catch {
    previous.pop()
    return res.status(502).json({ error: 'correo' })
  }
  if (!r.ok) {
    previous.pop()
    // Only Resend's error body (it carries no keys) goes to the function logs, never CONTACT_TO's value.
    const detail = await r.text().catch(() => '')
    console.error('resend_error', r.status, detail.slice(0, 300), 'to_len=' + to.length, 'to_at=' + to.includes('@'))
    return res.status(502).json({ error: 'correo', estado: r.status })
  }
  return res.status(202).json({ ok: true })
}
