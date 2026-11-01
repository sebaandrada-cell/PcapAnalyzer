import { useEffect, useRef, useState } from 'react'
import type { FormEvent } from 'react'
import { TURNSTILE_SITE_KEY } from '../contactConfig'
import { useSettings } from '../settings'

// Contact form (no public email anywhere). It posts to the Vercel function /api/contacto,
// which checks Cloudflare Turnstile and forwards the message to a mailbox kept in an env var.
// Reached through the `#contacto` fragment so it works before signing in.

const SITE_KEY = TURNSTILE_SITE_KEY
const SCRIPT_SRC = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit'
const MAX_MESSAGE = 2000

type TurnstileApi = {
  render: (el: string | HTMLElement, opts: { sitekey: string; language?: string; callback?: (token: string) => void; 'expired-callback'?: () => void; 'error-callback'?: () => void }) => string
  reset: (id?: string) => void
  remove: (id?: string) => void
}
declare global {
  interface Window {
    turnstile?: TurnstileApi
  }
}

type Status = 'idle' | 'sending' | 'sent' | 'error'

// Loads the Turnstile script only when this page opens (not on every visit).
function loadTurnstile(): Promise<TurnstileApi> {
  return new Promise((resolve, reject) => {
    if (window.turnstile) return resolve(window.turnstile)
    const existing = document.querySelector<HTMLScriptElement>(`script[src="${SCRIPT_SRC}"]`)
    const script = existing ?? document.createElement('script')
    script.addEventListener('load', () => (window.turnstile ? resolve(window.turnstile) : reject(new Error('turnstile'))))
    script.addEventListener('error', () => reject(new Error('turnstile')))
    if (!existing) {
      script.src = SCRIPT_SRC
      script.async = true
      document.head.appendChild(script)
    }
  })
}

export default function ContactForm() {
  const { t, lang } = useSettings()
  const [status, setStatus] = useState<Status>('idle')
  const [errorKey, setErrorKey] = useState('')
  const [token, setToken] = useState('')
  const widget = useRef<HTMLDivElement>(null)
  const widgetId = useRef<string | undefined>(undefined)

  useEffect(() => {
    if (!SITE_KEY || !widget.current) return
    let cancelled = false
    loadTurnstile()
      .then((api) => {
        if (cancelled || !widget.current) return
        widgetId.current = api.render(widget.current, {
          sitekey: SITE_KEY,
          language: lang,
          callback: setToken,
          'expired-callback': () => setToken(''),
          'error-callback': () => setToken(''),
        })
      })
      .catch(() => setErrorKey('contact.errCaptcha'))
    return () => {
      cancelled = true
      if (widgetId.current) window.turnstile?.remove(widgetId.current)
      widgetId.current = undefined
    }
  }, [lang])

  async function submit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault()
    const form = e.currentTarget
    const data = new FormData(form)
    const email = String(data.get('email') ?? '').trim()
    const message = String(data.get('mensaje') ?? '').trim()
    if (!email || message.length < 5) {
      setErrorKey('contact.errFields')
      return
    }
    if (!token) {
      setErrorKey('contact.errCaptcha')
      return
    }
    setStatus('sending')
    setErrorKey('')
    try {
      const res = await fetch('/api/contacto', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email,
          nombre: String(data.get('nombre') ?? '').trim(),
          mensaje: message,
          web: String(data.get('web') ?? ''),
          idioma: lang,
          'cf-turnstile-response': token,
        }),
      })
      if (res.status === 202) {
        setStatus('sent')
        form.reset()
        return
      }
      const body = (await res.json().catch(() => ({}))) as { error?: string }
      const map: Record<string, string> = {
        email: 'contact.errFields',
        mensaje: 'contact.errFields',
        captcha: 'contact.errCaptcha',
        espera: 'contact.errWait',
        no_configurado: 'contact.errUnavailable',
      }
      setErrorKey(map[body.error ?? ''] ?? 'contact.errGeneric')
      setStatus('error')
    } catch {
      setErrorKey('contact.errGeneric')
      setStatus('error')
    }
    setToken('')
    if (widgetId.current) window.turnstile?.reset(widgetId.current)
  }

  return (
    <main className="policy">
      <a className="policy-back" href="#">
        ← {t('cookies.back')}
      </a>
      <h1>{t('contact.title')}</h1>
      <p>{t('contact.intro')}</p>
      {!SITE_KEY ? (
        <p className="contact-error" role="alert">
          {t('contact.errUnavailable')}
        </p>
      ) : status === 'sent' ? (
        <p className="auth-message" role="status">
          {t('contact.sent')}
        </p>
      ) : (
        <form className="auth-card contact-form" onSubmit={submit} noValidate>
          <label>
            {t('contact.name')}
            <input name="nombre" type="text" maxLength={80} autoComplete="name" />
          </label>
          <label>
            {t('contact.email')}
            <input name="email" type="email" maxLength={200} autoComplete="email" required />
          </label>
          <label>
            {t('contact.message')}
            <textarea name="mensaje" rows={6} maxLength={MAX_MESSAGE} required />
          </label>
          <div className="contact-hp" aria-hidden="true">
            <label>
              Web
              <input name="web" type="text" tabIndex={-1} autoComplete="off" />
            </label>
          </div>
          <div ref={widget} />
          <p className="sub">{t('contact.privacy')}</p>
          {errorKey && (
            <p className="contact-error" role="alert">
              {t(errorKey)}
            </p>
          )}
          <button type="submit" className="primary" disabled={status === 'sending'}>
            {status === 'sending' ? t('contact.sending') : t('contact.send')}
          </button>
        </form>
      )}
    </main>
  )
}
