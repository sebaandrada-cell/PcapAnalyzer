import { useEffect, useRef, useState, type FormEvent, type ReactNode } from 'react'
import type { Session } from '@supabase/supabase-js'
import { GOOGLE_LOGIN } from '../authConfig'
import { TURNSTILE_SITE_KEY } from '../contactConfig'
import { useSettings } from '../settings'
import { supabaseClient } from '../supabase'
import { loadTurnstile } from '../turnstile'
import SettingsBar from './SettingsBar'

interface Props {
  children: ReactNode
}

export default function SupabaseAuthGate({ children }: Props) {
  const { t, lang } = useSettings()
  const [session, setSession] = useState<Session | null>(null)
  const [loading, setLoading] = useState(true)
  const [signUp, setSignUp] = useState(false)
  const [busy, setBusy] = useState(false)
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [message, setMessage] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [captcha, setCaptcha] = useState('')
  const captchaBox = useRef<HTMLDivElement>(null)
  const captchaId = useRef<string | undefined>(undefined)

  useEffect(() => {
    if (!supabaseClient) return
    let active = true
    supabaseClient.auth.getSession().then(({ data, error: sessionError }) => {
      if (!active) return
      if (sessionError) setError(sessionError.message)
      setSession(data.session)
      setLoading(false)
    }).catch((sessionError: unknown) => {
      if (!active) return
      setError(sessionError instanceof Error ? sessionError.message : t('auth.failed'))
      setLoading(false)
    })
    const { data: listener } = supabaseClient.auth.onAuthStateChange((_event, next) => {
      if (active) setSession(next)
    })
    return () => {
      active = false
      listener.subscription.unsubscribe()
    }
  }, [t])

  // Supabase CAPTCHA protection (Auth > Attack Protection) expects a Turnstile token on
  // sign-in and sign-up. The widget only shows when a site key is configured.
  const showForm = !loading && !session
  useEffect(() => {
    const siteKey = TURNSTILE_SITE_KEY
    if (!siteKey || !showForm || !captchaBox.current) return
    let cancelled = false
    loadTurnstile()
      .then((api) => {
        if (cancelled || !captchaBox.current) return
        captchaId.current = api.render(captchaBox.current, {
          sitekey: siteKey,
          language: lang,
          callback: setCaptcha,
          'expired-callback': () => setCaptcha(''),
          'error-callback': () => setCaptcha(''),
        })
      })
      .catch(() => setError(t('auth.captchaFailed')))
    return () => {
      cancelled = true
      if (captchaId.current) window.turnstile?.remove(captchaId.current)
      captchaId.current = undefined
    }
  }, [showForm, lang, t])

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!supabaseClient) return
    if (TURNSTILE_SITE_KEY && !captcha) {
      setError(t('auth.captchaRequired'))
      return
    }
    const options = captcha ? { captchaToken: captcha } : undefined
    setBusy(true)
    setError(null)
    setMessage(null)
    try {
      const response = signUp
        ? await supabaseClient.auth.signUp({ email, password, options })
        : await supabaseClient.auth.signInWithPassword({ email, password, options })
      if (response.error) throw response.error
      if (signUp && !response.data.session) {
        setMessage(t('auth.confirmEmail'))
      }
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : t('auth.failed'))
    } finally {
      setBusy(false)
      // A Turnstile token is single-use.
      setCaptcha('')
      if (captchaId.current) window.turnstile?.reset(captchaId.current)
    }
  }

  async function handleGoogle() {
    if (!supabaseClient) return
    setBusy(true)
    setError(null)
    setMessage(null)
    const { error: oauthError } = await supabaseClient.auth.signInWithOAuth({
      provider: 'google',
      options: { redirectTo: `${window.location.origin}/` },
    })
    // On success the browser leaves for Google; we only get here when it failed.
    if (oauthError) {
      setError(oauthError.message || t('auth.failed'))
      setBusy(false)
    }
  }

  if (loading) {
    return (
      <>
        <SettingsBar />
        <div className="upload-wrap">
          <p className="sub">{t('auth.loading')}</p>
        </div>
      </>
    )
  }

  if (!session) {
    return (
      <>
        <SettingsBar />
        <main className="auth-wrap">
          <form className="auth-card" onSubmit={handleSubmit}>
            <h1>{t(signUp ? 'auth.signUpTitle' : 'auth.signInTitle')}</h1>
            <p className="sub">{t('auth.description')}</p>
            {GOOGLE_LOGIN && (
              <>
                <button className="auth-google" type="button" disabled={busy} onClick={handleGoogle}>
                  {t('auth.google')}
                </button>
                <div className="auth-sep" role="separator">{t('auth.or')}</div>
              </>
            )}
            <label>
              <span>{t('auth.email')}</span>
              <input
                autoComplete="email"
                type="email"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                required
              />
            </label>
            <label>
              <span>{t('auth.password')}</span>
              <input
                autoComplete={signUp ? 'new-password' : 'current-password'}
                type="password"
                minLength={8}
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                required
              />
            </label>
            {TURNSTILE_SITE_KEY && <div ref={captchaBox} className="auth-captcha" />}
            {error && <div className="upload-error" role="alert">{error}</div>}
            {message && <div className="auth-message" role="status">{message}</div>}
            <button type="submit" disabled={busy}>
              {t(busy ? 'auth.working' : signUp ? 'auth.signUp' : 'auth.signIn')}
            </button>
            <button
              className="auth-switch"
              type="button"
              onClick={() => {
                setSignUp(!signUp)
                setError(null)
                setMessage(null)
              }}
            >
              {t(signUp ? 'auth.haveAccount' : 'auth.needAccount')}
            </button>
            <a className="demo-link" href="#demo">
              {t('auth.tryDemo')}
            </a>
          </form>
        </main>
      </>
    )
  }

  return <>{children}</>
}
