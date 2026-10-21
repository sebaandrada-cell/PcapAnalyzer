import { useEffect, useState, type FormEvent, type ReactNode } from 'react'
import type { Session } from '@supabase/supabase-js'
import { useSettings } from '../settings'
import { supabaseClient } from '../supabase'
import SettingsBar from './SettingsBar'

interface Props {
  children: ReactNode
}

export default function SupabaseAuthGate({ children }: Props) {
  const { t } = useSettings()
  const [session, setSession] = useState<Session | null>(null)
  const [loading, setLoading] = useState(true)
  const [signUp, setSignUp] = useState(false)
  const [busy, setBusy] = useState(false)
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [message, setMessage] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)

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

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!supabaseClient) return
    setBusy(true)
    setError(null)
    setMessage(null)
    try {
      const response = signUp
        ? await supabaseClient.auth.signUp({ email, password })
        : await supabaseClient.auth.signInWithPassword({ email, password })
      if (response.error) throw response.error
      if (signUp && !response.data.session) {
        setMessage(t('auth.confirmEmail'))
      }
    } catch (submitError) {
      setError(submitError instanceof Error ? submitError.message : t('auth.failed'))
    } finally {
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
          </form>
        </main>
      </>
    )
  }

  return <>{children}</>
}
