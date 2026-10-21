import { useEffect, useState } from 'react'
import { useSettings } from '../settings'
import { isSupabaseConfigured, supabaseClient } from '../supabase'

// Compact settings control (top-right): theme and language toggles.
export default function SettingsBar() {
  const { t, theme, setTheme, lang, setLang, apiToken, setApiToken } = useSettings()
  const [userEmail, setUserEmail] = useState<string | null>(null)
  const [authError, setAuthError] = useState<string | null>(null)

  useEffect(() => {
    if (!supabaseClient) return
    supabaseClient.auth.getUser().then(({ data, error }) => {
      if (error) setAuthError(error.message)
      setUserEmail(data.user?.email ?? null)
    }).catch((error: unknown) => {
      setAuthError(error instanceof Error ? error.message : t('auth.failed'))
    })
    const { data: listener } = supabaseClient.auth.onAuthStateChange((_event, session) => {
      setUserEmail(session?.user.email ?? null)
    })
    return () => listener.subscription.unsubscribe()
  }, [t])

  async function signOut() {
    if (!supabaseClient) return
    try {
      const { error } = await supabaseClient.auth.signOut()
      if (error) setAuthError(error.message)
    } catch (error) {
      setAuthError(error instanceof Error ? error.message : t('auth.failed'))
    }
  }

  return (
    <div className="settings-bar">
      {isSupabaseConfigured ? (
        userEmail && (
          <div className="account-control">
            <span>{userEmail}</span>
            <button className="seg-btn" onClick={() => void signOut()}>
              {t('auth.signOut')}
            </button>
          </div>
        )
      ) : (
        <label className="api-token">
          <span>{t('settings.apiToken')}</span>
          <input
            aria-label={t('settings.apiToken')}
            autoComplete="off"
            type="password"
            value={apiToken}
            onChange={(event) => setApiToken(event.target.value.trim())}
            placeholder={t('settings.apiTokenPlaceholder')}
          />
          <span className={apiToken ? 'token-state ready' : 'token-state'}>
            {apiToken ? t('settings.tokenReady') : t('settings.tokenMissing')}
          </span>
        </label>
      )}
      {authError && <span role="alert">{authError}</span>}
      <div className="seg" role="group" aria-label={t('settings.theme')}>
        <button
          className={theme === 'light' ? 'seg-btn active' : 'seg-btn'}
          onClick={() => setTheme('light')}
          title={t('settings.light')}
        >
          ☀ {t('settings.light')}
        </button>
        <button
          className={theme === 'dark' ? 'seg-btn active' : 'seg-btn'}
          onClick={() => setTheme('dark')}
          title={t('settings.dark')}
        >
          ☾ {t('settings.dark')}
        </button>
      </div>
      <div className="seg" role="group" aria-label={t('settings.language')}>
        <button
          className={lang === 'es' ? 'seg-btn active' : 'seg-btn'}
          onClick={() => setLang('es')}
        >
          ES
        </button>
        <button
          className={lang === 'en' ? 'seg-btn active' : 'seg-btn'}
          onClick={() => setLang('en')}
        >
          EN
        </button>
      </div>
    </div>
  )
}
