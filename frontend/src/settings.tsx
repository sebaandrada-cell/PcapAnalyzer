import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { translate, type Lang } from './i18n'
import { setFormatLang } from './format'

type Theme = 'light' | 'dark'

interface Settings {
  lang: Lang
  theme: Theme
  apiToken: string
  setLang: (lang: Lang) => void
  setTheme: (theme: Theme) => void
  setApiToken: (token: string) => void
  t: (key: string, params?: Record<string, string | number>) => string
}

const SettingsContext = createContext<Settings | null>(null)

function initialLang(): Lang {
  const stored = localStorage.getItem('pcap.lang')
  return stored === 'en' ? 'en' : 'es'
}

function initialTheme(): Theme {
  const stored = localStorage.getItem('pcap.theme')
  if (stored === 'dark' || stored === 'light') return stored
  return window.matchMedia?.('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
}

export function SettingsProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(initialLang)
  const [theme, setThemeState] = useState<Theme>(initialTheme)
  const [apiToken, setApiTokenState] = useState(() => sessionStorage.getItem('pcap.apiToken') ?? '')

  // Keep the <html data-theme> attribute and number-formatting locale in sync.
  useEffect(() => {
    document.documentElement.dataset.theme = theme
  }, [theme])
  useEffect(() => {
    setFormatLang(lang)
    document.documentElement.lang = lang
  }, [lang])

  const setLang = useCallback((next: Lang) => {
    localStorage.setItem('pcap.lang', next)
    setLangState(next)
  }, [])
  const setTheme = useCallback((next: Theme) => {
    localStorage.setItem('pcap.theme', next)
    setThemeState(next)
  }, [])
  const setApiToken = useCallback((next: string) => {
    if (next) sessionStorage.setItem('pcap.apiToken', next)
    else sessionStorage.removeItem('pcap.apiToken')
    setApiTokenState(next)
  }, [])

  const value = useMemo<Settings>(
    () => ({
      lang,
      theme,
      apiToken,
      setLang,
      setTheme,
      setApiToken,
      t: (key, params) => translate(lang, key, params),
    }),
    [lang, theme, apiToken, setLang, setTheme, setApiToken],
  )

  return <SettingsContext.Provider value={value}>{children}</SettingsContext.Provider>
}

export function useSettings(): Settings {
  const ctx = useContext(SettingsContext)
  if (!ctx) throw new Error('useSettings must be used within SettingsProvider')
  return ctx
}
