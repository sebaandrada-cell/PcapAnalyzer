// Shared Cloudflare Turnstile loader (contact form and sign-in).
const SCRIPT_SRC = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit'

export type TurnstileApi = {
  render: (el: string | HTMLElement, opts: { sitekey: string; language?: string; callback?: (token: string) => void; 'expired-callback'?: () => void; 'error-callback'?: () => void }) => string
  reset: (id?: string) => void
  remove: (id?: string) => void
}
declare global {
  interface Window {
    turnstile?: TurnstileApi
  }
}

// Loads the Turnstile script only when a page that needs it opens (not on every visit).
export function loadTurnstile(): Promise<TurnstileApi> {
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
