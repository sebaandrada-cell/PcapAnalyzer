import { useEffect, useState } from 'react'

export const COOKIES_HASH = '#cookies'

export const CONTACT_HASH = '#contacto'

/** True while the URL fragment equals `hash`; follows back/forward and link clicks. */
function useHashRoute(hash: string): boolean {
  const [active, setActive] = useState(() => window.location.hash === hash)
  useEffect(() => {
    const onChange = () => setActive(window.location.hash === hash)
    window.addEventListener('hashchange', onChange)
    return () => window.removeEventListener('hashchange', onChange)
  }, [hash])
  return active
}

/** True while the URL fragment is `#cookies`. */
export function useCookiesRoute(): boolean {
  return useHashRoute(COOKIES_HASH)
}

/** True while the URL fragment is `#contacto`. */
export function useContactRoute(): boolean {
  return useHashRoute(CONTACT_HASH)
}
