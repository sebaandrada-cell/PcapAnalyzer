import { useEffect, useState } from 'react'

export const COOKIES_HASH = '#cookies'

/** True while the URL fragment is `#cookies`; follows back/forward and link clicks. */
export function useCookiesRoute(): boolean {
  const [active, setActive] = useState(() => window.location.hash === COOKIES_HASH)
  useEffect(() => {
    const onChange = () => setActive(window.location.hash === COOKIES_HASH)
    window.addEventListener('hashchange', onChange)
    return () => window.removeEventListener('hashchange', onChange)
  }, [])
  return active
}
