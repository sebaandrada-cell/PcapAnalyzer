// The contact form only exists on our hosted beta, where VITE_TURNSTILE_SITE_KEY is set at build time.
// The self-hosted customer download has no /api/contacto, so it must not show a "Contact" link.
export const TURNSTILE_SITE_KEY = import.meta.env.VITE_TURNSTILE_SITE_KEY as string | undefined
export const CONTACT_ENABLED = Boolean(TURNSTILE_SITE_KEY)
