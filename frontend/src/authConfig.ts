// Shows "Continue with Google" in the sign-in screen. Turn it on (VITE_GOOGLE_LOGIN=1) only
// after the Google provider is enabled in Supabase; otherwise the button would fail.
export const GOOGLE_LOGIN = import.meta.env.VITE_GOOGLE_LOGIN === '1'
