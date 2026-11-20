// Locale-aware formatting helpers shared by the dashboard components.
// The active language is set by the settings provider (setFormatLang), so
// callers stay pure and don't have to thread the locale everywhere.

import type { Lang } from './i18n'

let activeLang: Lang = 'es'

export function setFormatLang(lang: Lang): void {
  activeLang = lang
}

export function getFormatLang(): Lang {
  return activeLang
}

function decimal(value: number, digits: number): string {
  const fixed = value.toFixed(digits)
  return activeLang === 'es' ? fixed.replace('.', ',') : fixed
}

/** Locale-aware fixed-decimal (comma in es, dot in en). */
export function formatDecimal(value: number, digits: number): string {
  return decimal(value, digits)
}

export function formatNumber(value: number): string {
  return new Intl.NumberFormat(activeLang === 'es' ? 'es-ES' : 'en-US').format(value)
}

export function formatBytes(value: number): string {
  if (value >= 1024 ** 3) return `${decimal(value / 1024 ** 3, 1)} GB`
  if (value >= 1024 ** 2) return `${decimal(value / 1024 ** 2, 1)} MB`
  if (value >= 1024) return `${decimal(value / 1024, 1)} KB`
  return `${value} B`
}

export function formatDuration(seconds: number): string {
  if (seconds < 1) return `${Math.round(seconds * 1000)} ms`
  if (seconds < 60) return `${seconds % 1 === 0 ? seconds : decimal(seconds, 1)} s`
  const minutes = Math.floor(seconds / 60)
  const rest = Math.round(seconds % 60)
  if (minutes < 60) return `${minutes}m ${rest.toString().padStart(2, '0')}s`
  const hours = Math.floor(minutes / 60)
  return `${hours}h ${(minutes % 60).toString().padStart(2, '0')}m`
}

/** Axis tick for a time offset in seconds ("45s", "4m", "1h10m"). */
export function formatTick(t: number, total: number): string {
  if (total <= 180) return `${t}s`
  if (total <= 3600 * 3) {
    const minutes = Math.floor(t / 60)
    return t % 60 === 0 ? `${minutes}m` : `${minutes}m${Math.round(t % 60)}s`
  }
  const hours = Math.floor(t / 3600)
  const minutes = Math.round((t % 3600) / 60)
  return minutes === 0 ? `${hours}h` : `${hours}h${minutes}m`
}
