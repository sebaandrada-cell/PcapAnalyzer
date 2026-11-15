import type { CaptureQuality as Quality } from '../api'
import { useSettings } from '../settings'

interface Props {
  quality: Quality | undefined
}

// Limits of the capture itself (duplicated frames, one-way capture, truncated
// frames...). Shown above the findings because it decides how far to trust
// them. Renders nothing for a clean capture.
export default function CaptureQuality({ quality }: Props) {
  const { t, lang } = useSettings()
  if (!quality || quality.notes.length === 0) return null

  return (
    <section className={`card quality quality-${quality.verdict}`} aria-labelledby="quality-title">
      <h2 className="card-title" id="quality-title">
        {t('quality.title')}
        <span className={`quality-badge quality-badge-${quality.verdict}`}>
          {t(`quality.verdict.${quality.verdict}`)}
        </span>
      </h2>
      <p className="card-sub">{t('quality.subtitle')}</p>
      <ul className="quality-notes">
        {quality.notes.map((note) => (
          <li key={note.code} className={`quality-note quality-note-${note.severity}`}>
            <strong>{(lang === 'en' && note.title_en) || note.title}</strong>
            <span>{(lang === 'en' && note.detail_en) || note.detail}</span>
          </li>
        ))}
      </ul>
    </section>
  )
}
