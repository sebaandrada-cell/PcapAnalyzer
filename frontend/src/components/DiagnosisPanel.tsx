import { useState } from 'react'
import type { AnalysisResult } from '../api'
import { diagnose } from '../api'
import { useSettings } from '../settings'

// Minimal markdown rendering for the diagnosis: paragraphs + **bold**.
function renderDiagnosis(text: string) {
  return text.split(/\n{2,}/).map((paragraph, index) => (
    <p key={index}>
      {paragraph.split(/(\*\*[^*]+\*\*)/g).map((part, partIndex) =>
        part.startsWith('**') && part.endsWith('**') ? (
          <strong key={partIndex}>{part.slice(2, -2)}</strong>
        ) : (
          part
        ),
      )}
    </p>
  ))
}

interface Props {
  analysis: AnalysisResult
  onGenerated?: (diagnosis: string) => void
}

export default function DiagnosisPanel({ analysis, onGenerated }: Props) {
  const { t, lang } = useSettings()
  const [text, setText] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const generate = () => {
    setLoading(true)
    setError(null)
    diagnose(analysis, lang)
      .then((response) => {
        setText(response.diagnosis)
        onGenerated?.(response.diagnosis)
      })
      .catch((err: Error) => setError(err.message))
      .finally(() => setLoading(false))
  }

  return (
    <div className="diagnosis">
      <h2>{t('diagnosis.title')}</h2>
      {text === null && !loading && !error && (
        <>
          <p>{t('diagnosis.intro')}</p>
          <div className="diagnosis-actions">
            <button className="primary" onClick={generate}>
              {t('diagnosis.generate')}
            </button>
          </div>
        </>
      )}
      {loading && <p>{t('diagnosis.loading')}</p>}
      {error && (
        <>
          <p className="diagnosis-error">{error}</p>
          <div className="diagnosis-actions">
            <button onClick={generate}>{t('common.retry')}</button>
          </div>
        </>
      )}
      {text !== null && !loading && !error && (
        <>
          <div className="diagnosis-text">{renderDiagnosis(text)}</div>
          <div className="diagnosis-actions">
            <button onClick={generate}>{t('diagnosis.regenerate')}</button>
          </div>
        </>
      )}
    </div>
  )
}
