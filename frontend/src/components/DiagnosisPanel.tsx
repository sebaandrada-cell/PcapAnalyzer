import { useState } from 'react'
import type { AnalysisResult } from '../api'
import { diagnose } from '../api'
import { useSettings } from '../settings'

// Minimal markdown rendering for the diagnosis: paragraphs + **bold**.
function renderDiagnosis(text: string) {
  return text.split(/\n{2,}/).map((paragraph, index) => {
    // A paragraph wrapped in underscores is a note (the demo-mode mark): italic,
    // without the literal underscores.
    const note = /^_([\s\S]+)_$/.exec(paragraph.trim())
    if (note) {
      return (
        <p key={index}>
          <em>{note[1]}</em>
        </p>
      )
    }
    return (
      <p key={index}>
        {paragraph.split(/(\*\*[^*]+\*\*)/g).map((part, partIndex) =>
          part.startsWith('**') && part.endsWith('**') ? (
            <strong key={partIndex}>{part.slice(2, -2)}</strong>
          ) : (
            part
          ),
        )}
      </p>
    )
  })
}

interface Props {
  analysis: AnalysisResult
  onGenerated?: (diagnosis: string) => void
  /** Public demo: pre-computed text shown instead of calling the backend. */
  demoText?: string
}

export default function DiagnosisPanel({ analysis, onGenerated, demoText }: Props) {
  const { t, lang } = useSettings()
  const [text, setText] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const generate = () => {
    if (demoText !== undefined) {
      setText(demoText)
      onGenerated?.(demoText)
      return
    }
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
          {demoText === undefined && (
            <div className="diagnosis-actions">
              <button onClick={generate}>{t('diagnosis.regenerate')}</button>
            </div>
          )}
        </>
      )}
    </div>
  )
}
