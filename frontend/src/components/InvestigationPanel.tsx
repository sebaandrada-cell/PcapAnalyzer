import { useCallback, useEffect, useMemo, useReducer, useRef, useState } from 'react'
import type { AnalysisResult } from '../api'
import { API_BASE, ChatHttpError, INVESTIGATE_SENTINEL, chatStream, deleteSession, getSession, patchSession } from '../api'
import { BUY_URL } from '../demo'
import { initialState, reduce, type Turn } from '../investigationState'
import { estimateCostUsd } from '../pricing'
import { useSettings } from '../settings'
import EvidenceText from './EvidenceText'
import SessionBar from './SessionBar'

interface Props {
  result: AnalysisResult
  demo: boolean
  /** Public demo: pre-generated report shown instead of calling the backend. */
  demoText?: string
  onShowPackets: (filter: string) => void
  onSelectPacket: (n: number) => void
  /** The automatic report, for the PDF (null until it exists). */
  onReportText: (text: string | null) => void
  onSessionDeleted: () => void
}

const MAX_SUGGESTIONS = 3

// The AI investigates the capture as soon as it is analyzed, then answers
// follow-up questions. All streaming/error state lives in the pure reducer.
export default function InvestigationPanel({
  result, demo, demoText, onShowPackets, onSelectPacket, onReportText, onSessionDeleted,
}: Props) {
  const { t, lang } = useSettings()
  const session = result.session ?? null
  const [state, dispatch] = useReducer(
    reduce,
    undefined,
    () => initialState(session?.id ?? null, session?.expires_at ?? null, session?.content_allowed ?? false),
  )
  const [draft, setDraft] = useState('')
  const [model, setModel] = useState<string | null>(null)
  const startedFor = useRef<string | null>(null)
  const abortRef = useRef<AbortController | null>(null)
  const reportRef = useRef('')

  const knownProtocols = useMemo(
    () => new Set(result.packet_list.rows.map((row) => row.protocol.toLowerCase())),
    [result.packet_list.rows],
  )

  // The model id only matters for the cost estimate.
  useEffect(() => {
    if (demo) return
    fetch(`${API_BASE}/health`)
      .then((r) => (r.ok ? r.json() : null))
      .then((h: { ai?: { model?: string | null } } | null) => setModel(h?.ai?.model ?? null))
      .catch(() => setModel(null))
  }, [demo])

  const refreshSession = useCallback(async () => {
    if (!session) return
    try {
      const info = await getSession(session.id)
      dispatch({ type: 'session', info })
    } catch {
      /* 404 after expiry is reported by the next turn */
    }
  }, [session])

  const send = useCallback(
    async (message: string, question: string | null) => {
      if (!session) return
      dispatch({ type: 'start', question })
      const controller = new AbortController()
      abortRef.current = controller
      if (question === null) reportRef.current = ''
      try {
        await chatStream(session.id, message, lang, {
          onToolStart: (d) => dispatch({ type: 'tool_start', ...d }),
          onToolEnd: (d) => dispatch({ type: 'tool_end', ...d }),
          onText: (delta) => {
            if (question === null) reportRef.current += delta
            dispatch({ type: 'text', delta })
          },
          onUsage: (u) =>
            dispatch({
              type: 'usage',
              usage: {
                input_tokens: u.input_tokens ?? 0,
                output_tokens: u.output_tokens ?? 0,
                cache_read_tokens: u.cache_read_tokens ?? 0,
                cache_write_tokens: u.cache_write_tokens ?? 0,
              },
            }),
          onDone: (d) => {
            dispatch({ type: 'done', limited: d.limited })
            if (question === null) onReportText(reportRef.current)
          },
          onError: (d) => dispatch({ type: 'error', code: d.code, message: d.message }),
        }, controller.signal)
      } catch (err) {
        if (err instanceof ChatHttpError) dispatch({ type: 'http_error', status: err.status, message: err.message })
        else dispatch({ type: 'interrupted' })
      } finally {
        abortRef.current = null
        void refreshSession()
      }
    },
    [session, lang, onReportText, refreshSession],
  )

  // Automatic investigation, once per session.
  useEffect(() => {
    if (!session || demo || startedFor.current === session.id) return
    startedFor.current = session.id
    void send(INVESTIGATE_SENTINEL, null)
  }, [session, demo, send])

  useEffect(() => () => abortRef.current?.abort(), [])

  const streaming = state.turns.some((turn) => turn.streaming)
  const blocked = state.blockedReason !== null
  const canAsk = Boolean(session) && !demo && !streaming && !blocked

  const ask = (question: string) => {
    const trimmed = question.trim()
    if (!trimmed || !canAsk) return
    setDraft('')
    void send(trimmed, trimmed)
  }

  const resend = (turn: Turn) => {
    if (streaming || blocked) return
    void send(turn.question ?? INVESTIGATE_SENTINEL, turn.question)
  }

  const toggleContent = async (next: boolean) => {
    if (!session) return
    try {
      const info = await patchSession(session.id, next)
      dispatch({ type: 'session', info })
    } catch {
      /* the bar keeps the previous value */
    }
  }

  const remove = async () => {
    abortRef.current?.abort()
    if (session) {
      try {
        await deleteSession(session.id)
      } catch {
        /* already gone */
      }
    }
    onReportText(null)
    onSessionDeleted()
  }

  const suggestions = useMemo(() => {
    if (state.turns.some((turn) => turn.question !== null)) return []
    return result.issues.slice(0, MAX_SUGGESTIONS).map((issue) => {
      const title = (lang === 'en' && issue.title_en) || issue.title
      return t('investigation.suggestion', { title })
    })
  }, [result.issues, lang, state.turns, t])

  const totalTokens = state.totalUsage.input_tokens + state.totalUsage.output_tokens
  const costUsd = model ? estimateCostUsd(state.totalUsage, model) : null

  const renderTurn = (turn: Turn) => {
    const open = turn.steps.filter((step) => !step.done).length
    return (
      <div className="turn" key={turn.id}>
        {turn.question !== null && (
          <p className="question">
            <span>{t('investigation.you')}</span>
            {turn.question}
          </p>
        )}
        {turn.steps.length > 0 && (
          <details className="steps" open={turn.streaming}>
            <summary>
              {turn.streaming && open > 0 ? t('investigation.investigating') : t('investigation.steps', { n: turn.steps.length })}
            </summary>
            <ul>
              {turn.steps.map((step, i) => (
                <li key={i} className={step.isError ? 'error' : step.done ? '' : 'running'}>
                  <code>{step.label}</code>
                  {step.done && step.ms !== undefined && ` · ${step.ms} ms`}
                  {step.truncated && ' · ✂'}
                </li>
              ))}
            </ul>
          </details>
        )}
        {turn.text ? (
          <EvidenceText text={turn.text} knownProtocols={knownProtocols} onShowPackets={onShowPackets} onSelectPacket={onSelectPacket} />
        ) : (
          turn.streaming && turn.steps.length === 0 && <p className="steps">{t('investigation.thinking')}</p>
        )}
        {turn.limited && <p className="turn-note">{t('investigation.limited')}</p>}
        {turn.error && <p className="turn-error">{turn.error.message}</p>}
        {turn.interrupted && (
          <p className="turn-error">
            {t('investigation.interrupted')}{' '}
            <button className="chip small" onClick={() => resend(turn)} disabled={streaming || blocked}>
              {t('investigation.resend')}
            </button>
          </p>
        )}
      </div>
    )
  }

  return (
    <section className="investigation" aria-label={t('investigation.title')}>
      <h2>{t('investigation.title')}</h2>
      <p className="card-sub">{t('investigation.subtitle')}</p>
      <SessionBar
        expiresAt={state.expiresAt}
        expired={state.expired}
        contentAllowed={state.contentAllowed}
        onToggleContent={toggleContent}
        costUsd={costUsd}
        totalTokens={totalTokens}
        onDelete={remove}
        onExpired={() => dispatch({ type: 'expired' })}
        demo={demo}
      />
      {demo && demoText !== undefined && (
        <>
          <EvidenceText text={demoText} knownProtocols={knownProtocols} onShowPackets={onShowPackets} onSelectPacket={onSelectPacket} />
          <p className="blocked-note">
            {t('investigation.demoNote')} {t('investigation.demoChat')}{' '}
            <a className="demo-buy" href={BUY_URL} target="_blank" rel="noopener noreferrer">
              {t('demo.buy')}
            </a>
          </p>
        </>
      )}
      {!demo && !session && <p className="blocked-note">{t('investigation.unavailable')}</p>}
      {state.notice === 'already_investigated' && <p className="turn-note">{t('investigation.alreadyInvestigated')}</p>}
      {state.turns.map(renderTurn)}
      {state.blockedReason === 'expired' && <p className="blocked-note">{t('investigation.blockedExpired')}</p>}
      {state.blockedReason === 'tokens' && <p className="blocked-note">{t('investigation.blockedTokens')}</p>}
      {canAsk && suggestions.length > 0 && !streaming && (
        <div className="suggestions" aria-label={t('investigation.suggestions')}>
          {suggestions.map((question) => (
            <button key={question} className="chip small" onClick={() => ask(question)}>
              {question}
            </button>
          ))}
        </div>
      )}
      {session && !demo && (
        <div className="chat-input">
          <textarea
            value={draft}
            placeholder={t('investigation.placeholder')}
            disabled={!canAsk}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault()
                ask(draft)
              }
            }}
          />
          <button className="primary" disabled={!canAsk || draft.trim().length === 0} onClick={() => ask(draft)}>
            {streaming ? t('investigation.sending') : t('investigation.send')}
          </button>
        </div>
      )}
    </section>
  )
}
