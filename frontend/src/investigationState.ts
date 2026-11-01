// State of the investigation panel as a pure reducer, so the streaming
// lifecycle, errors and session changes are testable without React.
// `node --test src/investigationState.test.ts`.
import { EMPTY_USAGE, addUsage, type Usage } from './pricing.ts'

export interface Step {
  name: string
  label: string
  ms?: number
  isError?: boolean
  truncated?: boolean
  done: boolean
}

export interface Turn {
  id: number
  question: string | null // null = the automatic investigation
  text: string
  steps: Step[]
  usage?: Usage
  limited: boolean
  error?: { code: string; message: string }
  interrupted: boolean
  streaming: boolean
}

export interface PanelState {
  turns: Turn[]
  sessionId: string | null
  expiresAt: number | null
  contentAllowed: boolean
  expired: boolean
  totalUsage: Usage
  investigated: boolean
  blockedReason: 'expired' | 'tokens' | null
  notice: 'already_investigated' | null
}

export type Action =
  | { type: 'start'; question: string | null }
  | { type: 'tool_start'; name: string; label: string }
  | { type: 'tool_end'; name: string; ms: number; is_error: boolean; truncated: boolean }
  | { type: 'text'; delta: string }
  | { type: 'usage'; usage: Usage }
  | { type: 'done'; limited: boolean }
  | { type: 'error'; code: string; message: string }
  | { type: 'interrupted' }
  | { type: 'http_error'; status: number; message: string }
  | { type: 'session'; info: { expires_at: number; content_allowed: boolean } }
  | { type: 'expired' }
  | { type: 'reset' }

export function initialState(sessionId: string | null, expiresAt: number | null, contentAllowed: boolean): PanelState {
  return {
    turns: [],
    sessionId,
    expiresAt,
    contentAllowed,
    expired: false,
    totalUsage: EMPTY_USAGE,
    investigated: false,
    blockedReason: null,
    notice: null,
  }
}

function updateLast(state: PanelState, change: (turn: Turn) => Turn): PanelState {
  if (state.turns.length === 0) return state
  const turns = state.turns.slice()
  turns[turns.length - 1] = change(turns[turns.length - 1])
  return { ...state, turns }
}

export function reduce(state: PanelState, action: Action): PanelState {
  switch (action.type) {
    case 'start':
      return {
        ...state,
        notice: null,
        turns: [
          ...state.turns,
          { id: Date.now() + state.turns.length, question: action.question, text: '', steps: [], limited: false, interrupted: false, streaming: true },
        ],
      }
    case 'tool_start':
      return updateLast(state, (turn) => ({
        ...turn,
        steps: [...turn.steps, { name: action.name, label: action.label, done: false }],
      }))
    case 'tool_end':
      return updateLast(state, (turn) => {
        const index = turn.steps.findIndex((step) => step.name === action.name && !step.done)
        if (index === -1) return turn
        const steps = turn.steps.slice()
        steps[index] = { ...steps[index], done: true, ms: action.ms, isError: action.is_error, truncated: action.truncated }
        return { ...turn, steps }
      })
    case 'text':
      return updateLast(state, (turn) => ({ ...turn, text: turn.text + action.delta }))
    case 'usage':
      return {
        ...updateLast(state, (turn) => ({ ...turn, usage: action.usage })),
        totalUsage: addUsage(state.totalUsage, action.usage),
      }
    case 'done': {
      const last = state.turns[state.turns.length - 1]
      const next = updateLast(state, (turn) => ({ ...turn, streaming: false, limited: action.limited }))
      return last && last.question === null ? { ...next, investigated: true } : next
    }
    case 'error': {
      const next = updateLast(state, (turn) => ({
        ...turn,
        streaming: false,
        error: { code: action.code, message: action.message },
      }))
      if (action.code === 'session_expired') return { ...next, expired: true, blockedReason: 'expired' }
      if (action.code === 'session_tokens') return { ...next, blockedReason: 'tokens' }
      return next
    }
    case 'interrupted':
      return updateLast(state, (turn) => ({ ...turn, streaming: false, interrupted: true }))
    case 'http_error': {
      const last = state.turns[state.turns.length - 1]
      if (last && last.question === null && action.status === 409) {
        return { ...state, turns: state.turns.slice(0, -1), investigated: true, notice: 'already_investigated' }
      }
      const next = updateLast(state, (turn) => ({
        ...turn,
        streaming: false,
        error: { code: `http_${action.status}`, message: action.message },
      }))
      return action.status === 404 ? { ...next, expired: true, blockedReason: 'expired' } : next
    }
    case 'session':
      return { ...state, expiresAt: action.info.expires_at, contentAllowed: action.info.content_allowed }
    case 'expired':
      return { ...state, expired: true, blockedReason: 'expired' }
    case 'reset':
      return initialState(null, null, false)
    default:
      return state
  }
}
