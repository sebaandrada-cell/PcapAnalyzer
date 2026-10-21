import { Component, type ReactNode } from 'react'
import { useSettings } from '../settings'

// Without a boundary, any render error unmounts the whole tree and leaves a
// blank white page. This catches it and shows a recoverable message instead.

function Fallback({ message }: { message: string }) {
  const { t } = useSettings()
  return (
    <div className="boundary">
      <h1>{t('boundary.title')}</h1>
      <p>{t('boundary.body')}</p>
      {message && <pre className="boundary-detail">{message}</pre>}
      <button className="primary" onClick={() => window.location.reload()}>
        {t('boundary.reload')}
      </button>
    </div>
  )
}

interface State {
  error: Error | null
}

export default class ErrorBoundary extends Component<{ children: ReactNode }, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidCatch(error: Error) {
    // eslint-disable-next-line no-console
    console.error('PcapAnalyzer UI error:', error)
  }

  render() {
    if (this.state.error) return <Fallback message={this.state.error.message} />
    return this.props.children
  }
}
