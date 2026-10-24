import type { AnalysisResult, TopTalker } from '../api'
import { formatBytes } from '../format'
import { useSettings } from '../settings'

interface Props {
  result: AnalysisResult
  names?: Map<string, string>
  onSelect: (talker: TopTalker) => void
}

export default function TopTalkers({ result, names, onSelect }: Props) {
  const { t } = useSettings()
  const talkers = result.conversations.top_talkers.slice(0, 6)
  // Hosts mentioned in issues get a warning mark, as in the mockup.
  const flagged = new Set<string>()
  for (const issue of result.issues) {
    for (const talker of talkers) {
      if (issue.conversation?.includes(talker.address)) flagged.add(talker.address)
    }
  }

  return (
    <div className="card">
      <h2 className="card-title">{t('talkers.title')}</h2>
      <ul className="row-list">
        {talkers.map((talker) => (
          <li
            key={talker.address}
            className="clickable"
            title={t('talkers.viewConvs')}
            onClick={() => onSelect(talker)}
          >
            <span className="mono">
              {talker.address}
              {flagged.has(talker.address) && <span className="warn-mark">⚠</span>}
              {names?.get(talker.address) && (
                <span className="resolved-name">{names.get(talker.address)}</span>
              )}
            </span>
            <span className="bytes">{formatBytes(talker.bytes_total)}</span>
          </li>
        ))}
      </ul>
      {result.tunnels.length > 0 && (
        <>
          <div className="section-label">{t('talkers.tunnels')}</div>
          <ul className="row-list">
            {result.tunnels.map((tunnel) => (
              <li key={`${tunnel.type}-${tunnel.peer_a}-${tunnel.peer_b}`}>
                <span className="mono">
                  {tunnel.type.toUpperCase()} {tunnel.peer_a} ⇄ {tunnel.peer_b}
                </span>
                <span className="bytes">{formatBytes(tunnel.bytes)}</span>
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  )
}
