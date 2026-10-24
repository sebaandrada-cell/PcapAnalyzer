import { useMemo, useState } from 'react'
import type { ExpertEntry, ExpertSeverity } from '../api'
import { useSettings } from '../settings'

const SEVERITIES: ExpertSeverity[] = ['error', 'warning', 'note', 'chat']

interface Props {
  entries: ExpertEntry[]
  onShowPacket: (packetNumber: number) => void
}

// Wireshark's "Expert Information": everything the dissectors flagged as unusual,
// grouped by message. Only shown when the capture has something to report.
export default function ExpertInfo({ entries, onShowPacket }: Props) {
  const { t } = useSettings()
  const [severity, setSeverity] = useState<ExpertSeverity | null>(null)

  const counts = useMemo(() => {
    const result: Record<ExpertSeverity, number> = { error: 0, warning: 0, note: 0, chat: 0 }
    for (const entry of entries) result[entry.severity] += entry.count
    return result
  }, [entries])

  if (entries.length === 0) return null
  const visible = severity ? entries.filter((entry) => entry.severity === severity) : entries
  const groupLabel = (group: string) => {
    const key = `expert.group.${group}`
    const label = t(key)
    return label === key ? group : label
  }

  return (
    <div className="card" style={{ marginBottom: 20 }}>
      <h2 className="card-title">{t('expert.title')}</h2>
      <p className="card-sub">{t('expert.subtitle')}</p>
      <div className="proto-chips">
        <button className={severity === null ? 'chip active' : 'chip'} onClick={() => setSeverity(null)}>
          {t('expert.all')} ({entries.length})
        </button>
        {SEVERITIES.filter((level) => counts[level] > 0).map((level) => (
          <button
            key={level}
            className={severity === level ? `chip active sev-${level}` : `chip sev-${level}`}
            onClick={() => setSeverity(severity === level ? null : level)}
          >
            {t(`expert.${level}`)} ({counts[level]})
          </button>
        ))}
      </div>
      <div className="table-scroll">
        <table className="data-table">
          <thead>
            <tr>
              <th>{t('expert.colSeverity')}</th>
              <th>{t('expert.colGroup')}</th>
              <th>{t('expert.colSummary')}</th>
              <th>{t('expert.colCount')}</th>
              <th>{t('expert.colFirst')}</th>
            </tr>
          </thead>
          <tbody>
            {visible.map((entry) => (
              <tr key={`${entry.severity}-${entry.group}-${entry.summary}`}>
                <td>
                  <span className={`expert-badge sev-${entry.severity}`}>{t(`expert.${entry.severity}`)}</span>
                </td>
                <td>{groupLabel(entry.group)}</td>
                <td>{entry.summary}</td>
                <td className="num">{entry.count}</td>
                <td>
                  <button
                    className="link mono"
                    onClick={() => onShowPacket(entry.first_packet)}
                    title={t('expert.goto', { n: entry.first_packet })}
                  >
                    #{entry.first_packet}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
