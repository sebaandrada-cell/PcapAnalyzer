import type { AnalysisResult } from '../api'
import { formatBytes, formatDuration, formatNumber } from '../format'
import { useSettings } from '../settings'

function absTime(epoch: number | null, lang: string): string {
  if (epoch == null) return '—'
  return new Date(epoch * 1000).toLocaleString(lang === 'es' ? 'es-ES' : 'en-US')
}

// Wireshark "Capture File Properties" — derived entirely from existing data.
export default function CaptureProperties({ result }: { result: AnalysisResult }) {
  const { t, lang } = useSettings()
  const { file, summary } = result
  const avgSize = summary.packets ? Math.round(summary.bytes / summary.packets) : 0

  const rows: [string, string][] = [
    [t('capture.filename'), file.name],
    [t('capture.size'), formatBytes(file.size_bytes)],
    [t('capture.packets'), formatNumber(summary.packets)],
    [t('capture.elapsed'), formatDuration(summary.duration_seconds)],
    [t('capture.firstPacket'), absTime(summary.start_time_epoch, lang)],
    [t('capture.lastPacket'), absTime(summary.end_time_epoch, lang)],
    [t('capture.avgSize'), `${avgSize} B`],
    [t('capture.avgRate'), formatNumber(summary.avg_packets_per_second)],
    [t('capture.avgBitrate'), formatBytes(summary.avg_bytes_per_second)],
  ]

  return (
    <div className="card" style={{ marginBottom: 20 }}>
      <h2 className="card-title">{t('capture.title')}</h2>
      <div className="kv-grid">
        {rows.map(([label, value]) => (
          <div key={label}>
            <div className="k">{label}</div>
            <div className="v">{value}</div>
          </div>
        ))}
      </div>
    </div>
  )
}
