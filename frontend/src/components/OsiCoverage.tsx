import { useSettings } from '../settings'

const LAYERS = [
  { key: 'l1', status: 'none' },
  { key: 'l2', status: 'partial' },
  { key: 'l3', status: 'partial' },
  { key: 'l4', status: 'good' },
  { key: 'l5', status: 'partial' },
  { key: 'l6', status: 'partial' },
  { key: 'l7', status: 'partial' },
] as const

export default function OsiCoverage() {
  const { t } = useSettings()
  return (
    <section className="card osi-coverage" aria-labelledby="osi-coverage-title">
      <h2 className="card-title" id="osi-coverage-title">{t('osi.title')}</h2>
      <p className="chart-sub">{t('osi.note')}</p>
      <div className="osi-layers">
        {LAYERS.map(({ key, status }, index) => (
          <article className="osi-layer" key={key}>
            <span className="osi-number">{index + 1}</span>
            <div>
              <div className="osi-heading">
                <strong>{t(`osi.${key}`)}</strong>
                <span className={`badge ${status === 'good' ? 'ok' : status === 'partial' ? 'warning' : 'info'}`}>
                  {t(`osi.status${status === 'good' ? 'Good' : status === 'partial' ? 'Partial' : 'None'}`)}
                </span>
              </div>
              <p>{t(`osi.${key}detail`)}</p>
            </div>
          </article>
        ))}
      </div>
    </section>
  )
}
