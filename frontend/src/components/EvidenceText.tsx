import { useState, type ReactNode } from 'react'
import { filterApplicability, parseBlocks, type Block, type Inline } from '../evidence'
import { useSettings } from '../settings'

interface Props {
  text: string
  knownProtocols: ReadonlySet<string>
  onShowPackets: (filter: string) => void
  onSelectPacket: (n: number) => void
}

// Renders the agent's markdown-lite with evidence marks as buttons. Everything
// is rendered as React text nodes: no HTML from the model ever reaches the DOM.
export default function EvidenceText({ text, knownProtocols, onShowPackets, onSelectPacket }: Props) {
  const { t } = useSettings()
  const [copied, setCopied] = useState<string | null>(null)

  const copy = async (key: string, value: string) => {
    try {
      await navigator.clipboard.writeText(value)
      setCopied(key)
      window.setTimeout(() => setCopied((current) => (current === key ? null : current)), 1500)
    } catch {
      /* clipboard blocked */
    }
  }

  const renderInline = (inline: Inline, key: string): ReactNode => {
    switch (inline.kind) {
      case 'bold':
        return <strong key={key}>{inline.text}</strong>
      case 'code':
        return <code key={key}>{inline.text}</code>
      case 'pkt': {
        const single = inline.from === inline.to
        const title = single
          ? t('investigation.packet', { n: inline.from })
          : t('investigation.packets', { from: inline.from, to: inline.to })
        return (
          <button
            key={key}
            className="evidence-btn"
            title={title}
            onClick={() =>
              single
                ? onSelectPacket(inline.from)
                : onShowPackets(`frame.number >= ${inline.from} && frame.number <= ${inline.to}`)
            }
          >
            {single ? `#${inline.from}` : `#${inline.from}–${inline.to}`}
          </button>
        )
      }
      case 'filter': {
        const local = filterApplicability(inline.filter, knownProtocols) === 'local'
        return (
          <span key={key} className="evidence-filter">
            {local ? (
              <button className="evidence-btn" title={inline.filter} onClick={() => onShowPackets(inline.filter)}>
                {t('investigation.showPackets')}
              </button>
            ) : (
              <code title={t('investigation.copyOnly')}>{inline.filter}</code>
            )}
            <button
              className="evidence-btn ghost"
              title={local ? `${t('investigation.copy')}: ${inline.filter}` : t('investigation.copyOnly')}
              onClick={() => copy(key, inline.filter)}
            >
              {copied === key ? t('investigation.copied') : '⧉'}
            </button>
          </span>
        )
      }
      default:
        return <span key={key}>{inline.text}</span>
    }
  }

  const renderInlines = (inlines: Inline[], prefix: string) => inlines.map((inline, i) => renderInline(inline, `${prefix}-${i}`))

  const blocks = parseBlocks(text)
  const out: ReactNode[] = []
  let bullets: Block[] = []
  const flushBullets = (key: string) => {
    if (bullets.length === 0) return
    out.push(
      <ul key={key}>
        {bullets.map((b, i) => (
          <li key={i}>{b.kind === 'bullet' ? renderInlines(b.inlines, `${key}-${i}`) : null}</li>
        ))}
      </ul>,
    )
    bullets = []
  }
  blocks.forEach((block, index) => {
    const key = `b${index}`
    if (block.kind === 'bullet') {
      bullets.push(block)
      return
    }
    flushBullets(`ul${index}`)
    if (block.kind === 'heading') {
      out.push(block.level === 2 ? <h3 key={key}>{renderInlines(block.inlines, key)}</h3> : <h4 key={key}>{renderInlines(block.inlines, key)}</h4>)
    } else if (block.kind === 'code') {
      out.push(<pre key={key}>{block.text}</pre>)
    } else {
      out.push(<p key={key}>{renderInlines(block.inlines, key)}</p>)
    }
  })
  flushBullets('ul-end')
  return <div className="evidence-text">{out}</div>
}
