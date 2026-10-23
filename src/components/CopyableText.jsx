import { useCallback, useState } from 'react'
import { useLocale } from '../i18n/useLocale'

/**
 * @param {{ value: string, label?: string, className?: string, emptyLabel?: string, highlight?: { start: number, end: number } | null }} props
 */
export default function CopyableText({ value, label, className = '', emptyLabel = '—', highlight = null }) {
  const { tr } = useLocale()
  const [copied, setCopied] = useState(false)
  const canCopy = Boolean(value?.trim())
  const hasHighlight =
    canCopy &&
    highlight &&
    highlight.start >= 0 &&
    highlight.end > highlight.start &&
    highlight.end <= value.length

  const copy = useCallback(async () => {
    if (!canCopy) return
    try {
      await navigator.clipboard.writeText(value)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 2000)
    } catch {
      const ta = document.createElement('textarea')
      ta.value = value
      ta.setAttribute('readonly', '')
      ta.style.position = 'fixed'
      ta.style.left = '-9999px'
      document.body.appendChild(ta)
      ta.select()
      document.execCommand('copy')
      document.body.removeChild(ta)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 2000)
    }
  }, [canCopy, value])

  const displayContent = !canCopy ? (
    emptyLabel
  ) : hasHighlight ? (
    <>
      {value.slice(0, highlight.start)}
      <mark className="sp-copy-highlight">
        {value.slice(highlight.start, highlight.end)}
      </mark>
      {value.slice(highlight.end)}
    </>
  ) : (
    value
  )

  const copyControl = canCopy ? (
    <button
      type="button"
      onClick={copy}
      title={tr('copyHint')}
      aria-label={`${tr('copy')}: ${label ? `${label} · ` : ''}${value}`}
      className="sp-copy-control"
      data-copied={copied || undefined}
    >
      <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true" focusable="false">
        <path fillRule="evenodd" d={copied ? 'M2 7h2v2h2v2h2V9h2V7h2V5h2V3h-2v2h-2v2H8v2H6V7H4V5H2v2Z' : 'M5 1h9v10h-2V3H5V1ZM2 4h9v11H2V4Zm2 2v7h5V6H4Z'} />
      </svg>
      <span className="sp-copy-control-text" aria-live="polite">{copied ? tr('copied') : tr('copy')}</span>
    </button>
  ) : null

  return (
    <div className={`sp-copy-field ${className}`}>
      {label && <div className="sp-copy-heading"><span className="sp-copy-label">{label}</span>{copyControl}</div>}
      <code className="sp-copy-value">{displayContent}</code>
      {!label && copyControl && <div className="sp-copy-actions">{copyControl}</div>}
    </div>
  )
}
