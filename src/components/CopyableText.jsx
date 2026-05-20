import { useCallback, useState } from 'react'
import { useLocale } from '../i18n/LocaleContext'

/**
 * @param {{ value: string, className?: string, emptyLabel?: string, highlight?: { start: number, end: number } | null }} props
 */
export default function CopyableText({ value, className = '', emptyLabel = '—', highlight = null }) {
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
      <mark className="rounded bg-bp-blue/20 px-0.5 font-semibold text-bp-blue ring-1 ring-bp-blue/25 dark:bg-bp-canvas/35 dark:text-bp-blue dark:ring-bp-canvas/40">
        {value.slice(highlight.start, highlight.end)}
      </mark>
      {value.slice(highlight.end)}
    </>
  ) : (
    value
  )

  return (
    <button
      type="button"
      onClick={copy}
      disabled={!canCopy}
      title={canCopy ? tr('copyHint') : undefined}
      className={`group relative mt-1 block w-full rounded-lg border border-bp-200 bg-bp-50 p-3 text-left font-mono text-xs text-bp-blue shadow-sm transition dark:border-bp-500/45 dark:bg-bp-700/55 dark:text-bp-canvas ${
        canCopy
          ? 'cursor-pointer hover:border-bp-blue/40 hover:bg-bp-100 hover:ring-2 hover:ring-bp-blue/25 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-bp-blue dark:hover:border-bp-canvas/35 dark:hover:bg-bp-700/80 dark:hover:ring-bp-canvas/30 dark:focus-visible:ring-bp-canvas'
          : 'cursor-default opacity-70'
      } ${className}`}
    >
      <span className="block whitespace-pre-wrap break-all pr-12 pt-0.5">{displayContent}</span>
      {canCopy ? (
        <span className="pointer-events-none absolute right-2 top-2 rounded-md bg-white/90 px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wide text-bp-500 shadow-sm transition group-hover:text-bp-blue group-focus-visible:text-bp-blue dark:bg-bp-800/90 dark:text-bp-200 dark:group-hover:text-bp-canvas">
          {copied ? tr('copied') : tr('copy')}
        </span>
      ) : null}
    </button>
  )
}
