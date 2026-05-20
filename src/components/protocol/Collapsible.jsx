import { useState } from 'react'

/**
 * @param {{
 *   title: string
 *   children: import('react').ReactNode
 *   defaultOpen?: boolean
 *   nested?: boolean
 * }} props
 */
export default function Collapsible({ title, children, defaultOpen = false, nested = false }) {
  const [open, setOpen] = useState(defaultOpen)

  return (
    <div className={nested ? 'sp-fold sp-fold-nested' : 'sp-fold'}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="sp-fold-trigger"
        aria-expanded={open}
      >
        <span>{title}</span>
        <span className="sp-fold-chevron" aria-hidden>
          {open ? '−' : '+'}
        </span>
      </button>
      {open ? <div className="sp-fold-panel">{children}</div> : null}
    </div>
  )
}
