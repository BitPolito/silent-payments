import { useCallback, useEffect } from 'react'

function CloseIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.25" strokeLinecap="round" aria-hidden>
      <path d="M18 6L6 18M6 6l12 12" />
    </svg>
  )
}

/**
 * @param {{
 *   open: boolean
 *   title: string
 *   subtitle?: string
 *   onClose: () => void
 *   children: import('react').ReactNode
 *   closeLabel: string
 *   closeConfirm?: string
 * }} props
 */
export default function ModalShell({ open, title, subtitle, onClose, closeLabel, children, closeConfirm }) {
  const requestClose = useCallback(() => {
    if (closeConfirm && typeof window !== 'undefined' && !window.confirm(closeConfirm)) return
    onClose()
  }, [closeConfirm, onClose])

  useEffect(() => {
    if (!open) return
    const onKey = (e) => {
      if (e.key === 'Escape') requestClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, requestClose])

  useEffect(() => {
    if (!open) return
    const prev = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => {
      document.body.style.overflow = prev
    }
  }, [open])

  if (!open) return null

  return (

    <div className="sp-modal-overlay fixed inset-0 z-[100] flex items-center justify-center px-3 py-6 sm:px-4" role="presentation" onClick={requestClose}>
    <div role="dialog" aria-modal="true" aria-labelledby="sp-modal-title" className="sp-surface relative flex max-h-[min(92dvh,880px)] w-full max-w-[720px] flex-col overflow-hidden rounded-2xl shadow-xl dark:shadow-2xl dark:shadow-black/40" onClick={(e) => e.stopPropagation()}>
    <div className="grid shrink-0 grid-cols-[2.25rem_1fr_2.25rem] items-center gap-2 border-b border-bp-200 bg-bp-50 px-3 py-3 dark:border-bp-500/35 dark:bg-bp-700/60 sm:px-4 sm:py-3.5">
              <span className="col-start-1" aria-hidden />
    <div className="col-start-2 min-w-0 text-center">
                <h2
              id="sp-modal-title"
              className="text-sm font-semibold leading-snug text-bp-blue dark:text-bp-canvas sm:text-base md:text-lg"
            >
              {title}
            </h2>
            {subtitle ? (
              <p className="mt-1 text-xs font-medium text-bp-600 dark:text-bp-200 sm:text-sm">{subtitle}</p>
            ) : null}
    </div>
              <button
            type="button"
            className="col-start-3 flex h-9 w-9 items-center justify-center justify-self-end rounded-full border border-bp-200 bg-white p-0 text-bp-blue transition hover:border-bp-300 hover:bg-bp-50 dark:border-bp-canvas/35 dark:bg-bp-600 dark:text-bp-canvas dark:hover:border-bp-canvas dark:hover:bg-bp-500"
            onClick={requestClose}
            aria-label={closeLabel}
          >
            <CloseIcon />
          </button>
    </div>
    <div className="min-h-0 flex-1 overflow-y-auto overflow-x-hidden p-4 sm:p-6">{children}</div>
    </div>
    </div>
      )
}
