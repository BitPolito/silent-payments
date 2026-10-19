import { useEffect, useId, useRef } from 'react'

export default function ModalShell({ open, title, subtitle, onClose, children, closeLabel, closeConfirm }) {
  const dialogRef = useRef(null)
  const titleRef = useRef(null)
  const backdropDown = useRef(false)
  const titleId = useId()
  useEffect(() => {
    if (!open) return
    const dialog = dialogRef.current
    const trigger = document.activeElement
    const previousOverflow = document.body.style.overflow
    dialog.showModal()
    titleRef.current?.focus({ preventScroll: true })
    document.body.style.overflow = 'hidden'
    return () => {
      dialog.close()
      document.body.style.overflow = previousOverflow
      if (trigger?.isConnected) trigger.focus({ preventScroll: true })
    }
  }, [open])
  const requestClose = () => {
    if (!closeConfirm || window.confirm(closeConfirm)) onClose()
  }
  const containFocus = (event) => {
    if (event.key !== 'Tab') return
    const elements = [...dialogRef.current.querySelectorAll('a[href], button, input, select, textarea, summary, [tabindex]')]
      .filter((element) => !element.disabled && element.tabIndex >= 0 && element.getClientRects().length > 0)
    const first = elements[0]
    const last = elements[elements.length - 1]
    if (!first) { event.preventDefault(); titleRef.current?.focus(); return }
    if (event.shiftKey && (document.activeElement === first || document.activeElement === titleRef.current)) {
      event.preventDefault(); last.focus()
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault(); first.focus()
    }
  }
  return <dialog ref={dialogRef} className="sp-modal" aria-labelledby={titleId} onKeyDown={containFocus}
    onCancel={(event) => { event.preventDefault(); requestClose() }}
    onPointerDown={(event) => { backdropDown.current = event.target === event.currentTarget }}
    onClick={(event) => { if (event.target === event.currentTarget && backdropDown.current) requestClose() }}>
    <div className="sp-modal-header">
      <div className="min-w-0"><h2 id={titleId} ref={titleRef} tabIndex={-1}>{title}</h2>{subtitle && <p className="sp-description mt-1 text-sm">{subtitle}</p>}</div>
      <button type="button" className="sp-close-button" onClick={requestClose} aria-label={closeLabel}>
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" aria-hidden><path d="m6 6 12 12M6 18 18 6" /></svg>
      </button>
    </div>
    <div className="sp-modal-body">{children}</div>
  </dialog>
}
