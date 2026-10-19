import { useId, useState } from 'react'
import { useLocale } from '../../i18n/useLocale'
import { visualContent } from './visualContent'
import { Fingerprint, StudioArt } from './Illustrations'

export function PaymentCard({ value, index, matched }) {
  const { locale }=useLocale(); const v=visualContent[locale] || visualContent.en
  const [open,setOpen]=useState(false); const id=useId()
  return <div className="sp-friendly-payment"><button type="button" aria-label={`${v.openPayment} ${index}`} aria-expanded={open} aria-controls={id} onClick={()=>setOpen(!open)}><Fingerprint value={value} /><span><strong>{v.paymentCard} {index}</strong><small>{matched == null ? v.ready : matched ? `✓ ${v.matched}` : `○ ${v.notFound}`}</small></span><span aria-hidden="true">{open?'−':'+'}</span></button>{open && <p id={id}>{v.paymentHint}</p>}</div>
}

export function ChoiceCard({ icon, title, hint, selected, onClick, children }) {
  return <button type="button" className="sp-choice-card" aria-pressed={selected} onClick={onClick}><span className="sp-choice-icon" aria-hidden="true">{icon}</span><strong>{title}</strong>{hint && <small>{hint}</small>}{children}<span className="sp-choice-check" aria-hidden="true">{selected?'✓':'+'}</span></button>
}

export function ConceptCard({ kind, title, children }) {
  const { locale }=useLocale(); const v=visualContent[locale] || visualContent.en
  const [open,setOpen]=useState(false);const id=useId()
  return <div className="sp-concept-card"><button type="button" aria-label={`${v.about} ${title}`} aria-expanded={open} aria-controls={id} onClick={()=>setOpen(!open)}><StudioArt kind={kind} compact /><strong>{title}</strong><span aria-hidden="true">{open?'−':'+'}</span></button>{open && <p id={id}>{children}</p>}</div>
}
