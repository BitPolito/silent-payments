import { useEffect, useRef } from 'react'
import { StudioArt } from './Illustrations'
import { useStudioText } from './useStudioText'
export function Preview({ kind = 'scan' }) { const t = useStudioText(); return <div className="sp-studio-preview"><StudioArt kind={kind} /><p className="sp-eyebrow">{t.conceptual}</p><p>{t.preview}</p></div> }
export function Details({ data, children }) { const t = useStudioText(); return <details className="sp-studio-details"><summary>{t.details}</summary>{data?.provenance && <a className="sp-back-link" href={`https://github.com/bitcoin/bips/blob/${data.provenance.commit}/bip-0352.mediawiki`} target="_blank" rel="noopener noreferrer">{t.source} ↗</a>}{children}<pre>{JSON.stringify(data, null, 2)}</pre></details> }
export function KeyCard({ title, value, index }) { return <div className="sp-studio-key"><span className="sp-eyebrow">{title} {index}</span><code title={value}>{value?.slice(0, 12)}…{value?.slice(-8)}</code></div> }

export function Failure({ code }) { const t = useStudioText(); return <p role="alert" className="sp-notice">{code === 'INVALID_INPUT' ? t.invalidControls : code === 'INTERNAL_ERROR' ? t.engineFailure : t.offline}</p> }

export function ComputedStatus({ data, children }) {
  const summaryRef = useRef(null)
  useEffect(() => {
    if (!data) return
    summaryRef.current?.focus({ preventScroll: true })
    const target = summaryRef.current?.closest('.sp-friendly-stage') || summaryRef.current
    target?.scrollIntoView({ block: 'start', behavior: 'auto' })
  }, [data])
  return <p ref={summaryRef} tabIndex={-1} role="status" className="sp-result-status sp-studio-computed">{children}</p>
}
