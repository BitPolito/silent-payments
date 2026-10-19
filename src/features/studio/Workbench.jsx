import { useStudioText } from './useStudioText'
export function Preview() { const t = useStudioText(); return <div className="sp-studio-preview"><p className="sp-eyebrow">{t.conceptual}</p><div aria-hidden="true" className="sp-studio-diagram"><span>01</span><i>→</i><span>02</span><i>→</i><span>03</span></div><p>{t.preview}</p></div> }
export function Details({ data, children }) { const t = useStudioText(); return <details className="sp-studio-details"><summary>{t.details}</summary>{children}<pre>{JSON.stringify(data, null, 2)}</pre></details> }
export function KeyCard({ title, value, index }) { return <div className="sp-studio-key"><span className="sp-eyebrow">{title} {index}</span><code title={value}>{value?.slice(0, 12)}…{value?.slice(-8)}</code></div> }
