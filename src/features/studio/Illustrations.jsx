import { STORY } from '../../assets/icons'
import { useLocale } from '../../i18n/useLocale'
import { visualContent } from './visualContent'

export function StudioArt({ kind = 'payment', compact = false }) {
  return <svg className={`sp-art ${compact ? 'is-compact' : ''}`} viewBox="0 0 320 160" fill="none" aria-hidden="true" focusable="false">
    <circle cx="160" cy="80" r="74" fill="currentColor" opacity=".05" />
    <g stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      {kind === 'payment' && <><path d="M74 80h160m-14-12 14 12-14 12" strokeDasharray="5 7" /><g className="sp-art-coin"><circle cx="80" cy="80" r="32" className="sp-art-fill" /><path d="M76 61v38m8-38v38m-16-31h18c15 0 15 14 0 14H68h20c15 0 15 14 0 14H68" /></g><rect x="213" y="49" width="72" height="62" rx="12" className="sp-art-fill" /><path d="M213 64h72m-22 17h22v18h-22z" /><circle cx="273" cy="90" r="2" fill="currentColor" /></>}
      {kind === 'address' && <><rect x="61" y="35" width="198" height="96" rx="16" className="sp-art-fill" /><path d="m66 43 94 62 94-62M68 122l57-44m127 44-57-44" /><circle cx="251" cy="40" r="23" className="sp-art-fill" /><path d="M242 40h18m-9-9v18" /></>}
      {kind === 'labels' && <><path d="M69 53V38a9 9 0 0 1 9-9h164a9 9 0 0 1 9 9v15" />{[55,125,195].map((x,i)=><g key={x}><rect x={x} y={50+i*9} width="69" height="79" rx="12" className="sp-art-fill" /><path d={`M${x} ${70+i*9}h69`} /><circle cx={x+35} cy={98+i*9} r="10" /></g>)}</>}
      {kind === 'scan' && <>{[60,125,190].map((x,i)=><g key={x}><rect x={x} y={35+i%2*14} width="52" height="72" rx="9" className="sp-art-fill" /><path d={`M${x+11} ${55+i%2*14}h29m-29 11h21`} /></g>)}<circle cx="205" cy="91" r="31" className="sp-art-fill" /><path d="m228 114 27 27m-62-50 8 8 16-18" /></>}
    </g>
    <g fill="currentColor" opacity=".35"><circle cx="44" cy="28" r="3" /><circle cx="286" cy="119" r="4" /><path d="M277 25v10m-5-5h10M34 120v8m-4-4h8" stroke="currentColor" strokeWidth="2" /></g>
  </svg>
}

export function PaymentStory({ coinCount = 2, paymentCount = 1, computed = false }) {
  const { locale } = useLocale(); const v = visualContent[locale] || visualContent.en
  return <figure className={`sp-payment-story ${computed ? 'is-computed' : ''}`}>
    <div className="sp-story-person"><img className="sp-icon-blue" src={STORY.alice} alt="" /><span>{v.alice}</span><div className="sp-mini-coins" aria-hidden="true">{Array.from({ length: coinCount },(_,i)=><i key={i}>₿</i>)}</div></div>
    <div className="sp-story-journey"><StudioArt kind="payment" /><span aria-hidden="true" className="sp-story-trail">→</span></div>
    <div className="sp-story-person"><img className="sp-icon-blue" src={STORY.bob} alt="" /><span>{v.bob}</span><div className="sp-mini-envelopes" aria-hidden="true">{Array.from({ length: paymentCount },(_,i)=><i key={i}>◇</i>)}</div></div>
    <figcaption>{computed ? v.preview : v.conceptual}</figcaption>
  </figure>
}

export function Fingerprint({ value }) {
  // A visual comparison aid for actual result values, never a substitute for a key/checksum.
  const cells=Array.from({length:16},(_,i)=>parseInt(value?.[i] || '0',16)%3)
  return <svg viewBox="0 0 64 64" className="sp-fingerprint" aria-hidden="true" focusable="false">{cells.map((cell,i)=><rect key={i} x={i%4*16+2} y={Math.floor(i/4)*16+2} width="12" height="12" rx={cell===1?6:2} fill="currentColor" opacity={cell===0?.14:cell===1?.55:1} />)}</svg>
}
