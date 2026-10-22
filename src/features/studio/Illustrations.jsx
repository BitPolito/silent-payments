import { ICON, STORY } from '../../assets/icons'
import BpIcon from '../../components/BpIcon'
import { useLocale } from '../../i18n/useLocale'
import { visualContent } from './visualContent'

export function StudioArt({ kind = 'payment', compact = false }) {
  return <div className={`sp-art is-${kind} ${compact ? 'is-compact' : ''}`} aria-hidden="true">
    {kind === 'payment' && <><BpIcon src={STORY.bitSymbol} className="sp-pixel-primary" /><BpIcon src={STORY.arrow} className="sp-pixel-arrow" /><BpIcon src={STORY.wallet} className="sp-pixel-secondary" /></>}
    {kind === 'address' && <BpIcon src={STORY.letter} className="sp-pixel-primary" />}
    {kind === 'labels' && [0, 1, 2].map(index => <BpIcon key={index} src={STORY.wallet} className={`sp-pixel-pocket pocket-${index}`} />)}
    {kind === 'scan' && <><div className="sp-pixel-batch">{[0, 1, 2].map(index => <BpIcon key={index} src={STORY.letter} className={`sp-pixel-document document-${index}`} />)}</div><BpIcon src={ICON.microscope} className="sp-pixel-secondary" /></>}
  </div>
}

export function PaymentStory({ coinCount = 2, paymentCount = 1, computed = false }) {
  const { locale } = useLocale(); const v = visualContent[locale] || visualContent.en
  return <figure className={`sp-payment-story ${computed ? 'is-computed' : ''}`}>
    <div className="sp-story-person"><img className="sp-icon-blue" src={STORY.alice} alt="" /><span>{v.alice}</span><div className="sp-mini-coins" aria-hidden="true">{Array.from({ length: coinCount },(_,i)=><i key={i}><BpIcon src={STORY.bitSymbol} className="sp-mini-pixel" /></i>)}</div></div>
    <div className="sp-story-journey"><StudioArt kind="payment" /></div>
    <div className="sp-story-person"><img className="sp-icon-blue" src={STORY.bob} alt="" /><span>{v.bob}</span><div className="sp-mini-envelopes" aria-hidden="true">{Array.from({ length: paymentCount },(_,i)=><i key={i}><BpIcon src={STORY.letter} className="sp-mini-pixel" /></i>)}</div></div>
    <figcaption>{computed ? v.preview : v.conceptual}</figcaption>
  </figure>
}

export function Fingerprint({ value }) {
  // A visual comparison aid for actual result values, never a substitute for a key/checksum.
  const cells=Array.from({length:16},(_,i)=>parseInt(value?.[i] || '0',16)%3)
  return <svg viewBox="0 0 64 64" className="sp-fingerprint" aria-hidden="true" focusable="false">{cells.map((cell,i)=><rect key={i} x={i%4*16+2} y={Math.floor(i/4)*16+2} width="12" height="12" rx={cell===1?6:2} fill="currentColor" opacity={cell===0?.14:cell===1?.55:1} />)}</svg>
}
