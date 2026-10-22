import { useId, useState } from 'react'
import BpIcon from '../../components/BpIcon'
import { ICON, STORY } from '../../assets/icons'
import AppLink from '../../components/AppLink'
import { useLocale } from '../../i18n/useLocale'
import { useExperiment } from './useExperiment'
import { useStudioText } from './useStudioText'
import { ComputedStatus, Details, Failure } from './Workbench'
import { ConceptCard, ChoiceCard, PaymentCard } from './VisualCards'
import { StudioArt } from './Illustrations'
import { visualContent } from './visualContent'
import { studioURL } from './navigation'
const names = ['donations', 'shop', 'project']
const pocketIcons = [ICON.heart, STORY.wallet, STORY.letter]
function TransactionCard({ tx, index, v }) {
  const [open,setOpen]=useState(false);const id=useId()
  return <section className={`sp-transaction-card ${tx ? `is-${tx.status}` : ''}`} data-testid={tx?`transaction-${tx.id}`:undefined}>
    <button type="button" aria-label={`${v.cardInspect} ${index+1}`} aria-expanded={open} aria-controls={id} onClick={()=>setOpen(!open)}><span className="sp-transaction-number">0{index+1}</span><StudioArt kind="address" compact /><strong>{tx?v[tx.status]:`${v.paymentCard} ${index+1}`}</strong><span className="sp-transaction-stamp" aria-hidden="true">{tx?(tx.status==='found'?'✓':tx.status==='rejected'?'!':'○'):'+'}</span></button>
    {open&&<p id={id}>{tx?v.reasons[tx.status]:v.noResult}</p>}
  </section>
}
export default function LabelScanExperiment({ tool }) {
  const t=useStudioText();const {locale}=useLocale();const v=visualContent[locale]||visualContent.en;const experiment=useExperiment(tool)
  const initial=()=>({network:'testnet',known_labels:[1,2,3],...(tool==='labels'?{label:1}:{})})
  const [controls,setControls]=useState(initial);const result=experiment.data?.result
  function update(change){experiment.clear();setControls(current=>({...current,...change}))}
  function reset(){experiment.clear();setControls(initial())}
  return <div className="sp-friendly-workbench">
    <section className="sp-friendly-controls">
      {tool==='labels'&&<div><h2>{v.pockets}</h2><div className="sp-pocket-choices" role="group" aria-label={v.pockets}>{names.map((name,index)=><ChoiceCard key={name} icon={<BpIcon src={pocketIcons[index]} className="sp-choice-pixel" />} title={t[name]} selected={controls.label===index+1} onClick={()=>update({label:index+1})} />)}</div></div>}
      <fieldset><legend>{v.recognizes}</legend><div className="sp-known-pockets">{names.map((name,index)=><label key={name}><input type="checkbox" checked={controls.known_labels.includes(index+1)} onChange={()=>update({known_labels:controls.known_labels.includes(index+1)?controls.known_labels.filter(id=>id!==index+1):[...controls.known_labels,index+1]})} /><span aria-hidden="true"><BpIcon src={pocketIcons[index]} className="sp-choice-pixel" /></span><strong>{t[name]}</strong></label>)}</div></fieldset>
      <details className="sp-studio-details sp-advanced"><summary>{v.settings}</summary><label>{t.network}<select aria-label={t.network} className="sp-input" value={controls.network} onChange={e=>update({network:e.target.value})}><option value="testnet">{t.testnet}</option><option value="mainnet">{t.mainnet}</option></select></label><p className="text-xs mt-4">{t.labelHint}</p></details>
      <button className="sp-back-link" onClick={reset}>{t.reset} <span aria-hidden="true">↺</span></button>
    </section>
    <div className="sp-studio-results sp-friendly-stage" aria-busy={experiment.busy}>
      {tool==='labels'?<div className="sp-pocket-scene"><StudioArt kind="labels" /><h2>{v.pocketHint}</h2></div>:<div className="sp-scan-title"><StudioArt kind="scan" compact /><h2>{v.batch}</h2></div>}
      <button className="sp-btn-solid sp-friendly-primary" disabled={experiment.busy} onClick={()=>experiment.run(controls)}>{experiment.busy?t.working:experiment.error?t.retry:tool==='labels'?t.labelScan:t.run} <span aria-hidden="true">→</span></button>
      {experiment.error&&<Failure code={experiment.error} />}
      {result&&<ComputedStatus data={experiment.data}>✓ {t.actual}</ComputedStatus>}
      {tool==='scan'?<>
        {!result&&<p className="sp-description text-xs">{v.noResult}</p>}
        {result&&<div className="sp-wallet-discovery" role="status"><span aria-hidden="true">✓</span><h2>{t.found}: {result.found}</h2></div>}
        <div className="sp-transaction-grid">{result?result.transactions.map((tx,index)=><TransactionCard key={tx.id} tx={tx} index={index} v={v} />):Array.from({length:6},(_,index)=><TransactionCard key={index} index={index} v={v} />)}</div>
        <AppLink className="sp-back-link" href={studioURL('labels').href}>{t.labels} →</AppLink>
      </>:result&&<>
        <h2 className="sp-friendly-outcome">{new Set(result.addresses.map(row=>row.scan_pub_key)).size===1&&new Set(result.addresses.map(row=>row.spend_pub_key)).size===result.addresses.length?v.pocketResult:t.engineFailure}</h2>
        <div className="sp-pocket-results">{result.addresses.slice(1).map(row=><ConceptCard key={row.index} kind="labels" title={t[row.name]}>{v.pocketHint}</ConceptCard>)}</div>
        <div role="status" className="sp-wallet-discovery"><span aria-hidden="true">{result.wallet.length?'✓':'○'}</span><h2>{t.found}: {result.wallet.length} / {result.outputs.length}</h2></div>
        {result.outputs.map((value,index)=><PaymentCard key={value} value={value} index={index+1} matched={result.wallet.some(row=>row.pub_key===value)} />)}
        <AppLink className="sp-back-link" href={studioURL('scan').href}>{t.scan} →</AppLink>
      </>}
      {result&&<Details data={experiment.data} />}
    </div>
  </div>
}
