import { useState } from 'react'
import { useLocale } from '../../i18n/useLocale'
import { useExperiment } from './useExperiment'
import { useStudioText } from './useStudioText'
import { ComputedStatus, Details, Failure, KeyCard } from './Workbench'
import { PaymentStory } from './Illustrations'
import { ChoiceCard, PaymentCard } from './VisualCards'
import { visualContent } from './visualContent'
const scenarioIcons = { changed: '↔', reorder: '⇄', amountOnly: '₿', mutation: '↶' }
export default function PaymentExperiment({ preset }) {
  const t = useStudioText(); const { locale }=useLocale(); const v=visualContent[locale] || visualContent.en
  const experiment = useExperiment('payment')
  const initial = () => ({ preset, network: 'testnet', inputs: [0, 1], recipients: 1, amount: 12000, comparison: preset === 'mutation' ? 'mutation' : 'changed' })
  const [controls, setControls] = useState(initial)
  const result = experiment.data?.result
  function update(change) { experiment.clear(); setControls((previous) => ({ ...previous, ...change })) }
  function reset() { experiment.clear(); setControls(initial()) }
  const action = result && !result.wallet ? 'scan' : result?.wallet && !result.evidence ? 'verify' : 'derive'
  const run = (action) => experiment.run({ ...controls, action })
  return <div className="sp-friendly-workbench">
    <section className="sp-friendly-controls" aria-label={v.coins}>
      <fieldset><legend>{v.coins}</legend><p className="sp-description text-xs mb-3">{v.coinHint}</p><div className="sp-coin-choices">{[0,1,2,3].map((id)=><label className="sp-coin-card" key={id}><input type="checkbox" checked={controls.inputs.includes(id)} onChange={()=>update({inputs: controls.inputs.includes(id)?controls.inputs.filter((i)=>i!==id):[...controls.inputs,id]})} /><span aria-hidden="true" className="sp-big-coin">₿</span><strong>{v.coin} {id+1}</strong><span className="sp-coin-check" aria-hidden="true">{controls.inputs.includes(id)?'✓':'+'}</span></label>)}</div></fieldset>
      <div><h2>{v.scenarios}</h2><div className="sp-scenario-choices" role="group" aria-label={v.scenarios}>{Object.keys(scenarioIcons).map((mode)=><ChoiceCard key={mode} icon={scenarioIcons[mode]} title={v[mode]} selected={controls.comparison===mode} onClick={()=>update({comparison:mode})} />)}</div><p className="sp-description text-sm mt-3">{v.hints[controls.comparison]}</p></div>
      <div><h2>{v.chooseCount}</h2><div className="sp-count-choices" role="group" aria-label={v.chooseCount}>{[1,2].map((count)=><button aria-pressed={controls.recipients===count} key={count} onClick={()=>update({recipients:count})}>{count===1?v.one:v.two}</button>)}</div></div>
      <details className="sp-studio-details sp-advanced"><summary>{v.settings}</summary><label>{t.network}<select aria-label={t.network} className="sp-input" value={controls.network} onChange={(e)=>update({network:e.target.value})}><option value="testnet">{t.testnet}</option><option value="mainnet">{t.mainnet}</option></select></label><label>{t.amount}<input aria-label={t.amount} type="number" min="1" max="2100000000000000" className="sp-input" value={controls.amount} onChange={(e)=>update({amount:Number(e.target.value)} )} /></label></details>
      <button className="sp-back-link" onClick={reset}>{t.reset} <span aria-hidden="true">↺</span></button>
    </section>
    <div className="sp-studio-results sp-friendly-stage" aria-busy={experiment.busy}>
      <PaymentStory coinCount={controls.inputs.length} paymentCount={controls.recipients} computed={Boolean(result)} />
      <button className="sp-btn-solid sp-friendly-primary" disabled={experiment.busy || !controls.inputs.length || !Number.isSafeInteger(controls.amount) || controls.amount<1 || controls.amount>2100000000000000} onClick={()=>run(action)}>{experiment.busy?t.working:experiment.error?t.retry:action==='scan'?t.discover:action==='verify'?t.verify:t.derive} <span aria-hidden="true">→</span></button>
      {experiment.error && <Failure code={experiment.error} />}
      {result && <>
        <ComputedStatus data={experiment.data}>✓ {t.actual}</ComputedStatus>
        <h2 className="sp-friendly-outcome">{result.comparison==='mutation'?v.hints.mutation:t[result.same_outputs?'equal':'different']}</h2>
        <div className="sp-studio-columns">{[['baseline',result.outputs],['comparison',result.comparison==='mutation'?result.outputs:result.comparison_outputs]].map(([label,outputs])=><section className="sp-visual-results" key={label}><h3>{label==='baseline'?v.before:v.after}</h3><p className="sp-payment-amount">{(label==='baseline'?result.amount:result.comparison_amount).toLocaleString(locale)} <small>sats</small></p>{outputs.map((value,index)=><PaymentCard key={`${index}:${value}`} value={value} index={index+1} matched={result.wallet?(label==='baseline'?result.wallet:result.comparison_wallet).some((item)=>item.pub_key===value):null} />)}</section>)}</div>
        {result.wallet ? <div className="sp-wallet-discovery" role="status"><span aria-hidden="true">{result.comparison_wallet.length?'✓':'○'}</span><div><h2>{t.found}</h2><p>{t.baseline}: {result.wallet.length} → {t.comparison}: {result.comparison_wallet.length}</p></div></div>:null}
        {result.evidence?<div className="sp-wallet-discovery" role="status"><span aria-hidden="true">✓</span><h2>{v.ownership}</h2></div>:null}
        <Details data={experiment.data}><p className="text-sm mb-4">{t.signatureHint}</p><KeyCard title={t.address} value={result.address} /></Details>
      </>}
    </div>
  </div>
}
