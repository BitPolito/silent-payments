import { useState } from 'react'
import { useExperiment } from './useExperiment'
import { useStudioText } from './useStudioText'
import { ComputedStatus, Details, Failure, KeyCard, Preview } from './Workbench'
export default function PaymentExperiment({ preset }) {
  const t = useStudioText()
  const experiment = useExperiment('payment')
  const [controls, setControls] = useState({ preset, network: 'testnet', inputs: [0, 1], recipients: 1, amount: 12000, comparison: preset === 'mutation' ? 'mutation' : 'changed' })
  const result = experiment.data?.result
  function update(change) { experiment.clear(); setControls((previous) => ({ ...previous, ...change })) }
  function reset() { experiment.clear(); setControls({ preset, network: 'testnet', inputs: [0, 1], recipients: 1, amount: 12000, comparison: preset === 'mutation' ? 'mutation' : 'changed' }) }
  const run = (action) => experiment.run({ ...controls, action })
  return <div className="sp-studio-layout">
    <div className="sp-studio-controls"><button className="sp-btn-solid" disabled={experiment.busy || controls.inputs.length === 0 || !Number.isSafeInteger(controls.amount) || controls.amount < 1 || controls.amount > 2100000000000000} onClick={() => run('derive')}>{experiment.busy ? t.working : experiment.error ? t.retry : t.derive}</button>
      <label>{t.network}<select aria-label={t.network} className="sp-input" value={controls.network} onChange={(e) => update({ network: e.target.value })}><option value="testnet">{t.testnet}</option><option value="mainnet">{t.mainnet}</option></select></label>
      <fieldset className="sp-studio-inputs"><legend>{t.inputs}</legend>{[0, 1, 2, 3].map((id) => <label key={id}><input type="checkbox" checked={controls.inputs.includes(id)} onChange={() => update({ inputs: controls.inputs.includes(id) ? controls.inputs.filter((i) => i !== id) : [...controls.inputs, id] })} />P2PKH #{id + 1}</label>)}</fieldset>
      <label>{t.recipients}<select aria-label={t.recipients} className="sp-input" value={controls.recipients} onChange={(e) => update({ recipients: Number(e.target.value) })}><option>1</option><option>2</option></select></label>
      <label>{t.amount}<input aria-label={t.amount} type="number" min="1" max="2100000000000000" className="sp-input" value={controls.amount} onChange={(e) => update({ amount: Number(e.target.value) })} /></label>
      <label>{t.compare}<select aria-label={t.compare} className="sp-input" value={controls.comparison} onChange={(e) => update({ comparison: e.target.value })}>{['changed', 'reorder', 'amountOnly', 'mutation'].map((mode) => <option key={mode} value={mode}>{t[mode]}</option>)}</select></label>
      <button className="sp-back-link" onClick={reset}>{t.reset} <span aria-hidden="true">↺</span></button>
    </div>
    <div className="sp-studio-results" aria-busy={experiment.busy}>
      {experiment.error && <Failure code={experiment.error} />}
      {!result ? <Preview /> : <>
        <ComputedStatus data={experiment.data}>✓ {t.actual}</ComputedStatus>
        <p className="font-bold">{t[result.same_outputs ? 'equal' : 'different']}</p>
        <div className="sp-studio-columns">{[['baseline', result.outputs], ['comparison', result.comparison_outputs]].map(([label, outputs]) => <section key={label} className="sp-studio-result"><h2>{t[label]}</h2><p className="sp-description mb-3">{(label === 'baseline' ? result.amount : result.comparison_amount).toLocaleString()} sats</p>{outputs.map((value, index) => <KeyCard key={`${index}:${value}`} title="Output" value={value} index={index + 1} />)}</section>)}</div>
        {result.wallet ? <div className="sp-studio-result" role="status"><h2>{t.found}</h2><p>{t.baseline}: {result.wallet.length} → {t.comparison}: {result.comparison_wallet.length}</p></div> : <button className="sp-btn-outline" onClick={() => run('scan')}>{t.discover} <span aria-hidden="true">→</span></button>}
        {result.evidence ? <div className="sp-studio-result" role="status"><h2>✓ {t.signature}</h2><p>{result.evidence.length} / {result.recipient_count}</p></div> : result.wallet && <button className="sp-btn-outline" onClick={() => run('verify')}>{t.verify} <span aria-hidden="true">→</span></button>}
        {result.wallet && <p className="sp-description text-xs">{t.signatureHint}</p>}
        <Details data={experiment.data}><KeyCard title={t.address} value={result.address} /></Details>
      </>}
    </div>
  </div>
}
