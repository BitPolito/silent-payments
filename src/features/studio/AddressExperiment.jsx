import { useState } from 'react'
import { useLocale } from '../../i18n/useLocale'
import { useExperiment } from './useExperiment'
import { useStudioText } from './useStudioText'
import { ComputedStatus, Details, Failure } from './Workbench'
import { ConceptCard } from './VisualCards'
import { StudioArt } from './Illustrations'
import { visualContent } from './visualContent'
export default function AddressExperiment() {
  const t=useStudioText();const {locale}=useLocale();const v=visualContent[locale]||visualContent.en;const experiment=useExperiment('address')
  const [network,setNetwork]=useState('testnet');const [address,setAddress]=useState('')
  const result=experiment.data?.result;const sample=experiment.metadata?.samples[network]
  function reset(){experiment.clear();setAddress('');setNetwork('testnet')}
  const valid=result&&['supported','forward_compatible'].includes(result.status)
  return <div className="sp-friendly-workbench">
    <section className="sp-card sp-friendly-controls"><StudioArt kind="address" /><h2>{v.destination}</h2><button className="sp-btn-outline" disabled={!sample} onClick={()=>{experiment.clear();setAddress(sample)}}>{t.loadSample}</button>
      <label className="text-sm font-semibold">{t.publicAddress}<textarea aria-label={t.publicAddress} className="sp-input mt-2 font-mono" maxLength={1023} value={address} placeholder={v.paste} onChange={e=>{experiment.clear();setAddress(e.target.value)}} spellCheck="false" autoComplete="off" /></label>
      <details className="sp-studio-details sp-advanced"><summary>{v.settings}</summary><label>{t.network}<select aria-label={t.network} className="sp-input" value={network} onChange={e=>{experiment.clear();setNetwork(e.target.value);setAddress('')}}><option value="testnet">{t.testnet}</option><option value="mainnet">{t.mainnet}</option></select></label></details><button className="sp-back-link" onClick={reset}>{t.reset} <span aria-hidden="true">↺</span></button>
    </section>
    <div className="sp-card sp-studio-results sp-friendly-stage" aria-busy={experiment.busy}>
      <div className={`sp-address-pass ${result?(valid?'is-valid':'is-invalid'):''}`}><StudioArt kind="address" /><h2>{result?(valid?v.addressValid:v.addressInvalid):v.destination}</h2>{result&&<span className="sp-address-seal">{valid?'✓':'!'}</span>}{result?.network&&<p>{t[result.network]}</p>}</div>
      <button className="sp-btn-solid sp-friendly-primary" disabled={experiment.busy} onClick={()=>experiment.run({network,...(address.trim()?{address:address.trim()}:{})})}>{experiment.busy?t.working:experiment.error?t.retry:t.inspect} <span aria-hidden="true">→</span></button>
      {experiment.error&&<Failure code={experiment.error} />}
      {result&&<ComputedStatus data={experiment.data}>{valid?'✓':'!'} {t.actual}</ComputedStatus>}
      {(!result||valid)&&<><p className="sp-description text-xs">{v.publicInfo}</p><div className="sp-studio-columns"><ConceptCard kind="scan" title={v.findRole}>{v.findHint}</ConceptCard><ConceptCard kind="payment" title={v.spendRole}>{v.spendHint}</ConceptCard></div></>}
      {result&&<Details data={experiment.data}><p className="text-sm mb-3">{t[result.status]}</p><dl className="sp-studio-result grid grid-cols-2 gap-3"><dt>{t.checksum}</dt><dd>{result.checksum_valid?t.valid:'✕'}</dd>{result.network&&<><dt>{t.network}</dt><dd>{t[result.network]}</dd></>}{result.version!=null&&<><dt>{t.version}</dt><dd>{result.version}</dd></>}</dl></Details>}
    </div>
  </div>
}
