import { useState } from 'react'
import { useExperiment } from './useExperiment'
import { useStudioText } from './useStudioText'
import { Details, Failure, KeyCard, Preview } from './Workbench'
export default function AddressExperiment() {
  const t = useStudioText(); const experiment = useExperiment('address')
  const [network, setNetwork] = useState('testnet')
  const [address, setAddress] = useState('')
  const result = experiment.data?.result
  const sample = experiment.metadata?.samples[network]
  function reset() { experiment.clear(); setAddress(''); setNetwork('testnet') }
  return <div className="sp-studio-layout">
    <div className="sp-studio-controls"><label>{t.network}<select aria-label={t.network} className="sp-input" value={network} onChange={(e) => { experiment.clear(); setNetwork(e.target.value); setAddress('') }}><option value="testnet">{t.testnet}</option><option value="mainnet">{t.mainnet}</option></select></label>
    <button className="sp-btn-outline" disabled={!sample} onClick={() => { experiment.clear(); setAddress(sample) }}>{t.loadSample}</button><button className="sp-btn-solid" disabled={experiment.busy} onClick={() => experiment.run({ network, ...(address.trim() ? { address: address.trim() } : {}) })}>{experiment.busy ? t.working : experiment.error ? t.retry : t.inspect}</button><button className="sp-back-link" onClick={reset}>{t.reset} <span aria-hidden="true">↺</span></button></div>
    <div className="sp-studio-results" aria-busy={experiment.busy}>
      <label className="font-semibold text-sm">{t.publicAddress}<textarea aria-label={t.publicAddress} className="sp-input mt-2 font-mono" maxLength={1023} value={address} placeholder={sample || 'tsp1…'} onChange={(e) => { experiment.clear(); setAddress(e.target.value) }} spellCheck="false" autoComplete="off" /></label>
      <p className="sp-description text-xs">{t.addressHint}</p>
      {experiment.error && <Failure code={experiment.error} />}
      {!result ? <Preview /> : <>
        <p className="sp-result-status" role="status">{t[result.status]} · {t.actual}</p>
        <dl className="sp-studio-result grid grid-cols-2 gap-3"><dt>{t.checksum}</dt><dd>{result.checksum_valid ? t.valid : '✕'}</dd>{result.network && <><dt>{t.network}</dt><dd>{t[result.network]}</dd></>}{result.version != null && <><dt>{t.version}</dt><dd>{result.version}</dd></>}</dl>
        {result.scan_pub_key && <div className="sp-studio-columns"><KeyCard title={t.scanKey} value={result.scan_pub_key} /><KeyCard title={t.spendKey} value={result.spend_pub_key} /></div>}
        <Details data={experiment.data} />
      </>}
    </div>
  </div>
}
