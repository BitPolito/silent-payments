import { useState } from 'react'
import AppLink from '../../components/AppLink'
import { useExperiment } from './useExperiment'
import { useStudioText } from './useStudioText'
import { ComputedStatus, Details, Failure, KeyCard, Preview } from './Workbench'
import { studioURL } from './navigation'
const names = ['donations', 'shop', 'project']
export default function LabelScanExperiment({ tool }) {
  const t = useStudioText(); const experiment = useExperiment(tool)
  const [controls, setControls] = useState({ network: 'testnet', known_labels: [1, 2, 3], ...(tool === 'labels' ? { label: 1 } : {}) })
  const result = experiment.data?.result
  function update(change) { experiment.clear(); setControls((current) => ({ ...current, ...change })) }
  function reset() { experiment.clear(); setControls({ network: 'testnet', known_labels: [1, 2, 3], ...(tool === 'labels' ? { label: 1 } : {}) }) }
  return <div className="sp-studio-layout">
    <div className="sp-studio-controls"><button className="sp-btn-solid" disabled={experiment.busy} onClick={() => experiment.run(controls)}>{experiment.busy ? t.working : experiment.error ? t.retry : tool === 'labels' ? t.labelScan : t.run}</button><label>{t.network}<select aria-label={t.network} className="sp-input" value={controls.network} onChange={(e) => update({ network: e.target.value })}><option value="testnet">{t.testnet}</option><option value="mainnet">{t.mainnet}</option></select></label>
      {tool === 'labels' && <label>{t.destinationLabel}<select aria-label={t.destinationLabel} className="sp-input" value={controls.label} onChange={(e) => update({ label: Number(e.target.value) })}>{names.map((name, index) => <option key={name} value={index + 1}>{t[name]}</option>)}</select></label>}
      <fieldset><legend>{t.knownLabels}</legend>{names.map((name, index) => <label key={name}><input type="checkbox" checked={controls.known_labels.includes(index + 1)} onChange={() => update({ known_labels: controls.known_labels.includes(index + 1) ? controls.known_labels.filter((id) => id !== index + 1) : [...controls.known_labels, index + 1] })} />{t[name]}</label>)}</fieldset>
      <button className="sp-back-link" onClick={reset}>{t.reset} <span aria-hidden="true">↺</span></button>
      <details className="sp-studio-details"><summary>{t.details}</summary><p className="sp-description text-xs">{t.labelHint}</p></details>
    </div>
    <div className="sp-studio-results" aria-busy={experiment.busy}>
      {experiment.error && <Failure code={experiment.error} />}
      {!result ? <Preview /> : <>
        <ComputedStatus data={experiment.data}>✓ {t.actual}</ComputedStatus>
        {tool === 'labels' ? <>
          <div className="sp-studio-result"><h2>{new Set(result.addresses.map((row) => row.scan_pub_key)).size === 1 && new Set(result.addresses.map((row) => row.spend_pub_key)).size === result.addresses.length ? t.labelIdentity : t.engineFailure}</h2><div className="sp-studio-columns">{result.addresses.slice(1).map((row) => <KeyCard key={row.index} title={`${t[row.name]} · ${row.index}`} value={row.address} />)}</div></div>
          <div role="status" className="sp-studio-result"><h2>{t.found}: {result.wallet.length} / {result.outputs.length}</h2>{result.outputs.map((value, index) => <KeyCard key={value} title="Output" value={value} index={index + 1} />)}</div>
          <AppLink className="sp-back-link" href={studioURL('scan').href}>{t.scan} →</AppLink>
        </> : <>
          <div className="sp-studio-result" role="status"><h2>{t.found}: {result.found}</h2><p className="sp-description">{t.batch}</p></div>
          <div className="sp-studio-ledger">{result.transactions.map((tx, index) => <section className="sp-studio-result" key={tx.id} data-testid={`transaction-${tx.id}`}><div className="flex flex-wrap justify-between items-center gap-3"><h2>{String(index + 1).padStart(2, '0')} · {t[tx.id]}</h2><strong>{tx.status === 'found' ? '✓ ' : tx.status === 'rejected' ? '✕ ' : '○ '}{t[tx.status === 'found' ? 'found_status' : tx.status]}</strong></div><p className="sp-description text-xs">{t.found}: {tx.wallet.length}</p><details className="sp-studio-details"><summary>{t.details}</summary><pre>{JSON.stringify(tx, null, 2)}</pre></details></section>)}</div>
          <AppLink className="sp-back-link" href={studioURL('labels').href}>{t.labels} →</AppLink>
        </>}
        <Details data={experiment.data} />
      </>}
    </div>
  </div>
}
